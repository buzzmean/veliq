package clientservice

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/buzzmean/veliq/core/release"
	"github.com/buzzmean/veliq/core/security"
)

// BuildSequence is the git commit count of this build (set with -ldflags -X).
// "0" (developer build) never auto-updates.
var BuildSequence = "0"

const updateRepository = "buzzmean/veliq"
const updateInterval = 6 * time.Hour

type UpdateStatus struct {
	Downloaded int64     `json:"downloaded_bytes,omitempty"`
	Total      int64     `json:"total_bytes,omitempty"`
	State      string    `json:"state"`
	Current    string    `json:"current_build"`
	Available  uint64    `json:"available_build,omitempty"`
	Version    string    `json:"available_version,omitempty"`
	Error      string    `json:"error,omitempty"`
	Via        string    `json:"via,omitempty"`
	Checked    time.Time `json:"checked_at,omitempty"`
}

type updater struct {
	op        sync.Mutex // Serializes checks and owner-authorized installation.
	ready     release.Manifest
	readyPath string
	mu        sync.Mutex
	status    UpdateStatus
	http      *http.Client
	relay     *http.Client // optional: same requests through the VELIQ relay
	viaRelay  bool
	keys      map[string]ed25519.PublicKey
	dir       string // service install directory, e.g. %ProgramData%\VELIQ
	api       string
	launch    func(path string) error
	current   uint64
}

func newUpdater(keys map[string]ed25519.PublicKey, dir string, launch func(string) error) *updater {
	current, _ := strconv.ParseUint(BuildSequence, 10, 64)
	return &updater{status: UpdateStatus{State: "IDLE", Current: BuildSequence}, http: &http.Client{Timeout: 30 * time.Minute}, keys: keys, dir: dir, api: "https://api.github.com/repos/" + updateRepository + "/releases/latest", launch: launch, current: current}
}

func (u *updater) snapshot() UpdateStatus {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.status
}

func (u *updater) set(state, failure string, m *release.Manifest) {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.status.State, u.status.Error, u.status.Checked = state, failure, time.Now()
	u.status.Via = "direct"
	if u.viaRelay {
		u.status.Via = "relay"
	}
	if m != nil {
		u.status.Available, u.status.Version = m.Build, m.Version
	}
}

// Club images are frozen and diskless: an update would be downloaded again on
// every boot and lost. The owner updates the image instead.
func (u *updater) disabled() string {
	if u.current == 0 {
		return "DEVELOPER_BUILD"
	}
	if _, e := os.Stat(filepath.Join(u.dir, "club-mode.json")); e == nil {
		return "CLUB_IMAGE_MANAGED"
	}
	return ""
}

func (u *updater) run(ctx context.Context) {
	timer := time.NewTimer(time.Minute)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		}
		u.check(ctx)
		// A throttled or stalled download resumes soon from the partial file
		// instead of waiting for the next regular check.
		if s := u.snapshot(); s.State == "DOWNLOAD_FAILED" && s.Error == "UPDATE_DOWNLOAD_SLOW" {
			timer.Reset(10 * time.Second)
		} else if s.State == "DOWNLOAD_FAILED" {
			timer.Reset(downloadRetry)
		} else {
			timer.Reset(updateInterval)
		}
	}
}

const downloadRetry = 3 * time.Minute

// Abort a download that delivers nothing for this long; it resumes later.
const downloadStall = time.Minute

// A direct download slower than downloadSlowBytes per downloadSlowWindow switches to the relay.
const downloadSlowWindow = 30 * time.Second
const downloadSlowBytes = 3 << 20

type githubRelease struct {
	Assets []struct {
		Name string `json:"name"`
		URL  string `json:"browser_download_url"`
		Size int64  `json:"size"`
	} `json:"assets"`
}

func (u *updater) check(ctx context.Context) {
	if !u.op.TryLock() {
		return
	}
	defer u.op.Unlock()
	if u.snapshot().State == "INSTALLING" {
		return
	}
	if reason := u.disabled(); reason != "" {
		u.set("DISABLED", reason, nil)
		return
	}
	m, setupURL, e := u.latest(ctx)
	if e != nil {
		u.set("CHECK_FAILED", e.Error(), nil)
		return
	}
	if m.Build <= u.current {
		u.set("UP_TO_DATE", "", &m)
		return
	}
	u.readyPath = ""
	u.progress(0, m.SetupSize)
	u.set("DOWNLOADING", "", &m)
	path, e := u.download(ctx, setupURL, m)
	if e != nil {
		// Throttled or blocked direct path: the next attempt alternates to the relay.
		u.mu.Lock()
		u.viaRelay = u.relay != nil && !u.viaRelay
		u.mu.Unlock()
		u.set("DOWNLOAD_FAILED", e.Error(), &m)
		return
	}
	u.ready, u.readyPath = m, path
	u.progress(m.SetupSize, m.SetupSize)
	u.set("READY", "", &m)
}

// Only this authenticated owner IPC action can launch an installer. A timer,
// download retry, GUI reopen or service restart never implies consent.
func (u *updater) install(build uint64) error {
	if !u.op.TryLock() {
		return errors.New("UPDATE_BUSY")
	}
	defer u.op.Unlock()
	if reason := u.disabled(); reason != "" {
		u.set("DISABLED", reason, nil)
		return errors.New(reason)
	}
	state := u.snapshot().State
	if (state != "READY" && state != "INSTALL_FAILED") || u.readyPath == "" || build != u.ready.Build || build <= u.current {
		return errors.New("UPDATE_NOT_READY")
	}
	// Recheck the verified manifest's size/hash immediately before launch.
	if ok, _ := fileMatches(u.readyPath, u.ready); !ok {
		u.readyPath = ""
		u.set("DOWNLOAD_FAILED", "UPDATE_DOWNLOAD_MISMATCH", &u.ready)
		return errors.New("UPDATE_DOWNLOAD_MISMATCH")
	}
	u.set("INSTALLING", "", &u.ready)
	if err := u.launch(u.readyPath); err != nil {
		u.set("INSTALL_FAILED", "UPDATE_LAUNCH_FAILED", &u.ready)
		return errors.New("UPDATE_LAUNCH_FAILED")
	}
	return nil
}

// A successful replacement stops this old service. If it is still alive when
// Setup exits, expose a retryable failure instead of leaving INSTALLING forever.
func (u *updater) installExited() {
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.status.State == "INSTALLING" {
		u.status.State, u.status.Error = "INSTALL_FAILED", "UPDATE_NOT_COMPLETED"
	}
}

func (u *updater) progress(have, total int64) {
	u.mu.Lock()
	defer u.mu.Unlock()
	if have > total {
		have = total
	}
	u.status.Downloaded, u.status.Total = have, total
}

func (u *updater) get(ctx context.Context, url string, limit int64) ([]byte, error) {
	req, e := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if e != nil {
		return nil, e
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "VELIQ-updater")
	resp, e := u.client().Do(req)
	if e != nil && u.relay != nil && !u.usingRelay() {
		// Metadata is small: retry once through the relay right away.
		req2, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		req2.Header = req.Header.Clone()
		resp, e = u.relay.Do(req2)
	}
	if e != nil {
		return nil, errors.New("UPDATE_SOURCE_UNREACHABLE")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("UPDATE_SOURCE_HTTP_%d", resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, limit))
}

func (u *updater) latest(ctx context.Context) (release.Manifest, string, error) {
	var m release.Manifest
	body, e := u.get(ctx, u.api, 1<<20)
	if e != nil {
		return m, "", e
	}
	var r githubRelease
	if json.Unmarshal(body, &r) != nil {
		return m, "", errors.New("UPDATE_RELEASE_INVALID")
	}
	manifestURL, setupURL := "", ""
	for _, a := range r.Assets {
		switch a.Name {
		case release.ManifestAsset:
			manifestURL = a.URL
		case release.SetupAsset:
			setupURL = a.URL
		}
	}
	if manifestURL == "" || setupURL == "" {
		return m, "", errors.New("UPDATE_ASSETS_MISSING")
	}
	signed, e := u.get(ctx, manifestURL, security.MaxDocument)
	if e != nil {
		return m, "", e
	}
	if security.Verify(release.Domain, u.keys, signed, &m) != nil || m.Validate() != nil {
		return m, "", errors.New("UPDATE_SIGNATURE_INVALID")
	}
	return m, setupURL, nil
}

func (u *updater) download(ctx context.Context, url string, m release.Manifest) (string, error) {
	dir := filepath.Join(u.dir, "updates")
	if e := os.MkdirAll(dir, 0o700); e != nil {
		return "", e
	}
	path := filepath.Join(dir, fmt.Sprintf("VELIQ-Setup-%d.exe", m.Build))
	if ok, _ := fileMatches(path, m); ok {
		return path, nil
	}
	// Resume a partial download: hash what is already on disk, request the rest.
	tmp := path + ".part"
	h := sha256.New()
	have := int64(0)
	if f, e := os.Open(tmp); e == nil {
		have, _ = io.Copy(h, f)
		f.Close()
	}
	if have > m.SetupSize {
		os.Remove(tmp)
		h.Reset()
		have = 0
	}
	work, cancel := context.WithCancel(ctx)
	defer cancel()
	req, e := http.NewRequestWithContext(work, http.MethodGet, url, nil)
	if e != nil {
		return "", e
	}
	req.Header.Set("User-Agent", "VELIQ-updater")
	if have > 0 {
		req.Header.Set("Range", fmt.Sprintf("bytes=%d-", have))
	}
	resp, e := u.client().Do(req)
	if e != nil {
		return "", errors.New("UPDATE_SOURCE_UNREACHABLE")
	}
	defer resp.Body.Close()
	flags := os.O_CREATE | os.O_WRONLY | os.O_APPEND
	switch {
	case resp.StatusCode == http.StatusPartialContent && have > 0:
	case resp.StatusCode == http.StatusOK:
		flags = os.O_CREATE | os.O_WRONLY | os.O_TRUNC
		h.Reset()
		have = 0
	default:
		return "", fmt.Errorf("UPDATE_SOURCE_HTTP_%d", resp.StatusCode)
	}
	f, e := os.OpenFile(tmp, flags, 0o600)
	if e != nil {
		return "", e
	}
	// Abort when nothing arrives for downloadStall; the next attempt resumes.
	stall := time.AfterFunc(downloadStall, cancel)
	defer stall.Stop()
	var got atomic.Int64
	body := &progressReader{r: io.LimitReader(resp.Body, m.SetupSize-have+1), onRead: func(n int) { got.Add(int64(n)); u.progress(have+got.Load(), m.SetupSize); stall.Reset(downloadStall) }}
	slow := atomic.Bool{}
	if !u.usingRelay() && u.relay != nil {
		// Throttled direct path (seen at ~20 KB/s): give up early and resume via relay.
		go func() {
			tick := time.NewTicker(downloadSlowWindow)
			defer tick.Stop()
			last := int64(0)
			for {
				select {
				case <-work.Done():
					return
				case <-tick.C:
					now := got.Load()
					if now-last < downloadSlowBytes {
						slow.Store(true)
						cancel()
						return
					}
					last = now
				}
			}
		}()
	}
	n, e := io.Copy(io.MultiWriter(f, h), body)
	if ce := f.Close(); e == nil {
		e = ce
	}
	if e != nil {
		if slow.Load() {
			return "", errors.New("UPDATE_DOWNLOAD_SLOW")
		}
		return "", errors.New("UPDATE_DOWNLOAD_INTERRUPTED")
	}
	if have+n != m.SetupSize || hex.EncodeToString(h.Sum(nil)) != m.SetupSHA256 {
		os.Remove(tmp)
		return "", errors.New("UPDATE_DOWNLOAD_MISMATCH")
	}
	if e = os.Rename(tmp, path); e != nil {
		return "", e
	}
	return path, nil
}

type progressReader struct {
	r      io.Reader
	onRead func(int)
}

func (p *progressReader) Read(b []byte) (int, error) {
	n, e := p.r.Read(b)
	if n > 0 {
		p.onRead(n)
	}
	return n, e
}

func fileMatches(path string, m release.Manifest) (bool, error) {
	f, e := os.Open(path)
	if e != nil {
		return false, e
	}
	defer f.Close()
	h := sha256.New()
	n, e := io.Copy(h, f)
	return e == nil && n == m.SetupSize && hex.EncodeToString(h.Sum(nil)) == m.SetupSHA256, e
}

func (u *updater) usingRelay() bool {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.viaRelay && u.relay != nil
}

func (u *updater) client() *http.Client {
	if u.usingRelay() {
		return u.relay
	}
	return u.http
}
