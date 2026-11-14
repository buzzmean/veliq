package clientservice

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/buzzmean/neexitlag/core/browserproxy"
	"github.com/buzzmean/neexitlag/core/security"
	wp "github.com/buzzmean/neexitlag/platform/windows"
)

const youtubeLocalBetaPreferenceFile = "browser-youtube-local-beta.json"

type youtubeLocalBetaPreference struct {
	mu          sync.Mutex
	active      atomic.Pointer[youtubeLocalBetaCounters] // Nil while OFF. Old counters stay isolated from each new generation.
	lastEpoch   uint64                                   // Mode transitions are serialized by mu.
	unreadable  bool
	lastFailure string
}

type youtubeLocalBetaCounters struct {
	generation uint64
	localRX    atomic.Uint64
	localDNS   atomic.Uint64
}

type youtubeLocalBetaSetting struct {
	Enabled *bool `json:"enabled"`
}

type youtubeLocalBetaStatus struct {
	Manageable      bool   `json:"manageable"`
	Enabled         bool   `json:"enabled"`
	Active          bool   `json:"active"`
	Generation      uint64 `json:"generation"`
	Reason          string `json:"reason"`
	LastFailure     string `json:"last_failure,omitempty"`
	LocalCDNRX      uint64 `json:"local_cdn_rx"`
	LocalDNSQueries uint64 `json:"local_dns_queries"`
}

// The optional file keeps settings.json compatible with the strict 0.3.708
// reader and is ignored by 0.3.708 during a rollback.
func (c *Controller) loadYouTubeLocalBetaPreference() {
	pref := &c.youtubeLocalBeta
	pref.mu.Lock()
	defer pref.mu.Unlock()
	if c.customPath == "" {
		pref.unreadable = false
		pref.setGeneration(false)
		return
	}

	var value youtubeLocalBetaSetting
	raw, err := os.ReadFile(filepath.Join(filepath.Dir(c.customPath), youtubeLocalBetaPreferenceFile))
	pref.unreadable = !os.IsNotExist(err) && (err != nil || security.Parse(raw, &value) != nil || value.Enabled == nil)
	pref.setGeneration(!pref.unreadable && value.Enabled != nil && *value.Enabled)
}

func (p *youtubeLocalBetaPreference) setGeneration(enabled bool) {
	if enabled == (p.active.Load() != nil) {
		return
	}
	p.lastFailure = ""
	if !enabled {
		p.active.Store(nil)
		return
	}
	p.lastEpoch++
	p.active.Store(&youtubeLocalBetaCounters{generation: p.lastEpoch})
}

func (c *Controller) handleYouTubeLocalBeta(method string, raw json.RawMessage) (youtubeLocalBetaStatus, error) {
	if method == "browser.youtube.local.set" {
		if c.clubMode.Load() {
			return youtubeLocalBetaStatus{}, errors.New("CLUB_ADMIN_MANAGED")
		}
		if c.BrowserOwnerSID == "" || c.customPath == "" {
			return youtubeLocalBetaStatus{}, errors.New("INSTALLATION_OWNER_UNAVAILABLE")
		}
		var value youtubeLocalBetaSetting
		if security.Parse(raw, &value) != nil || value.Enabled == nil {
			return youtubeLocalBetaStatus{}, errors.New("YOUTUBE_LOCAL_INVALID_PREFERENCE")
		}
		if err := c.setYouTubeLocalBetaPreference(value); err != nil {
			return youtubeLocalBetaStatus{}, err
		}
	}
	return c.youtubeLocalBetaStatus(), nil
}

func (c *Controller) setYouTubeLocalBetaPreference(value youtubeLocalBetaSetting) error {
	pref := &c.youtubeLocalBeta
	pref.mu.Lock()
	defer pref.mu.Unlock()
	if !pref.unreadable && *value.Enabled == (pref.active.Load() != nil) {
		return nil
	}
	dir := filepath.Dir(c.customPath)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return errors.New("YOUTUBE_LOCAL_PREFERENCE_WRITE_FAILED")
	}
	raw, err := json.Marshal(value)
	if err != nil || writeFileAtomic(filepath.Join(dir, youtubeLocalBetaPreferenceFile), raw) != nil {
		return errors.New("YOUTUBE_LOCAL_PREFERENCE_WRITE_FAILED")
	}
	pref.unreadable = false
	pref.setGeneration(*value.Enabled)
	return nil
}

func (c *Controller) youtubeLocalBetaStatus() youtubeLocalBetaStatus {
	if c.clubMode.Load() {
		return youtubeLocalBetaStatus{Reason: "CLUB_ADMIN_MANAGED"}
	}
	if c.BrowserOwnerSID == "" || c.customPath == "" {
		return youtubeLocalBetaStatus{Reason: "INSTALLATION_OWNER_UNAVAILABLE"}
	}
	pref := &c.youtubeLocalBeta
	pref.mu.Lock()
	status := youtubeLocalBetaStatus{
		Manageable:  true,
		LastFailure: pref.lastFailure,
	}
	if counts := pref.active.Load(); counts != nil {
		status.Enabled = true
		status.Generation = counts.generation
		status.LocalCDNRX = counts.localRX.Load()
		status.LocalDNSQueries = counts.localDNS.Load()
	}
	unreadable := pref.unreadable
	pref.mu.Unlock()

	status.Reason = "OFF"
	if unreadable {
		status.Reason = "PREFERENCE_UNREADABLE"
	} else if status.Enabled {
		status.Reason = c.youtubeLocalBetaReadiness()
		status.Active = status.Reason == "READY"
	}
	return status
}

func (c *Controller) youtubeLocalBetaReadiness() string {
	if !c.activationNetworkAllowed() {
		return "ACTIVATION_REQUIRED"
	}
	c.mu.Lock()
	routingEnabled := c.enabled && c.settings.Automatic
	c.mu.Unlock()
	if routingEnabled {
		for _, p := range c.Profiles.List() {
			if nativeBrowserProfile(p) && chromeProfile(p) {
				if !c.nativeBackendReady() {
					return "WAITING_FOR_CAPTURE"
				}
				n := c.network.Load()
				if n == nil || n.Error != "" || n.Fingerprint == "" || time.Since(n.ObservedAt) > 45*time.Second {
					return "WAITING_FOR_NETWORK"
				}
				if !c.youtubeLocalAllowed(n.Fingerprint) {
					return "WAITING_FOR_LOCAL_GUARD"
				}
				authority := c.browser.authority.published.Load()
				if authority != nil && authority.applied && authority.reason == "" && authority.server != nil {
					return "READY"
				}
				c.browser.mu.Lock()
				legacyReady := c.browser.server != nil && c.chromePolicyActive()
				c.browser.mu.Unlock()
				if legacyReady {
					return "READY"
				}
				return "WAITING_FOR_CHROME_AUTHORITY"
			}
		}
	}
	return "WAITING_FOR_CHROME_AUTO"
}

func (c *Controller) youtubeLocalBetaScope(q browserproxy.Request) uint64 {
	counts := c.youtubeLocalBeta.active.Load()
	if counts == nil || !c.youtubeLocalBetaCurrent(counts.generation) || c.BrowserOwnerSID == "" || q.Owner.PID == 0 || q.Owner.Birth == 0 || !strings.EqualFold(filepath.Base(q.Owner.Exe), "chrome.exe") {
		return 0
	}
	id, err := c.discovery.Lookup(q.Owner.PID)
	if err != nil || id.CreationTime != q.Owner.Birth || !strings.EqualFold(id.Path, q.Owner.Exe) {
		return 0
	}
	sid, err := wp.ProcessUserSID(id)
	if err != nil || sid != c.BrowserOwnerSID || !wp.IsCurrent(id) {
		return 0
	}
	p, matched := c.matchApplication(id)
	if !matched || q.Owner.Profile != p.ID || !nativeBrowserProfile(p) || !chromeProfile(p) || !c.youtubeLocalBetaCurrent(counts.generation) {
		return 0
	}
	return counts.generation
}

func (c *Controller) youtubeLocalBetaCurrent(generation uint64) bool {
	counts := c.youtubeLocalBeta.active.Load()
	return counts != nil && counts.generation == generation && !c.clubMode.Load() && c.activationNetworkAllowed()
}

func (c *Controller) youtubeLocalBetaCount(generation, originRX, dnsLocal uint64) {
	if counts := c.youtubeLocalBeta.active.Load(); counts != nil && counts.generation == generation && c.youtubeLocalBetaCurrent(generation) {
		counts.localRX.Add(originRX)
		counts.localDNS.Add(dnsLocal)
	}
}

func (c *Controller) youtubeLocalBetaOutcome(generation uint64, reason string) {
	pref := &c.youtubeLocalBeta
	pref.mu.Lock()
	defer pref.mu.Unlock()
	if !c.youtubeLocalBetaCurrent(generation) {
		return
	}
	if reason == "OPENED_LOCAL" {
		pref.lastFailure = ""
		return
	}
	// Routing supplies only bounded reason enums. Keep the diagnostic surface
	// incapable of echoing an arbitrary hostname or error message.
	if len(reason) > 64 || !strings.HasPrefix(reason, "DPI_LOCAL_") {
		return
	}
	for _, ch := range reason {
		if ch != '_' && (ch < 'A' || ch > 'Z') {
			return
		}
	}
	pref.lastFailure = reason
}
