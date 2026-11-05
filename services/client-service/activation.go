package clientservice

import (
	"context"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"github.com/buzzmean/neexitlag/core/controlclient"
	"github.com/buzzmean/neexitlag/core/enrollment"
	"github.com/buzzmean/neexitlag/core/freshpc"
	"github.com/buzzmean/neexitlag/core/security"
	"github.com/buzzmean/neexitlag/internal/clientconfig"
	wp "github.com/buzzmean/neexitlag/platform/windows"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type ActivationStatus struct {
	Hardware         enrollment.HardwareDiagnostics `json:"hardware"`
	PolicyCleanup    string                         `json:"policy_cleanup"`
	CapturePermitted bool                           `json:"capture_permitted"`
	State            string                         `json:"state"`
	Error            string                         `json:"error"`
	HasIdentity      bool                           `json:"has_identity"`
	CANotAfter       string                         `json:"ca_not_after"`
	ServerNotAfter   string                         `json:"server_not_after"`
}
type activationRecord struct {
	AccountLink     *enrollment.DeviceLink    `json:"account_link,omitempty"`
	AccountStarted  int64                     `json:"account_started,omitempty"`
	Account         enrollment.AccountBinding `json:"account,omitempty"`
	AccountOrigin   string                    `json:"account_origin,omitempty"`
	BootstrapID     string                    `json:"club_bootstrap_id,omitempty"`
	BootstrapSecret string                    `json:"club_bootstrap_secret,omitempty"`
	ImageTemplate   bool                      `json:"image_template,omitempty"`
	Code            string                    `json:"code"`
	RequestID       string                    `json:"request_id"`
	Pending         bool                      `json:"pending"`
	Machine         string                    `json:"machine_hash"`
	Salt            string                    `json:"hardware_salt"`
	CANotAfter      string                    `json:"ca_not_after,omitempty"`
	ServerNotAfter  string                    `json:"server_not_after,omitempty"`
}
type activationRuntime struct {
	account              atomic.Pointer[accountConnectionStatus]
	networkBlocked       atomic.Bool
	stopAutomatic        atomic.Bool
	preactivationCleanup bool
	policyCleanup        string
	diagnostics          enrollment.HardwareDiagnostics
	hardware             func(context.Context) (enrollment.Hardware, error)
	mu                   sync.Mutex
	manifest             Manifest
	status               ActivationStatus
	wake                 chan struct{}
	revision             uint64
	configured           bool
	revoked              bool
	paused               bool
	done                 chan struct{}
}

func (c *Controller) activationStatus() ActivationStatus {
	c.activation.mu.Lock()
	defer c.activation.mu.Unlock()
	out := c.activation.status
	out.Hardware = c.activation.diagnostics
	out.PolicyCleanup = c.activation.policyCleanup
	out.CapturePermitted = c.activationNetworkAllowed()
	if c.activation.revoked {
		out.State = "ACTIVATION_ERROR"
		out.Error = "DEVICE_REVOKED"
	}
	m := c.activation.manifest
	caFile := m.ControlPlaneCAFile
	if caFile == "" {
		caFile = m.CAFile
	}
	if raw, e := os.ReadFile(caFile); e == nil {
		if ca, e := freshpc.ParseCertificate(string(raw)); e == nil {
			out.CANotAfter = ca.NotAfter.UTC().Format(time.RFC3339)
		}
	}
	return out
}
func activationFile(m Manifest) string {
	if m.ActivationCodeFile != "" {
		return m.ActivationCodeFile
	}
	return filepath.Join(filepath.Dir(m.DeviceIdentityFile), "activation-code.json")
}
func protectedActivationWrite(path string, raw []byte) error {
	if !filepath.IsAbs(path) {
		return errors.New("ACTIVATION_STORAGE_FAILED")
	}
	if e := os.MkdirAll(filepath.Dir(path), 0700); e != nil {
		return errors.New("ACTIVATION_STORAGE_FAILED")
	}
	if st, e := os.Lstat(path); e == nil && st.Mode()&os.ModeSymlink != 0 {
		return errors.New("ACTIVATION_STORAGE_FAILED")
	}
	f, e := os.CreateTemp(filepath.Dir(path), ".activation-*")
	if e != nil {
		return errors.New("ACTIVATION_STORAGE_FAILED")
	}
	name := f.Name()
	defer os.Remove(name)
	if e = f.Chmod(0600); e == nil {
		_, e = f.Write(raw)
	}
	if e == nil {
		e = f.Sync()
	}
	ce := f.Close()
	if e == nil {
		e = ce
	}
	if e == nil {
		e = wp.ProtectActivationFile(name)
	}
	if e == nil {
		e = os.Rename(name, path)
	}
	if e != nil {
		return errors.New("ACTIVATION_STORAGE_FAILED")
	}
	return nil
}
func readActivationRecord(path string) (activationRecord, error) {
	var r activationRecord
	b, e := os.ReadFile(path)
	if e != nil {
		return r, e
	}
	if len(b) > 4096 || security.Parse(b, &r) != nil {
		return r, errors.New("ACTIVATION_STORAGE_FAILED")
	}
	if r.AccountLink == nil && r.BootstrapID == "" && r.Account.Kind == "" {
		if _, e = enrollment.CodeHash(r.Code); e != nil {
			return r, e
		}
	} else if e = validateAccountActivationRecord(r); e != nil {
		return r, e
	}
	if len(r.RequestID) != 32 {
		return r, errors.New("ACTIVATION_STORAGE_FAILED")
	}
	return r, nil
}
func pendingActivationFile(m Manifest) string { return activationFile(m) + ".pending" }
func readActivation(m Manifest) (activationRecord, error) {
	if _, e := os.Stat(pendingActivationFile(m)); e == nil {
		return readActivationRecord(pendingActivationFile(m))
	}
	return readActivationRecord(activationFile(m))
}
func validActivationIdentity(m Manifest) bool {
	if _, e := os.Stat(m.DeviceIdentityFile); e != nil {
		return false
	}
	_, key, e := security.LoadOrCreateIdentity(m.DeviceIdentityFile)
	if e != nil {
		return false
	}
	b, e := os.ReadFile(m.DeviceCertificate)
	if e != nil {
		return false
	}
	leaf, e := freshpc.ParseCertificate(string(b))
	if e != nil {
		return false
	}
	ca, e := os.ReadFile(m.CAFile)
	if e != nil {
		return false
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(ca) {
		return false
	}
	if _, e = leaf.Verify(x509.VerifyOptions{Roots: pool, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); e != nil {
		return false
	}
	pub, e := x509.MarshalPKIXPublicKey(leaf.PublicKey)
	if e != nil {
		return false
	}
	want, _ := x509.MarshalPKIXPublicKey(key.Public())
	return string(pub) == string(want)
}

// Called before IPC startup. Only installations with a stored code/missing
// identity use this background manager; existing valid legacy installs do not.
func (c *Controller) ConfigureActivation(m Manifest) bool {
	m = clientconfig.Normalize(m)
	c.browser.readiness.enforced.Store(true)
	c.configureBrowserTransportCheck(m)
	c.mu.Lock()
	c.ControlPlaneURL = m.ControlPlaneURL
	c.mu.Unlock()
	c.activation.mu.Lock()
	defer c.activation.mu.Unlock()
	if m.ControlPlaneURL == "" || m.DeviceIdentityFile == "" || m.DeviceCertificate == "" {
		c.activation.status.State = "UNAVAILABLE"
		c.activation.networkBlocked.Store(true)
		return false
	}
	c.activation.manifest = m
	c.activation.configured = true
	c.activation.wake = make(chan struct{}, 1)
	valid := validActivationIdentity(m)
	c.activation.status = ActivationStatus{State: "CODE_REQUIRED", HasIdentity: valid}
	if valid {
		c.activation.status.State = "ACTIVATED"
	}
	_, recordError := readActivation(m)
	_, identityErr := os.Stat(m.DeviceIdentityFile)
	_, certErr := os.Stat(m.DeviceCertificate)
	managed := recordError == nil || identityErr != nil || certErr != nil
	c.activation.preactivationCleanup = os.IsNotExist(identityErr) && os.IsNotExist(certErr)
	c.activation.networkBlocked.Store(managed)
	if recordError == nil {
		c.activation.status.State = "ACTIVATING"
	}
	if m.ClubImage && !clubBootReady(m) {
		c.activation.paused = true
		c.activation.status.State = "CLUB_IMAGE_STAGED"
		c.activation.networkBlocked.Store(true)
		c.wg.Add(1)
		go func() { defer c.wg.Done(); c.waitClubBoot(m) }()
	}
	// Even a legacy install needs the idle worker for GUI's explicit Change action.
	c.activation.done = make(chan struct{})
	c.wg.Add(1)
	go func() { defer c.wg.Done(); defer close(c.activation.done); c.activationLoop(managed) }()
	// A pending replacement must not prevent a valid legacy identity connecting.
	_, activeErr := readActivationRecord(activationFile(m))
	return managed && !(valid && activeErr != nil)
}
func (c *Controller) handleActivation(method string, raw json.RawMessage) (any, error) {
	if method == "activation.status" {
		return c.activationStatus(), nil
	}
	var q struct {
		Code         string `json:"code"`
		StageForBoot bool   `json:"stage_for_boot"`
	}
	if security.Parse(raw, &q) != nil {
		return nil, errors.New("ACTIVATION_INVALID")
	}
	if _, e := enrollment.CodeHash(q.Code); e != nil {
		return nil, e
	}
	c.activation.mu.Lock()
	defer c.activation.mu.Unlock()
	if !c.activation.configured {
		return nil, errors.New("ACTIVATION_UNAVAILABLE")
	}
	id, e := security.NewID()
	if e != nil {
		return nil, errors.New("ACTIVATION_STORAGE_FAILED")
	}
	record := activationRecord{Code: q.Code, RequestID: id, Pending: true}
	b, _ := json.Marshal(record)
	if e = protectedActivationWrite(pendingActivationFile(c.activation.manifest), b); e != nil {
		return nil, e
	}
	c.activation.revision++
	c.activation.paused = q.StageForBoot
	c.activation.status.State = "ACTIVATING"
	if q.StageForBoot {
		c.activation.status.State = "CODE_STAGED"
	}
	c.activation.status.Error = ""
	select {
	case c.activation.wake <- struct{}{}:
	default:
	}
	return c.activation.status, nil
}
func (c *Controller) activationAttempt(ctx context.Context, m Manifest, r activationRecord) (activationRecord, enrollment.Policy, error) {
	caFile := m.ControlPlaneCAFile
	if caFile == "" {
		caFile = m.CAFile
	}
	raw, e := os.ReadFile(caFile)
	if e != nil {
		return r, enrollment.Policy{}, errors.New("ACTIVATION_TRUST_NOT_CONFIGURED")
	}
	ca, e := freshpc.ParseCertificate(string(raw))
	if e != nil || m.ActivationCAFingerprint == "" || freshpc.Fingerprint(ca) != strings.ToLower(strings.ReplaceAll(m.ActivationCAFingerprint, ":", "")) {
		return r, enrollment.Policy{}, errors.New("ACTIVATION_TRUST_NOT_CONFIGURED")
	}
	http, e := controlclient.HTTPSClient(caFile)
	if e != nil {
		return r, enrollment.Policy{}, errors.New("ACTIVATION_TRUST_NOT_CONFIGURED")
	}
	http.Timeout = 4 * time.Second
	defer http.CloseIdleConnections()
	client := enrollment.Client{URL: m.ControlPlaneURL, HTTP: http}
	policy, e := client.Policy(ctx)
	if e != nil {
		return r, policy, e
	}
	if !policy.Ready {
		return r, policy, errors.New("ACTIVATION_UNAVAILABLE")
	}
	if r.AccountLink != nil && r.AccountLink.Mode == "image" {
		return c.accountImageAttempt(ctx, m, r, policy, client)
	}
	salt, e := hex.DecodeString(policy.HardwareSalt)
	if e != nil || len(salt) != 32 {
		return r, policy, errors.New("ACTIVATION_INVALID_RESPONSE")
	}
	machine, e := c.activationHardware(ctx, salt)
	if e != nil {
		return r, policy, e
	}
	r.Machine, r.Salt = machine, policy.HardwareSalt
	// A cloned image cannot reuse a candidate key from a different physical PC.
	dir := filepath.Join(m.StateDirectory, "activation-pending", machine, r.RequestID)
	identityPath := filepath.Join(dir, "identity.json")
	if r.AccountLink != nil && validActivationIdentity(m) {
		identityPath = m.DeviceIdentityFile
	}
	id, key, e := security.LoadOrCreateIdentity(identityPath)
	if e != nil {
		return r, policy, errors.New("ACTIVATION_KEY_FAILED")
	}
	if e = wp.ProtectActivationFile(identityPath); e != nil {
		return r, policy, errors.New("ACTIVATION_STORAGE_FAILED")
	}
	request, e := enrollment.NewRequest(id.ID, machine, key)
	if e != nil {
		return r, policy, errors.New("ACTIVATION_KEY_FAILED")
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	response, e := accountEnrollmentResponse(ctx, c, m, &r, policy, client, request, key, roots)
	if e != nil {
		return r, policy, e
	}
	if len(response.ProbeToken) < 24 || len(response.ProbeToken) > 256 {
		return r, policy, errors.New("ACTIVATION_INVALID_RESPONSE")
	}
	for _, v := range response.Trust {
		if _, e = security.DecodePublicKey(v); e != nil {
			return r, policy, errors.New("ACTIVATION_INVALID_RESPONSE")
		}
	}
	identityRaw, e := os.ReadFile(identityPath)
	if e != nil {
		return r, policy, errors.New("ACTIVATION_STORAGE_FAILED")
	}
	trust, _ := json.Marshal(response.Trust)
	// All cryptographic checks precede writes. On power loss, the same candidate
	// CSR is retried; mismatched intermediate identity/cert fails closed.
	c.activation.mu.Lock()
	changed := c.activation.configured && c.activation.status.State != "" && r.RequestID != ""
	if changed {
		current, err := readActivation(m)
		changed = err != nil || current.RequestID != r.RequestID
	}
	c.activation.mu.Unlock()
	if changed {
		return r, policy, errors.New("ACTIVATION_CHANGED")
	}
	c.remoteMu.Lock()
	defer c.remoteMu.Unlock()
	if e = c.stopRemoteLocked(ctx); e != nil {
		return r, policy, errors.New("ACTIVATION_UNAVAILABLE")
	}
	for _, item := range []struct {
		path string
		raw  []byte
	}{{m.ProbeTokenFile, []byte(response.ProbeToken)}, {m.DeviceIdentityFile, identityRaw}, {m.DeviceCertificate, []byte(response.Certificate)}, {m.TrustFile, trust}} {
		if e = protectedActivationWrite(item.path, item.raw); e != nil {
			return r, policy, e
		}
	}
	r.CANotAfter, r.ServerNotAfter = policy.CANotAfter, policy.ServerNotAfter
	r.Pending = false
	c.activation.mu.Lock()
	c.activation.revoked = false
	c.activation.mu.Unlock()
	return r, policy, nil
}
func (c *Controller) activationLoop(managed bool) {
	backoff := time.Second
	var nextMetadata time.Time
	var connected bool
	var automaticStarted bool
	captureBackoff := 2 * time.Second
	for {
		if c.ctx.Err() != nil {
			return
		}
		c.activation.mu.Lock()
		m := c.activation.manifest
		rev := c.activation.revision
		paused := c.activation.paused
		c.activation.mu.Unlock()
		if paused {
			select {
			case <-c.ctx.Done():
				return
			case <-c.activation.wake:
				continue
			}
		}
		captureRetry := false
		r, e := readActivation(m)
		if e == nil && (managed || r.Pending) {
			if r.Pending && !connected && validActivationIdentity(m) {
				if previous, err := readActivationRecord(activationFile(m)); err == nil && previous.Salt != "" {
					checkCtx, cancel := context.WithTimeout(c.ctx, 5*time.Second)
					salt, se := hex.DecodeString(previous.Salt)
					if se == nil {
						hash, he := c.activationHardware(checkCtx, salt)
						if he == nil && hash == previous.Machine {
							connectCtx, cancel := context.WithTimeout(c.ctx, 8*time.Second)
							connected = c.activationConnect(connectCtx, m)
							cancel()
						}
					}
					cancel()
				}
			}

			valid := validActivationIdentity(m)
			// Verify hardware binding on every boot, even for an accidentally cloned
			// valid certificate. Legacy installations without a code are unaffected.
			bound := valid && !r.Pending && connected
			if valid && !r.Pending && !bound && r.Salt != "" {
				ctx, cancel := context.WithTimeout(c.ctx, 5*time.Second)
				salt, se := hex.DecodeString(r.Salt)
				if se == nil {
					hash, he := c.activationHardware(ctx, salt)
					bound = he == nil && hash == r.Machine
				}
				cancel()
			}
			for _, path := range []string{m.TrustFile, m.ProbeTokenFile} {
				if _, err := os.Stat(path); err != nil {
					bound = false
				}
			}
			policy := enrollment.Policy{CANotAfter: r.CANotAfter, ServerNotAfter: r.ServerNotAfter}
			if !bound {
				ctx, cancel := context.WithTimeout(c.ctx, 12*time.Second)
				next, p, err := c.activationAttempt(ctx, m, r)
				cancel()
				// A rejected code must preserve established workers. A successful
				// replacement (or interrupted file commit) actually stops them.
				connected = connected && c.activationRemoteRunning()
				policy = p
				e = err
				c.activation.mu.Lock()
				if rev == c.activation.revision && e == nil {
					b, _ := json.Marshal(next)
					e = protectedActivationWrite(activationFile(m), b)
					if e == nil {
						if err := os.Remove(pendingActivationFile(m)); err != nil && !os.IsNotExist(err) {
							e = errors.New("ACTIVATION_STORAGE_FAILED")
						}
					}
				}
				if rev != c.activation.revision {
					e = errors.New("ACTIVATION_CHANGED")
				}
				c.activation.mu.Unlock()
			}
			if current, err := readActivation(m); e == nil && err == nil && current.ImageTemplate {
				if e = c.finishAccountImage(m, current); e == nil {
					return
				}
			}
			if c.ctx.Err() != nil {
				return
			}
			if e == nil && !connected {
				ctx, cancel := context.WithTimeout(c.ctx, 8*time.Second)
				connected = c.activationConnect(ctx, m)
				cancel()
				if !connected {
					e = errors.New("ACTIVATION_UNAVAILABLE")
				}
			}
			// Also cover an authenticated previous identity while replacing a code.
			// Do not re-enable after an unsuccessful enrollment or connectivity check.
			if connected && e == nil && c.activation.networkBlocked.Swap(false) {
				_ = c.RestoreBrowserTransport()
			}
			c.activation.mu.Lock()
			if rev == c.activation.revision {
				c.activation.status = ActivationStatus{State: "ACTIVATED", HasIdentity: validActivationIdentity(m), CANotAfter: policy.CANotAfter, ServerNotAfter: policy.ServerNotAfter}
				if e != nil {
					c.activation.status.State = "ACTIVATION_ERROR"
					c.activation.status.Error = activationSafeError(e)
					if e.Error() == "ACCOUNT_APPROVAL_PENDING" {
						c.activation.status.State = "ACTIVATING"
						c.activation.status.Error = ""
					}
				}
			}
			c.activation.mu.Unlock()
			if e == nil {
				captureRetry = c.startActivatedCapture(connected, &automaticStarted) != nil
			}
		} else if os.IsNotExist(e) {
			c.activation.mu.Lock()
			c.activation.status.HasIdentity = validActivationIdentity(m)
			if !c.activation.status.HasIdentity {
				c.activation.status.State = "CODE_REQUIRED"
			} else {
				c.activation.status.State = "ACTIVATED"
			}
			c.activation.mu.Unlock()
		}
		if time.Now().After(nextMetadata) && c.ctx.Err() == nil {
			metadataCtx, cancel := context.WithTimeout(c.ctx, 3*time.Second)
			metadata, err := activationDeadlines(metadataCtx, m)
			cancel()
			nextMetadata = time.Now().Add(time.Minute)
			if err == nil {
				nextMetadata = time.Now().Add(time.Hour)
				c.activation.mu.Lock()
				c.activation.status.CANotAfter = metadata.CANotAfter
				c.activation.status.ServerNotAfter = metadata.ServerNotAfter
				c.activation.mu.Unlock()
			}
		}
		if e == nil {
			backoff = time.Minute
		} else if backoff < time.Minute {
			backoff *= 2
			if backoff > time.Minute {
				backoff = time.Minute
			}
		}
		if e != nil && e.Error() == "ACCOUNT_APPROVAL_PENDING" {
			backoff = 3 * time.Second
		}
		if captureRetry {
			backoff = captureBackoff
			if captureBackoff < 30*time.Second {
				captureBackoff *= 2
				if captureBackoff > 30*time.Second {
					captureBackoff = 30 * time.Second
				}
			}
		}
		timer := time.NewTimer(backoff)
		select {
		case <-c.ctx.Done():
			timer.Stop()
			return
		case <-c.activation.wake:
			timer.Stop()
			managed = true
			backoff = time.Second
		case <-timer.C:
		}
	}
}
func activationSafeError(e error) string {
	switch e.Error() {
	case "ACTIVATION_INVALID", "ACTIVATION_REVOKED", "ACTIVATION_EXPIRED", "ACTIVATION_LIMIT", "MACHINE_DISABLED", "ACTIVATION_RATE_LIMIT", "ACTIVATION_TRUST_NOT_CONFIGURED", "HARDWARE_ID_UNAVAILABLE", "ACTIVATION_STORAGE_FAILED", "ACTIVATION_IDENTITY_CONFLICT", "ACCOUNT_NOT_CONFIGURED", "ACCOUNT_LINK_INVALID", "ACCOUNT_LINK_EXPIRED", "ACCOUNT_APPROVAL_PENDING", "ACCOUNT_DEVICE_ALREADY_OWNED", "ACCOUNT_SUBSCRIPTION_REQUIRED", "ACCOUNT_IMAGE_NOT_CLEAN", "ACCOUNT_IMAGE_STORAGE_FAILED", "ACCOUNT_IMAGE_REVOKED", "ACCOUNT_IMAGE_LIMIT", "ACCOUNT_SIGN_IN_REQUIRED", "SUBSCRIPTION_EXPIRED":
		return e.Error()
	}
	return "ACTIVATION_UNAVAILABLE"
}

// Public authenticated metadata only; no code/device key is sent. Works for
// existing SSH/admin installations too; an older CP may simply lack the endpoint.
func activationDeadlines(ctx context.Context, m Manifest) (enrollment.Policy, error) {
	ca := m.ControlPlaneCAFile
	if ca == "" {
		ca = m.CAFile
	}
	client, e := controlclient.HTTPSClient(ca)
	if e != nil {
		return enrollment.Policy{}, errors.New("ACTIVATION_UNAVAILABLE")
	}
	defer client.CloseIdleConnections()
	client.Timeout = 2 * time.Second
	return (enrollment.Client{URL: m.ControlPlaneURL, HTTP: client}).Policy(ctx)
}

// Initial CP outage can return an error after background workers have started.
// Keep their retry/established-flow lifecycle; retry only actual setup failures.
func (c *Controller) activationConnect(ctx context.Context, m Manifest) bool {
	_ = c.ConnectRemote(ctx, m)
	return c.activationRemoteRunning()
}

func (c *Controller) activationRemoteRunning() bool {
	c.remoteMu.Lock()
	defer c.remoteMu.Unlock()
	if c.remoteDone == nil {
		return false
	}
	select {
	case <-c.remoteDone:
		return false
	default:
		return true
	}
}
