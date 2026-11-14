package clientservice

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/buzzmean/neexitlag/core/browserproxy"
	"github.com/buzzmean/neexitlag/core/profiles"
	"github.com/buzzmean/neexitlag/core/transport"
)

type browserPolicyReadiness struct {
	started          time.Time
	firstReady       [2]time.Time
	listenerAttempts [2]uint64
	enforced         atomic.Bool
	ready            [2]atomic.Bool
	liveUntil        [2]atomic.Int64
	lastOK           [2]time.Time
	reasons          [2]string
	lastEndpoints    [2]string
	mu               sync.Mutex
	target, token    string
	tls              *tls.Config
	checked          time.Time
	result           string
	check            func(context.Context, string, string, string, *tls.Config) error
	relay            func() bool // isolated test seam, never exported via IPC
}

func (c *Controller) configureBrowserTransportCheck(m Manifest) {
	p := &c.browser.readiness
	p.mu.Lock()
	defer p.mu.Unlock()
	p.started = time.Now()
	u, err := url.Parse(m.ControlPlaneURL)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" {
		return
	}
	ca := m.ControlPlaneCAFile
	if ca == "" {
		ca = m.CAFile
	}
	raw, err := os.ReadFile(ca)
	if err != nil {
		return
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(raw) {
		return
	}
	nonce := make([]byte, 32)
	if _, err = rand.Read(nonce); err != nil {
		return
	}
	port := u.Port()
	if port == "" {
		port = "443"
	}
	p.target = net.JoinHostPort(u.Hostname(), port)
	p.token = hex.EncodeToString(nonce)
	p.tls = &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS13, ServerName: u.Hostname()}
}
func (c *Controller) transportCheckSettings() (string, string) {
	p := &c.browser.readiness
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.target, p.token
}
func (c *Controller) relayConnected() bool {
	p := &c.browser.readiness
	p.mu.Lock()
	override := p.relay
	p.mu.Unlock()
	if override != nil {
		return override()
	}
	c.mu.Lock()
	pools := make([]*transport.Pool, 0, len(c.relayPools))
	for _, p := range c.relayPools {
		pools = append(pools, p)
	}
	c.mu.Unlock()
	for _, p := range pools {
		if p.Healthy() {
			return true
		}
	}
	return false
}

// No browser lock, no recursive Snapshot: safe before policy mutation.
func (c *Controller) browserPolicyBaseReason() string {
	if c.ctx.Err() != nil {
		return "SERVICE_STOPPING"
	}
	if !c.activationNetworkAllowed() {
		return "ACTIVATION_REQUIRED"
	}
	c.activation.mu.Lock()
	configured, state := c.activation.configured, c.activation.status.State
	c.activation.mu.Unlock()
	if configured && state != "ACTIVATED" {
		return "ACTIVATION_NOT_READY"
	}
	c.mu.Lock()
	enabled, automatic := c.enabled, c.settings.Automatic
	c.mu.Unlock()
	if !automatic {
		return "AUTOMATIC_DISABLED"
	}
	if !enabled {
		return "OPTIMIZATION_DISABLED"
	}
	if c.Backend == nil || !c.Backend.Status().Ready {
		return "CAPTURE_NOT_READY"
	}
	if browserDPILocalFieldEnabled() {
		return ""
	}
	p := &c.browser.readiness
	p.mu.Lock()
	relay := p.relay
	p.mu.Unlock()
	connected := c.relayConnected()
	if relay != nil {
		connected = relay()
	}
	if !connected {
		return "RELAY_NOT_CONNECTED"
	}
	return ""
}

// Caller holds browser.mu. Both endpoints must pass within a bounded health
// window; any base-state change invalidates the window before another write.
func (c *Controller) browserPolicyReadyLocked(edge bool) error {
	p := &c.browser.readiness
	if !p.enforced.Load() {
		return nil
	}
	index := 0
	if edge {
		index = 1
	}
	if reason := c.browserPolicyBaseReason(); reason != "" {
		p.mu.Lock()
		p.checked = time.Time{}
		p.lastOK[index] = time.Time{}
		p.ready[index].Store(false)
		p.result = reason
		p.mu.Unlock()
		return errors.New(reason)
	}
	ids := c.browser.silent.Profiles
	if edge {
		ids = c.edgeLocked().saved.Silent.Profiles
	}
	eligible := false
	for _, profile := range c.Profiles.List() {
		for _, id := range ids {
			if profile.ID == id && profile.Mode == profiles.Auto && ((edge && edgeProfile(profile)) || (!edge && chromeProfile(profile))) {
				eligible = true
			}
		}
	}
	if !eligible {
		return errors.New("BROWSER_PROFILE_NOT_AUTO")
	}
	primary, recovery := c.browser.address, c.browser.recoveryAddress
	if edge {
		e := c.edgeLocked()
		primary = e.saved.Address
		recovery = e.saved.Recovery
	}
	if err := c.ensureBrowserListenerLocked(edge); err != nil {
		return err
	}
	listener := c.browser.server
	if edge {
		listener = c.edgeLocked().server
	}
	if listener == nil || !listener.Snapshot().Listening {
		return errors.New("CONNECT_LISTENER_UNAVAILABLE")
	}
	p.mu.Lock()
	target, token, cfg, check := p.target, p.token, p.tls, p.check
	p.mu.Unlock()
	p.mu.Lock()
	cached := time.Since(p.lastOK[index]) < 10*time.Second && p.lastEndpoints[index] == primary+";"+recovery
	p.mu.Unlock()
	if cached {
		return nil
	}
	if check == nil {
		check = browserproxy.ProbeConnect
	}
	if primary == "" || recovery == "" || primary == recovery || target == "" || cfg == nil {
		return errors.New("CONNECT_CHECK_NOT_CONFIGURED")
	}
	ctx, cancel := context.WithTimeout(c.ctx, 4*time.Second)
	defer cancel()
	// Endpoint-specific checks never reuse a different browser's result.
	for _, address := range []string{primary, recovery} {
		if err := check(ctx, address, target, token, cfg); err != nil {
			p.mu.Lock()
			p.result = err.Error()
			p.checked = time.Now()
			p.mu.Unlock()
			return err
		}
	}
	if reason := c.browserPolicyBaseReason(); reason != "" {
		return errors.New(reason)
	}
	p.mu.Lock()
	p.lastOK[index] = time.Now()
	p.lastEndpoints[index] = primary + ";" + recovery
	p.reasons[index] = "READY"
	p.result = "READY"
	p.checked = time.Now()
	p.mu.Unlock()
	return nil
}

func (c *Controller) browserPolicyPublishReadyLocked(edge bool) error {
	if err := c.browserPolicyReadyLocked(edge); err != nil {
		_ = c.cleanupOwnedBrowserPoliciesLocked(&edge)
		i := 0
		if edge {
			i = 1
		}
		p := &c.browser.readiness
		p.mu.Lock()
		p.reasons[i] = err.Error()
		p.mu.Unlock()
		if edge {
			c.edgeLocked().lastError = "POLICY_SUSPENDED: " + err.Error()
		} else {
			c.browser.lastError = "POLICY_SUSPENDED: " + err.Error()
		}
		return &browserPolicyPending{err.Error()}
	}
	return nil
}

type browserPolicyPending struct{ reason string }

func (e *browserPolicyPending) Error() string { return e.reason }
func (c *Controller) browserPolicyMarkReady(edge bool) {
	i := 0
	if edge {
		i = 1
	}
	p := &c.browser.readiness
	p.mu.Lock()
	if p.firstReady[i].IsZero() {
		p.firstReady[i] = time.Now()
	}
	deadline := p.lastOK[i].Add(15 * time.Second).UnixNano()
	p.mu.Unlock()
	p.liveUntil[i].Store(deadline)
	p.ready[i].Store(true)
}
func (c *Controller) browserPolicyInvalidateLocked(edge *bool) {
	p := &c.browser.readiness
	p.mu.Lock()
	defer p.mu.Unlock()
	for i := 0; i < 2; i++ {
		if edge != nil && (*edge != (i == 1)) {
			continue
		}
		p.ready[i].Store(false)
		p.liveUntil[i].Store(0)
		p.lastOK[i] = time.Time{}
	}
}

type BrowserPolicyHealth struct {
	StartedAt          time.Time `json:"started_at"`
	ChromeFirstReadyAt time.Time `json:"chrome_first_ready_at"`
	EdgeFirstReadyAt   time.Time `json:"edge_first_ready_at"`
	ListenerAttempts   [2]uint64 `json:"listener_attempts"`
	ChromeConfigured   bool      `json:"chrome_configured"`
	EdgeConfigured     bool      `json:"edge_configured"`
	ChromeCheckedAt    time.Time `json:"chrome_checked_at"`
	EdgeCheckedAt      time.Time `json:"edge_checked_at"`
	ChromeReason       string    `json:"chrome_reason"`
	EdgeReason         string    `json:"edge_reason"`
	ChromeReady        bool      `json:"chrome_ready"`
	EdgeReady          bool      `json:"edge_ready"`
	Reason             string    `json:"reason"`
	LastCheck          time.Time `json:"last_check"`
	FailOpen           bool      `json:"direct_fallback"`
}

func (c *Controller) browserPolicyHealth() BrowserPolicyHealth {
	p := &c.browser.readiness
	p.mu.Lock()
	v := BrowserPolicyHealth{StartedAt: p.started, ChromeFirstReadyAt: p.firstReady[0], EdgeFirstReadyAt: p.firstReady[1], ListenerAttempts: p.listenerAttempts, ChromeCheckedAt: p.lastOK[0], EdgeCheckedAt: p.lastOK[1], ChromeReason: p.reasons[0], EdgeReason: p.reasons[1], ChromeReady: p.laneReady(0), EdgeReady: p.laneReady(1), Reason: p.result, LastCheck: p.checked, FailOpen: true}
	p.mu.Unlock()
	for _, profile := range c.Profiles.List() {
		if profile.Mode == profiles.Auto {
			v.ChromeConfigured = v.ChromeConfigured || chromeProfile(profile)
			v.EdgeConfigured = v.EdgeConfigured || edgeProfile(profile)
		}
	}
	// Capture bytes on raw TLS are the degraded relay fallback, not authority
	// isolation. Readiness needs this owner's actual authority listener exchange.
	authority := c.authorityStatus()
	for _, profile := range c.Profiles.List() {
		if !nativeBrowserProfile(profile) {
			continue
		}
		exchanges := authority.ChromeExchanges
		if edgeProfile(profile) {
			exchanges = authority.EdgeExchanges
		}
		ready := c.nativeBackendReady() && exchanges > 0
		reason := "AUTHORITY_TRANSPORT_PENDING"
		if ready {
			reason = "AUTHORITY_EXCHANGE_OBSERVED"
		}
		if edgeProfile(profile) {
			v.EdgeReady, v.EdgeReason = ready, reason
		} else {
			v.ChromeReady, v.ChromeReason = ready, reason
		}
	}
	if reason := c.browserPolicyBaseReason(); reason != "" {
		v.Reason = reason
		v.ChromeReady = false
		v.EdgeReady = false
	}
	return v
}
func (c *Controller) connectionReason(s Snapshot) string {
	if !s.CapturePermitted {
		return "ACTIVATION_REQUIRED"
	}
	c.mu.Lock()
	err := c.captureStartError
	c.mu.Unlock()
	if err != "" && !s.Backend.Ready {
		return err
	}
	if !s.Optimizing {
		return "OPTIMIZATION_DISABLED"
	}
	if !s.Backend.Ready {
		return "CAPTURE_NOT_READY"
	}
	if !s.Connected {
		return "RELAY_NOT_CONNECTED"
	}
	return "READY"
}

func (c *Controller) browserProfileMutation(raw json.RawMessage) bool {
	var q struct {
		ID          string   `json:"id"`
		Profile     string   `json:"profile_id"`
		Executables []string `json:"executables"`
	}
	if json.Unmarshal(raw, &q) != nil {
		return false
	}
	for _, p := range c.Profiles.List() {
		if (p.ID == q.ID || p.ID == q.Profile) && (chromeProfile(p) || edgeProfile(p)) {
			return true
		}
	}
	for _, exe := range q.Executables {
		if strings.HasSuffix(strings.ToLower(strings.ReplaceAll(exe, `\`, "/")), "/chrome.exe") || edgeExecutable(exe) {
			return true
		}
	}
	return false
}

func (p *browserPolicyReadiness) laneReady(i int) bool {
	return p.ready[i].Load() && time.Now().UnixNano() < p.liveUntil[i].Load()
}
