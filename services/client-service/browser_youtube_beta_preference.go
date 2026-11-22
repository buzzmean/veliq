package clientservice

import (
	"encoding/json"
	"errors"
	"path"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/buzzmean/neexitlag/core/browserproxy"
	"github.com/buzzmean/neexitlag/core/security"
	wp "github.com/buzzmean/neexitlag/platform/windows"
)

type youtubeLocalBetaPreference struct {
	mu          sync.Mutex
	active      atomic.Pointer[youtubeLocalBetaCounters] // Nil while OFF. Old counters stay isolated from each new generation.
	lastEpoch   uint64                                   // Mode transitions are serialized by mu.
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
	Automatic       bool   `json:"automatic"`
	Manageable      bool   `json:"manageable"`
	Enabled         bool   `json:"enabled"`
	Active          bool   `json:"active"`
	Generation      uint64 `json:"generation"`
	Reason          string `json:"reason"`
	LastFailure     string `json:"last_failure,omitempty"`
	LocalCDNRX      uint64 `json:"local_cdn_rx"`
	LocalDNSQueries uint64 `json:"local_dns_queries"`
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
		// Older desktop builds can still request ON. The previous preference
		// file stays intact so an older service can read it after rollback.
		if !*value.Enabled {
			return youtubeLocalBetaStatus{}, errors.New("YOUTUBE_LOCAL_AUTOMATIC")
		}
	}
	return c.youtubeLocalBetaStatus(), nil
}

func (c *Controller) youtubeLocalBetaStatus() youtubeLocalBetaStatus {
	pref := &c.youtubeLocalBeta
	pref.mu.Lock()
	status := youtubeLocalBetaStatus{
		Automatic:   true,
		LastFailure: pref.lastFailure,
	}
	if counts := pref.active.Load(); counts != nil {
		status.Enabled = true
		status.Generation = counts.generation
		status.LocalCDNRX = counts.localRX.Load()
		status.LocalDNSQueries = counts.localDNS.Load()
	}
	pref.mu.Unlock()

	status.Reason = "OFF"
	if status.Enabled {
		status.Reason = c.youtubeLocalBetaReadiness()
		status.Active = status.Reason == "READY" || strings.HasPrefix(status.Reason, "DIRECT_ONLY_")
	}
	return status
}

func (c *Controller) youtubeLocalBetaReadiness() string {
	if c.BrowserOwnerSID == "" {
		return "INSTALLATION_OWNER_UNAVAILABLE"
	}
	if !c.activationNetworkAllowed() {
		return "ACTIVATION_REQUIRED"
	}
	c.mu.Lock()
	routingEnabled := c.enabled && c.settings.Automatic
	c.mu.Unlock()
	chrome, edge := false, false
	for _, p := range c.Profiles.List() {
		if browserAuto(p) {
			chrome = chrome || chromeProfile(p)
			edge = edge || edgeProfile(p)
		}
	}
	if !routingEnabled || !(chrome || edge) {
		return "WAITING_FOR_BROWSER_AUTO"
	}
	authority := c.browser.authority.published.Load()
	ready := authority != nil && authority.applied && authority.reason == "" && authority.server != nil
	if !ready {
		c.browser.mu.Lock()
		e := c.browser.edge
		ready = chrome && c.browser.server != nil && c.chromePolicyActive() || edge && e != nil && e.server != nil && e.policyActive(c.BrowserOwnerSID)
		c.browser.mu.Unlock()
	}
	if !ready {
		return "WAITING_FOR_BROWSER_AUTHORITY"
	}
	if !c.nativeBackendReady() {
		return "DIRECT_ONLY_CAPTURE_NOT_READY"
	}
	n := c.network.Load()
	if n == nil || n.Error != "" || n.Fingerprint == "" || time.Since(n.ObservedAt) > 45*time.Second {
		return "DIRECT_ONLY_NETWORK_PENDING"
	}
	if !c.youtubeLocalAllowed(n.Fingerprint) {
		return "DIRECT_ONLY_LOCAL_GUARD"
	}
	return "READY"
}

func (c *Controller) youtubeLocalBetaScope(q browserproxy.Request) uint64 {
	counts := c.youtubeLocalBeta.active.Load()
	exe := strings.ToLower(path.Base(strings.ReplaceAll(q.Owner.Exe, `\`, "/")))
	if counts == nil || !c.youtubeLocalBetaCurrent(counts.generation) || c.BrowserOwnerSID == "" || q.Owner.PID == 0 || q.Owner.Birth == 0 || (exe != "chrome.exe" && exe != "msedge.exe") {
		return 0
	}
	c.mu.Lock()
	routingEnabled := c.enabled && c.settings.Automatic
	c.mu.Unlock()
	if !routingEnabled {
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
	if !matched || q.Owner.Profile != p.ID || !browserAuto(p) || !c.youtubeLocalBetaCurrent(counts.generation) {
		return 0
	}
	return counts.generation
}

func (c *Controller) youtubeLocalBetaCurrent(generation uint64) bool {
	counts := c.youtubeLocalBeta.active.Load()
	return counts != nil && counts.generation == generation && c.activationNetworkAllowed()
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
