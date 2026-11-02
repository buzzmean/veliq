package clientservice

// IPC method bodies moved out of Controller.Handle unchanged.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"time"

	"github.com/buzzmean/neexitlag/core/profiles"
	"github.com/buzzmean/neexitlag/core/routing"
	"github.com/buzzmean/neexitlag/core/security"
	windowsplatform "github.com/buzzmean/neexitlag/platform/windows"
)

func (c *Controller) handleRelayDiagnostics(ctx context.Context, method string, raw json.RawMessage) (any, error) {
	switch method {
	case "acceptance.readiness":
		var query struct {
			RelayID string `json:"relay_id"`
		}
		if err := security.Parse(raw, &query); err != nil {
			return nil, err
		}
		if query.RelayID == "" || len(query.RelayID) > 128 {
			return nil, errors.New("configured relay ID required")
		}
		return c.acceptanceReadiness(ctx, query.RelayID), nil
	case "relay.primary.status":
		return c.relayPrimary.snapshot(), nil
	case "relay.pool.diagnostics":
		var query struct {
			RelayID string `json:"relay_id"`
		}
		if err := security.Parse(raw, &query); err != nil {
			return nil, err
		}
		if query.RelayID == "" || len(query.RelayID) > 128 {
			return nil, errors.New("configured relay ID required")
		}
		c.mu.Lock()
		pool := c.relayPools[query.RelayID]
		c.mu.Unlock()
		if pool == nil {
			return nil, errors.New("relay pool unavailable")
		}
		return pool.Snapshot(), nil
	case "quality.diagnostics":
		return c.DropDiagnostics(), nil
	default:
		return nil, fmt.Errorf("unsupported IPC method %q", method)
	}
}

func (c *Controller) handleCapture(ctx context.Context, method string, raw json.RawMessage) (any, error) {
	switch method {
	case "capture.changes.marker":
		if backend, ok := c.Backend.(interface {
			CaptureChangeMarker() windowsplatform.ChangeCursor
		}); ok {
			return backend.CaptureChangeMarker(), nil
		}
		return nil, errors.New("capture change cursor unavailable; update backend")
	case "capture.changes":
		var query windowsplatform.ChangeQuery
		if err := security.Parse(raw, &query); err != nil {
			return nil, err
		}
		if backend, ok := c.Backend.(interface {
			CaptureChanges(windowsplatform.ChangeQuery) (windowsplatform.ChangePage, error)
		}); ok {
			return backend.CaptureChanges(query)
		}
		return nil, errors.New("capture changes unavailable; update backend")
	case "capture.marker":
		if backend, ok := c.Backend.(interface {
			CaptureMarker() windowsplatform.EvidenceMarker
		}); ok {
			return backend.CaptureMarker(), nil
		}
		return nil, errors.New("capture markers unavailable; update service/backend")
	case "capture.diagnostics":
		var query windowsplatform.EvidenceQuery
		if len(raw) > 0 && string(raw) != "null" {
			if err := security.Parse(raw, &query); err != nil {
				return nil, err
			}
		}
		if query.CreationTime != 0 && query.PID == 0 {
			return nil, errors.New("creation_time requires exact PID")
		}
		if query.Source != "" {
			if _, err := netip.ParseAddrPort(query.Source); err != nil {
				return nil, errors.New("invalid diagnostic source")
			}
		}
		if len(query.Domain) > 253 || strings.ContainsAny(query.Domain, " /\\\t\r\n") {
			return nil, errors.New("invalid diagnostic domain")
		}
		if query.Since != nil || query.CreationTime != 0 || query.Source != "" || query.Domain != "" {
			if query.Destination != "" {
				if _, err := netip.ParseAddrPort(query.Destination); err != nil {
					return nil, errors.New("invalid diagnostic destination")
				}
			}
			if backend, ok := c.Backend.(interface {
				DiagnosticsScoped(windowsplatform.EvidenceQuery) (windowsplatform.CaptureEvidence, error)
			}); ok {
				return backend.DiagnosticsScoped(query)
			}
			return nil, errors.New("trial-scoped capture diagnostics unavailable; update service/backend")
		}
		if query.Destination != "" {
			if _, err := netip.ParseAddrPort(query.Destination); err != nil {
				return nil, errors.New("invalid diagnostic destination")
			}
			if backend, ok := c.Backend.(interface {
				DiagnosticsTarget(uint32, string) windowsplatform.CaptureEvidence
			}); ok {
				return backend.DiagnosticsTarget(query.PID, query.Destination), nil
			}
			return nil, errors.New("scoped capture diagnostics unavailable")
		}
		if backend, ok := c.Backend.(interface {
			Diagnostics(uint32) windowsplatform.CaptureEvidence
		}); ok {
			return backend.Diagnostics(query.PID), nil
		}
		return nil, errors.New("capture diagnostics unavailable on this backend")
	default:
		return nil, fmt.Errorf("unsupported IPC method %q", method)
	}
}

func (c *Controller) handleProfileDelete(ctx context.Context, raw json.RawMessage) (any, error) {
	var query struct {
		ID string `json:"id"`
	}
	if e := security.Parse(raw, &query); e != nil {
		return nil, e
	}
	c.mu.Lock()
	p, ok := c.localProfiles[query.ID]
	if !ok || !p.Custom {
		c.mu.Unlock()
		return nil, errors.New("only local custom profiles can be removed")
	}
	c.mu.Unlock()
	if edgeSitesProfile(p) {
		guard, _ := json.Marshal(map[string]string{"profile_id": p.ID, "operation": "guard"})
		if _, err := c.handleEdge("edge.policy", guard); err != nil {
			return nil, err
		}
	}
	if e := c.reconfigure(query.ID, func() error {
		c.mu.Lock()
		delete(c.localProfiles, query.ID)
		c.mu.Unlock()
		c.Profiles.Delete(query.ID)
		c.Engine.SetPolicy(query.ID, routing.Policy{})
		return nil
	}); e != nil {
		return nil, e
	}
	if err := c.saveProfiles(); err != nil {
		return nil, err
	}
	return c.Profiles.List(), nil
}

func (c *Controller) handleProfileSet(ctx context.Context, raw json.RawMessage) (any, error) {
	activationStarted := time.Now()
	c.pruneTrials(time.Now())
	var p profiles.Profile
	if e := security.Parse(raw, &p); e != nil {
		return nil, e
	}
	// Old clients omit newly added policy fields. Preserve them for the
	// same executable identity; explicit null/empty values still clear them.
	var fields map[string]json.RawMessage
	if e := json.Unmarshal(raw, &fields); e != nil {
		return nil, e
	}
	wasNative := false
	for _, old := range c.Profiles.List() {
		if old.ID == p.ID && sameProfileExecutables(old.Executables, p.Executables) {
			wasNative = nativeBrowserProfile(old)
			if _, ok := fields["browser_auto_disabled"]; !ok {
				p.BrowserAutoDisabled = old.BrowserAutoDisabled
			}
			if _, ok := fields["browser_transport"]; !ok {
				p.BrowserTransport = old.BrowserTransport
			}
			if _, ok := fields["rules"]; !ok {
				p.Rules = old.Rules
			}
			if _, ok := fields["browser_recovery_rules"]; !ok {
				p.BrowserRecoveryRules = old.BrowserRecoveryRules
			}
			if _, ok := fields["identity"]; !ok {
				p.Identity = old.Identity
			}
			if _, ok := fields["fallback"]; !ok {
				p.Fallback = old.Fallback
			}
			if _, ok := fields["app_preset"]; !ok {
				p.AppPreset = old.AppPreset
			}
			if _, ok := fields["auto_network"]; !ok {
				p.AutoNetwork = old.AutoNetwork
			}
			if _, ok := fields["auto_revision"]; !ok {
				p.AutoRevision = old.AutoRevision
			}
			break
		}
	}
	if p.Trial != nil {
		if !time.Now().Before(p.Trial.Expires) || p.Trial.Expires.After(time.Now().Add(15*time.Minute)) {
			return nil, errors.New("trial lifetime bound")
		}
		root, err := c.discovery.Lookup(p.Trial.PID)
		if err != nil || root.CreationTime != p.Trial.CreationTime || len(p.Executables) != 1 || !strings.EqualFold(root.Path, p.Executables[0]) {
			return nil, errors.New("trial root identity unavailable")
		}
		p.Identity = profiles.IdentityFor(root.Path, "")
		p.Identity.Helpers = []string{p.Identity.Executable}
	}
	prepareAuto(&p)
	if edgeSitesProfile(p) && !nativeBrowserProfile(p) && p.Mode == profiles.Auto && c.BrowserOwnerSID != "" {
		c.browser.mu.Lock()
		ready := c.edgeReadyLocked(p)
		c.browser.mu.Unlock()
		if !ready {
			return nil, errors.New("Edge AUTO requires verified Edge PAC before publishing profile")
		}
	}
	if browserAuto(p) && !nativeBrowserProfile(p) && !edgeSitesProfile(p) && c.BrowserOwnerSID != "" {
		c.browser.mu.Lock()
		ready := c.browser.recoveryAddress != "" && c.browser.server != nil && c.browser.server.Confirmed(p.ID)
		c.browser.mu.Unlock()
		if !ready {
			return nil, errors.New("Chrome AUTO not activated: prepare CONNECT, install Chrome PAC and verify readiness before publishing AUTO")
		}
	}
	if p.Mode == profiles.Auto && p.LocalStrategyID != "" && p.AutoNetwork == "" {
		for _, old := range c.Profiles.List() {
			if old.ID == p.ID && old.Mode == profiles.DirectPlus && old.LocalStrategyID == p.LocalStrategyID {
				n := c.network.Load()
				if n == nil || time.Since(n.ObservedAt) > 45*time.Second || len(n.VPN) > 0 || len(n.Conflicts) > 0 {
					return nil, errors.New("fresh VPN-free network required to adopt configured DIRECT+ into AUTO")
				}
				p.AutoNetwork = n.Fingerprint
				p.AutoRevision = c.baselineRevision(p)
			}
		}
	}
	if p.Mode == profiles.Block && !c.Demo && (c.Backend == nil || !c.Backend.Status().Capabilities.TCP) {
		return nil, errors.New("BLOCK profile requires UDP/TCP capture; current backend does not provide it")
	}
	if err := p.Validate(); err != nil {
		return nil, err
	}
	if nativeBrowserProfile(p) {
		if err := c.nativeGuardReady(p); err != nil {
			return nil, err
		}
	}
	c.mu.Lock()
	nativeActive := c.enabled && c.settings.Automatic
	c.mu.Unlock()
	if nativeBrowserProfile(p) && nativeActive && !c.nativeBackendReady() {
		return nil, errors.New("NATIVE_CAPTURE_NOT_READY")
	}
	for _, old := range c.Profiles.List() {
		if old.ID == p.ID {
			a, _ := json.Marshal(old)
			b, _ := json.Marshal(p)
			if bytes.Equal(a, b) {
				return c.Profiles.List(), nil
			}
		}
	}
	reconfigure := c.reconfigure
	if nativeBrowserProfile(p) || wasNative {
		reconfigure = c.reconfigureBrowserNewConnections
	}
	if e := reconfigure(p.ID, func() error {
		if e := c.Profiles.Upsert(p); e != nil {
			return e
		}
		c.mu.Lock()
		c.localProfiles[p.ID] = p
		c.mu.Unlock()
		c.syncPolicies()
		return nil
	}); e != nil {
		return nil, e
	}
	if edgeProfile(p) && p.Mode != profiles.Auto {
		c.forgetEdgeProfile(p.ID)
	}
	if chromeProfile(p) && !browserAuto(p) {
		c.browser.mu.Lock()
		if c.browser.server != nil {
			c.browser.server.Forget(p.ID)
			if c.customPath != "" {
				if err := c.saveBrowserAddress(); err != nil {
					c.browser.mu.Unlock()
					return nil, err
				}
			}
		}
		c.browser.mu.Unlock()
	}
	if err := c.saveProfiles(); err != nil {
		return nil, err
	}
	if nativeBrowserProfile(p) && nativeActive {
		c.browser.native.activateAt(p.ID, false, activationStarted)
	}
	return c.Profiles.List(), nil
}

func (c *Controller) handleOptimize(ctx context.Context, raw json.RawMessage) (any, error) {
	activationStarted := time.Now()
	var v struct {
		Enabled bool `json:"enabled"`
	}
	if e := security.Parse(raw, &v); e != nil {
		return nil, e
	}
	c.activation.stopAutomatic.Store(!v.Enabled)
	if v.Enabled && !c.activationNetworkAllowed() {
		return nil, errors.New("ACTIVATION_REQUIRED")
	}
	if !c.browser.readiness.enforced.Load() && v.Enabled {
		c.mu.Lock()
		automatic := c.settings.Automatic
		c.mu.Unlock()
		if automatic {
			if err := c.requireChromeActivation(); err != nil {
				return nil, err
			}
		}
	}
	if !c.Demo && c.Backend == nil {
		return nil, errors.New("Windows capture backend is not configured")
	}
	c.mu.Lock()
	wasEnabled := c.enabled
	c.enabled = v.Enabled
	c.mu.Unlock()
	if !v.Enabled {
		if err := c.publishBrowserGuard(false); err != nil {
			return nil, err
		}
		if err := c.releaseBrowserAuthority(); err != nil {
			return nil, err
		}
		_ = c.cleanupBrowserPoliciesForMutation()
	}
	c.nativeBrowserActivation(v.Enabled, wasEnabled, activationStarted)
	if c.Backend != nil {
		if v.Enabled {
			if !c.Backend.Status().Ready {
				if e := c.Backend.Start(c.ctx, c.Classify); e != nil {
					c.mu.Lock()
					c.enabled = wasEnabled
					c.captureStartError = "CAPTURE_START_FAILED"
					c.mu.Unlock()
					return nil, e
				}
			}
		} else {
			if e := c.Backend.Stop(); e != nil {
				return nil, e
			}
		}
	}
	c.mu.Lock()
	c.enabled = v.Enabled
	c.captureStartError = ""
	c.mu.Unlock()
	// Existing proxy TCP stays pinned; stopping capture must not close a newly
	// admitted DIRECT compatibility socket or replay its application bytes.

	if v.Enabled && !wasEnabled {
		if b, ok := c.Backend.(interface{ RequestHotAttach(string) }); ok {
			b.RequestHotAttach("optimize_enabled")
		}
	}
	c.Measurements.Active.Store(v.Enabled)
	return c.Snapshot(), nil
}

func (c *Controller) handleSettingsSet(ctx context.Context, raw json.RawMessage) (any, error) {
	var s Settings
	if e := security.Parse(raw, &s); e != nil {
		return nil, e
	}
	if (s.Failover != "DIRECT" && s.Failover != "BLOCK") || (s.UpdateChannel != "stable" && s.UpdateChannel != "preview") {
		return nil, errors.New("invalid settings")
	}
	c.mu.Lock()
	oldSettings := c.settings
	c.mu.Unlock()
	if !c.browser.readiness.enforced.Load() && s.Automatic {
		c.mu.Lock()
		enabled := c.enabled
		c.mu.Unlock()
		if enabled {
			if err := c.requireChromeActivation(); err != nil {
				return nil, err
			}
		}
	}
	apply := func() error {
		c.mu.Lock()
		c.settings = s
		c.mu.Unlock()
		c.syncPolicies()
		return nil
	}
	var updateErr error
	if oldSettings.Automatic != s.Automatic || oldSettings.Failover != s.Failover {
		updateErr = c.reconfigure("", apply)
	} else {
		updateErr = apply()
	}
	if updateErr != nil {
		return nil, updateErr
	}

	if err := c.saveSettings(); err != nil {
		return nil, err
	}
	if !s.Automatic {
		_ = c.cleanupBrowserPoliciesForMutation()
	}
	return s, nil
}
