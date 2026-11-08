package clientservice

// Edge has its own listener, PAC, readiness and recovery state. Only the existing
// immutable per-origin planner/open path is shared with Chrome.
import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/buzzmean/neexitlag/core/browserproxy"
	"github.com/buzzmean/neexitlag/core/flowpolicy"
	"github.com/buzzmean/neexitlag/core/profiles"
	"github.com/buzzmean/neexitlag/core/security"
	wp "github.com/buzzmean/neexitlag/platform/windows"
)

type edgeSaved struct {
	Address     string             `json:"address"`
	ExpectedPAC string             `json:"expected_pac"`
	Recovery    string             `json:"recovery_address"`
	Ready       []string           `json:"ready_profiles"`
	Owned       []string           `json:"owned_policy"`
	GuardPAC    string             `json:"guard_pac,omitempty"`
	Silent      browserSilentState `json:"silent_activation"`
}
type edgeRuntime struct {
	lastError                string
	healthProfile, healthURL string
	readinessFailure         string
	saved                    edgeSaved
	server                   *browserproxy.Server
	// Test embedders may provide an isolated policy store. Production uses HKU.
	write  func(string, []string, string) error
	remove func(string, []string) error
	active func(string, string) bool
}

func edgeExecutable(exe string) bool {
	return strings.EqualFold(filepath.Base(strings.ReplaceAll(exe, `\`, "/")), "msedge.exe")
}
func edgeSitesProfile(p profiles.Profile) bool { return edgeProfile(p) && p.AppPreset == "edge-sites" }
func isEdgeMutation(method string) bool {
	return method == "edge.silent.apply" || method == "edge.prepare" || method == "edge.confirm" || method == "edge.policy"
}
func edgeProfile(p profiles.Profile) bool {
	if len(p.Executables) == 0 {
		return false
	}
	for _, exe := range p.Executables {
		if !edgeExecutable(exe) {
			return false
		}
	}
	return true
}
func (c *Controller) edgeLocked() *edgeRuntime {
	if c.browser.edge == nil {
		c.browser.edge = &edgeRuntime{}
	}
	return c.browser.edge
}
func (e *edgeRuntime) policyActive(sid string) bool {
	if e.active != nil {
		return e.active(sid, e.saved.ExpectedPAC)
	}
	return wp.EdgeProxyPolicyActive(sid, e.saved.ExpectedPAC)
}
func (e *edgeRuntime) guardActive(sid string) bool {
	if e.saved.GuardPAC == "" {
		return false
	}
	if e.active != nil {
		return e.active(sid, e.saved.GuardPAC)
	}
	return wp.EdgeProxyPolicyActive(sid, e.saved.GuardPAC)
}
func (c *Controller) edgeOwner(ctx context.Context, source, local netip.AddrPort) (browserproxy.Owner, error) {
	id, err := wp.LookupTCPPeer(source, local)
	if err != nil {
		return browserproxy.Owner{}, browserproxy.ErrOwnerLookup
	}
	sid, err := wp.ProcessUserSID(id)
	if err != nil {
		return browserproxy.Owner{}, browserproxy.ErrOwnerToken
	}
	if c.BrowserOwnerSID == "" || sid != c.BrowserOwnerSID {
		return browserproxy.Owner{}, browserproxy.ErrOwnerSID
	}
	p, ok := c.matchApplication(id)
	if !ok || !edgeProfile(p) || p.Trial != nil {
		return browserproxy.Owner{}, browserproxy.ErrOwnerProfile
	}
	return browserproxy.Owner{PID: id.PID, Birth: id.CreationTime, Exe: id.Path, Profile: p.ID}, nil
}
func (c *Controller) edgeOwnerProfile(owner browserproxy.Owner) (profilesResult, error) {
	id := wp.ProcessIdentity{PID: owner.PID, CreationTime: owner.Birth, Path: owner.Exe}
	if !wp.IsCurrent(id) {
		return profilesResult{}, errors.New("Edge owner exited/reused")
	}
	p, ok := c.matchApplication(id)
	if !ok || !edgeProfile(p) || p.Trial != nil || p.ID != owner.Profile {
		return profilesResult{}, errors.New("Edge AUTO profile changed")
	}
	network := ""
	if n := c.network.Load(); n != nil && n.Error == "" && time.Since(n.ObservedAt) <= 45*time.Second {
		network = n.Fingerprint
	}
	c.mu.Lock()
	routingEnabled := c.enabled && c.settings.Automatic
	enabled := routingEnabled && p.Mode == profiles.Auto && (edgeSitesProfile(p) || nativeBrowserProfile(p))
	c.mu.Unlock()
	if routingEnabled && p.Mode != profiles.Auto && p.Mode != profiles.Direct {
		return profilesResult{}, errors.New("Edge AUTO profile changed")
	}
	return profilesResult{profile: p, id: id, network: network, enabled: enabled, routingDisabled: !routingEnabled}, nil
}
func (c *Controller) edgeRecoveryOwner(ctx context.Context, source, local, original, listener netip.AddrPort) (browserproxy.Owner, error) {
	helper, err := wp.LookupTCPPeer(source, local)
	if err != nil {
		return browserproxy.Owner{}, browserproxy.ErrOwnerLookup
	}
	program, err := os.Executable()
	if c.BrowserRecoveryExecutable != "" {
		program = c.BrowserRecoveryExecutable
	}
	if err != nil || !strings.EqualFold(helper.Path, program) {
		return browserproxy.Owner{}, browserproxy.ErrOwnerProfile
	}
	sid, err := wp.ProcessUserSID(helper)
	if err != nil || sid != c.BrowserOwnerSID {
		return browserproxy.Owner{}, browserproxy.ErrOwnerSID
	}
	return c.edgeOwner(ctx, original, listener)
}
func (c *Controller) listenEdge(e *edgeRuntime) error {
	if e.server != nil {
		return nil
	}
	server, err := browserproxy.Listen(c.ctx, browserproxy.Config{TransportCheck: c.transportCheckSettings, RequireClientHelloReplay: true, Address: e.saved.Address, Authorize: c.edgeOwner, AuthorizeForwarded: c.edgeRecoveryOwner, Plan: c.browserPlan, Open: c.browserOpen, OpenPlan: c.browserOpenPlan, TransformApplied: c.browserTransform, OnStall: c.browserStall, OnDirectAnswered: c.browserDirectAnswered})
	if err != nil {
		return err
	}
	e.server = server
	e.saved.Address = server.Address()
	return nil
}
func edgeGuard(p profiles.Profile) ([]string, bool) {
	domains := []string{}
	strict := false
	for _, r := range append(append([]flowpolicy.Rule{}, p.Rules...), p.BrowserRecoveryRules...) {
		if r.Action == flowpolicy.Direct {
			continue
		}
		if len(r.Domains) == 0 {
			strict = true
		} else {
			domains = append(domains, r.Domains...)
		}
	}
	return domains, strict
}
func edgeClosedPAC(p profiles.Profile) string {
	domains, strict := edgeGuard(p)
	domains = append(domains, "chatgpt.com", "openai.com", "oaistatic.com", "oaiusercontent.com", "chat.com", "youtube.com", "youtu.be", "googlevideo.com", "ytimg.com", "youtube-nocookie.com", "ggpht.com")
	raw, _ := json.Marshal(domains)
	script := "var guarded=" + string(raw) + ";var strict="
	if strict {
		script += "true"
	} else {
		script += "false"
	}
	script += `;function FindProxyForURL(url,host){host=host.toLowerCase().replace(/\.$/,'');for(var i=0;i<guarded.length;i++){var d=guarded[i].toLowerCase().replace(/\.$/,'');if(host===d||host.slice(-(d.length+1))==='.'+d)return 'PROXY fail-closed.neexitlag.invalid:9';}return strict?'PROXY fail-closed.neexitlag.invalid:9':'DIRECT';}`
	return "data:application/x-ns-proxy-autoconfig;base64," + base64.StdEncoding.EncodeToString([]byte(script))
}

// Recover only our known PAC framing when upgrading an old journal without a
// profile/guard field. Never guess away custom protected domains; corrupt state
// yields a strict guard, not a silent DIRECT authorization.
func edgeLegacyGuard(saved edgeSaved) string {
	candidates := []string{saved.ExpectedPAC}
	for _, owned := range saved.Owned {
		var value struct {
			PAC string `json:"ProxyPacUrl"`
		}
		if json.Unmarshal([]byte(owned), &value) == nil {
			candidates = append(candidates, value.PAC)
		}
	}
	for _, pac := range candidates {
		script, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(pac, "data:application/x-ns-proxy-autoconfig;base64,"))
		if err != nil {
			continue
		}
		for _, prefix := range []string{"var protectedSuffixes=", "var guarded="} {
			text := string(script)
			if !strings.HasPrefix(text, prefix) {
				continue
			}
			var domains []string
			if json.NewDecoder(strings.NewReader(strings.TrimPrefix(text, prefix))).Decode(&domains) != nil || len(domains) > 2048 {
				continue
			}
			valid := true
			for _, domain := range domains {
				if _, err := browserproxy.CanonicalHost(domain); err != nil {
					valid = false
					break
				}
			}
			if !valid {
				continue
			}
			strict := strings.Contains(text, "var strictProxy=true;") || strings.Contains(text, "var strict=true;")
			if !strict && !strings.Contains(text, "var strictProxy=false;") && !strings.Contains(text, "var strict=false;") {
				continue
			}
			profile := profiles.Profile{Rules: []flowpolicy.Rule{{Domains: domains, Action: flowpolicy.RelayRequired}}}
			if strict {
				profile.Rules = append(profile.Rules, flowpolicy.Rule{Action: flowpolicy.RelayRequired})
			}
			return edgeClosedPAC(profile)
		}
	}
	if len(saved.Owned) > 0 || saved.ExpectedPAC != "" {
		return edgeClosedPAC(profiles.Profile{Rules: []flowpolicy.Rule{{Action: flowpolicy.RelayRequired}}})
	}
	return edgeClosedPAC(profiles.Profile{})
}

func edgePolicyValue(pac string) string {
	raw, _ := json.Marshal(map[string]any{"ProxyMode": "pac_script", "ProxyPacUrl": pac, "ProxyPacMandatory": true})
	return string(raw)
}
func (c *Controller) saveEdge(e *edgeRuntime) error {
	if c.customPath == "" {
		return nil
	}
	if e.server != nil {
		e.saved.Ready = e.server.Snapshot().ReadyProfiles
	}
	raw, err := json.Marshal(e.saved)
	if err != nil {
		return err
	}
	dir := filepath.Dir(c.customPath)
	if err = os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, ".edge-transport-*")
	if err != nil {
		return err
	}
	name := f.Name()
	defer os.Remove(name)
	if err = f.Chmod(0600); err == nil {
		_, err = f.Write(raw)
	}
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	return os.Rename(name, filepath.Join(dir, "edge-transport.json"))
}
func (c *Controller) writeEdgePolicy(e *edgeRuntime, pac string) error {
	if err := c.browserPolicyPublishReadyLocked(true); err != nil {
		return err
	}
	if c.browser.readiness.enforced.Load() {
		if pac != e.saved.ExpectedPAC {
			_ = c.cleanupOwnedBrowserPoliciesLocked(func() *bool { v := true; return &v }())
			return nil
		}
		var err error
		pac, err = browserproxy.AvailabilityPAC(pac)
		if err != nil {
			return err
		}
		e.saved.ExpectedPAC = pac
	}
	next := edgePolicyValue(pac)
	// Journal both authorized values before touching HKU: crash between the two
	// writes can safely resume, but a foreign value is never overwritten.
	old := append([]string(nil), e.saved.Owned...)
	if len(old) > 0 {
		old = old[len(old)-1:]
	}
	e.saved.Owned = append(old, next)
	if err := c.saveEdge(e); err != nil {
		e.saved.Owned = old
		return err
	}
	write := e.write
	if write == nil {
		write = wp.EdgeProxyPolicyWrite
	}
	if err := write(c.BrowserOwnerSID, e.saved.Owned, next); err != nil {
		e.saved.Owned = old
		_ = c.saveEdge(e) // Preserve original write error if persistence is unavailable too.
		return err
	}
	return nil
}
func (c *Controller) handleEdge(method string, raw json.RawMessage) (result any, err error) {
	c.browser.mu.Lock()
	defer c.browser.mu.Unlock()
	e := c.edgeLocked()
	defer func() {
		if err != nil {
			e.lastError = method + ": " + edgeErrorCode(err)
			slog.Warn("Edge operation failed", "method", method, "code", edgeErrorCode(err))
			err = errors.New(e.lastError)
		}
	}()
	if method == "edge.status" {
		snapshot := browserproxy.Snapshot{ReadyProfiles: []string{}, Failures: map[string]uint64{}, Records: []browserproxy.Record{}}
		if e.server != nil {
			snapshot = e.server.Snapshot()
		}
		snapshot.RecoveryAddress = e.saved.Recovery
		snapshot.PolicyReady = e.policyActive(c.BrowserOwnerSID)
		if c.browser.readiness.enforced.Load() {
			snapshot.PolicyReady = snapshot.PolicyReady && c.browser.readiness.laneReady(1) && c.browserPolicyBaseReason() == ""
		}
		view := browserStatusView{PolicyRefresh: wp.BrowserPolicyRefreshStatus(), Snapshot: snapshot, DirectTimeouts: c.browser.directTimeouts.Stats(), RelayUsage: c.relayUsageLocked()}
		view.SilentActivation = c.silentViewLocked(true, snapshot)
		view.bound()
		state := "NOT_PREPARED"
		if e.server != nil && e.healthProfile != "" {
			state = e.server.ReadinessState(e.healthProfile, e.healthURL)
		}
		if e.readinessFailure != "" {
			state = e.readinessFailure
		}
		if len(view.SilentActivation.ConfiguredProfiles) > 0 {
			state = view.SilentActivation.State
		}
		nonceState := state
		transportMode := "PAC_LEGACY"
		for _, p := range c.Profiles.List() {
			if !edgeProfile(p) || !nativeBrowserProfile(p) {
				continue
			}
			transportMode = "NATIVE_ARMED_PAC_GUARD"
			state = "NATIVE_CAPTURE_NOT_READY"
			if c.nativeBackendReady() && e.server != nil && (e.policyActive(c.BrowserOwnerSID) || e.guardActive(c.BrowserOwnerSID)) {
				state = "NATIVE_ARMED_NO_NEW_FLOW"
				c.browser.native.mu.Lock()
				timing := c.browser.native.profiles[p.ID]
				c.browser.native.mu.Unlock()
				if timing.Opened > 0 {
					state = "NATIVE_UPSTREAM_OPENED_NO_EXCHANGE"
					if !timing.FirstExchange.IsZero() {
						state = "NATIVE_TUNNEL_OBSERVED"
					}
				} else {
					for _, m := range snapshot.PathMetrics {
						if m.Profile == p.ID && m.Opened > 0 {
							state = "PAC_TUNNEL_OBSERVED_NATIVE_IDLE"
						}
					}
				}
			}
			break
		}
		nativeState := c.nativeBrowserReadiness(true)
		if nativeState != "" && !e.policyActive(c.BrowserOwnerSID) && !e.guardActive(c.BrowserOwnerSID) {
			transportMode = "NATIVE_NEW_TCP"
			state = nativeState
			nonceState = "NOT_REQUIRED_FOR_NATIVE"
		}
		pendingProfile := e.healthProfile
		if transportMode == "NATIVE_ARMED_PAC_GUARD" || transportMode == "NATIVE_NEW_TCP" {
			pendingProfile = ""
		}
		guardRaw, _ := base64.StdEncoding.DecodeString(strings.TrimPrefix(e.saved.GuardPAC, "data:application/x-ns-proxy-autoconfig;base64,"))
		rollback := e.guardActive(c.BrowserOwnerSID) && strings.Contains(string(guardRaw), "fail-closed.neexitlag.invalid")
		return struct {
			TransportMode       string `json:"transport_mode"`
			PACNonceReadiness   string `json:"pac_nonce_readiness"`
			OwnedGuardInstalled bool   `json:"owned_guard_installed"`
			browserStatusView
			LastError           string `json:"last_error"`
			ActivationVersion   int    `json:"activation_version"`
			ReadinessState      string `json:"readiness_state"`
			PendingProfile      string `json:"pending_profile"`
			RollbackGuardActive bool   `json:"rollback_guard_active"`
		}{transportMode, nonceState, e.policyActive(c.BrowserOwnerSID) || e.guardActive(c.BrowserOwnerSID), view, e.lastError, 3, state, pendingProfile, rollback}, nil
	}
	if c.BrowserOwnerSID == "" {
		return nil, errors.New("Edge requires installation owner SID")
	}
	var q struct {
		Profile   string `json:"profile_id"`
		Directory string `json:"directory"`
		Recovery  string `json:"recovery_address"`
		Health    string `json:"health_url"`
		Operation string `json:"operation"`
		Phase     string `json:"phase"`
		Code      string `json:"code"`
	}
	if err := security.Parse(raw, &q); err != nil {
		return nil, err
	}
	var p profiles.Profile
	found := false
	for _, candidate := range c.Profiles.List() {
		if candidate.ID == q.Profile && edgeProfile(candidate) && candidate.Trial == nil {
			p = candidate
			found = true
			break
		}
	}
	if !found && !(method == "edge.policy" && q.Operation == "guard") && method != "edge.failure" {
		return nil, errors.New("Edge profile required")
	}
	switch method {
	case "edge.failure":
		if !edgeGUIFailureAllowed(q.Phase, q.Code) {
			return nil, errors.New("invalid Edge failure code")
		}
		e.lastError = q.Phase + ": " + q.Code
		return map[string]bool{"recorded": true}, nil
	case "edge.prepare":
		c.mu.Lock()
		automatic := c.settings.Automatic
		c.mu.Unlock()
		if !automatic {
			return nil, errors.New("Edge site routing requires Automatic routing enabled")
		}
		for _, other := range c.Profiles.List() {
			if other.ID != p.ID && edgeSitesProfile(other) && other.Mode == profiles.Auto {
				return nil, errors.New("another Edge site profile is active; keep its PAC intact")
			}
		}
		if (p.Mode != profiles.Auto && p.Mode != profiles.Direct) || q.Directory == "" || len(q.Directory) > 2048 {
			return nil, errors.New("Edge DIRECT/AUTO profile and persistent directory required")
		}
		if _, err := netip.ParseAddrPort(q.Recovery); err != nil {
			return nil, errors.New("owner-scoped Edge recovery endpoint required")
		}
		if err := c.listenEdge(e); err != nil {
			return nil, err
		}
		domains, strict := edgeGuard(p)
		args, err := browserproxy.ChromeArgumentsWithRecovery(e.server.Address(), q.Directory, domains, strict, q.Recovery)
		if err != nil {
			return nil, err
		}
		health, err := e.server.Challenge(p.ID)
		if err != nil {
			return nil, err
		}
		e.healthProfile, e.healthURL = p.ID, health
		e.readinessFailure = ""
		if c.browser.readiness.enforced.Load() {
			available, err := browserproxy.AvailabilityPAC(strings.TrimPrefix(args[1], "--proxy-pac-url="))
			if err != nil {
				return nil, err
			}
			args[1] = "--proxy-pac-url=" + available
		}
		e.saved.ExpectedPAC = strings.TrimPrefix(args[1], "--proxy-pac-url=")
		e.saved.GuardPAC = edgeClosedPAC(p)
		e.saved.Recovery = q.Recovery
		if err = c.saveEdge(e); err != nil {
			return nil, err
		}
		program, _ := os.Executable()
		return map[string]any{"arguments": args, "recovery_arguments": args, "address": e.server.Address(), "health_url": health, "recovery_program": program, "recovery_settings": browserproxy.RecoverySettings{CheckTarget: c.browser.readiness.target, CheckToken: c.browser.readiness.token, GuardFile: c.browserGuardFile(), Primary: e.server.Address(), Profile: p.ID, Domains: domains, Strict: strict}, "scope": "Edge only; Chrome and Windows proxy unchanged"}, nil
	case "edge.policy":
		pac := e.saved.ExpectedPAC
		switch q.Operation {
		case "guard":
			if found {
				var guardErr error
				pac, guardErr = c.edgeRollbackPAC(e, p)
				if guardErr != nil {
					return nil, guardErr
				}
				e.saved.GuardPAC = pac
			} else {
				pac = e.saved.GuardPAC
				if pac == "" {
					pac = edgeLegacyGuard(e.saved)
				}
			}
		case "install":
			if pac == "" || e.server == nil || !e.server.Snapshot().Listening || e.saved.Recovery == "" {
				return nil, errors.New("prepare Edge before installing policy")
			}
		default:
			return nil, errors.New("unsupported Edge policy operation")
		}
		if err := c.writeEdgePolicy(e, pac); err != nil {
			return nil, err
		}
		if q.Operation == "guard" && e.server != nil && !nativeBrowserProfile(p) {
			e.server.Forget(p.ID)
			e.server.CloseConnections()
			if err := c.saveEdge(e); err != nil {
				return nil, err
			}
		}
		ordinaryDirect := false
		if q.Operation == "guard" {
			script, _ := base64.StdEncoding.DecodeString(strings.TrimPrefix(pac, "data:application/x-ns-proxy-autoconfig;base64,"))
			ordinaryDirect = strings.Contains(string(script), "var strict=false;")
		}
		return map[string]bool{"applied": true, "guard": q.Operation == "guard", "ordinary_direct": ordinaryDirect}, nil
	case "edge.confirm":
		if e.server == nil || e.saved.Recovery == "" || !e.policyActive(c.BrowserOwnerSID) || !e.server.HealthVerified(p.ID, q.Health) {
			e.readinessFailure = "LISTENER_UNAVAILABLE"
			if e.server != nil {
				e.readinessFailure = e.server.ReadinessState(p.ID, q.Health)
			}
			if !e.policyActive(c.BrowserOwnerSID) {
				e.readinessFailure = "POLICY_NOT_ACTIVE"
			}
			// Roll back even if the GUI disappears after confirm or Edge never contacted
			// the proxy. Keep an inline domain guard: URLBlocklist is navigation-only and
			// cannot replace a PAC network boundary for protected subresources.
			var guardErr error
			e.saved.GuardPAC, guardErr = c.edgeRollbackPAC(e, p)
			if guardErr != nil {
				return nil, guardErr
			}
			if err := c.writeEdgePolicy(e, e.saved.GuardPAC); err != nil {
				return nil, err
			}
			if e.server != nil && !nativeBrowserProfile(p) {
				e.server.Forget(p.ID)
				e.server.CloseConnections()
			}
			if err := c.saveEdge(e); err != nil {
				return nil, err
			}

			return nil, errors.New("Edge PAC readiness not observed: policy, owner/SID or nonce")
		}
		if !e.server.AuthorizeProfile(p.ID, q.Health) {
			return nil, errors.New("Edge activation proof expired/changed")
		}
		e.lastError = "" // A fresh actual Edge policy/nonce proof supersedes restore errors.
		if err := c.saveEdge(e); err != nil {
			return nil, err
		}
		return map[string]bool{"ready": true}, nil
	}
	return nil, errors.New("unsupported Edge IPC")
}
func (c *Controller) edgeReadyLocked(p profiles.Profile) bool {
	e := c.browser.edge
	return e != nil && e.server != nil && e.server.Snapshot().Listening && e.saved.Recovery != "" && (e.server.Confirmed(p.ID) || c.silentConfiguredLocked(p.ID, true)) && e.policyActive(c.BrowserOwnerSID)
}

// Publishing a legacy PAC profile after edge.confirm completes the same activation,
// rather than revoking its PAC before optimize can observe it. Retain only an
// unchanged executable/guard scope with a confirmed live listener and policy.
// Other edits keep the existing cleanup path; no proof transfers to a new scope.
func (c *Controller) preserveConfirmedEdgeProfileUpdate(raw json.RawMessage, previous []profiles.Profile) bool {
	if c.browser.readiness.enforced.Load() {
		return false // The availability contract keeps its existing health/cleanup path.
	}
	var q struct {
		ID string `json:"id"`
	}
	if json.Unmarshal(raw, &q) != nil {
		return false
	}
	var old profiles.Profile
	for _, p := range previous {
		if p.ID == q.ID {
			old = p
			break
		}
	}
	if !edgeProfile(old) || old.Trial != nil || nativeBrowserProfile(old) || (old.Mode != profiles.Direct && old.Mode != profiles.Auto) {
		return false
	}
	c.activationMu.Lock()
	defer c.activationMu.Unlock()
	c.browser.mu.Lock()
	defer c.browser.mu.Unlock()
	for _, p := range c.Profiles.List() {
		if p.ID == q.ID && edgeSitesProfile(p) && p.Mode == profiles.Auto && p.Trial == nil && !nativeBrowserProfile(p) && sameProfileExecutables(old.Executables, p.Executables) && edgeClosedPAC(old) == edgeClosedPAC(p) {
			e := c.browser.edge
			return e != nil && e.server != nil && e.server.Confirmed(p.ID) && c.edgeReadyLocked(p)
		}
	}
	return false
}

func (c *Controller) requireEdgeActivation() error {
	if c.BrowserOwnerSID == "" {
		return nil
	}
	c.browser.mu.Lock()
	defer c.browser.mu.Unlock()
	for _, p := range c.Profiles.List() {
		if nativeBrowserProfile(p) {
			if err := c.nativeGuardReadyLocked(p); err != nil {
				return err
			}
			if !c.nativeBackendConfigured() {
				return errors.New("NATIVE_CAPTURE_NOT_CONFIGURED")
			}
			continue
		}
		if edgeSitesProfile(p) && p.Mode == profiles.Auto && p.Trial == nil && !c.edgeReadyLocked(p) {
			return errors.New("Edge AUTO requires verified Edge CONNECT/PAC; capture unchanged")
		}
	}
	return nil
}
func (c *Controller) closeEdgeConnections() {
	c.browser.mu.Lock()
	var server *browserproxy.Server
	if e := c.browser.edge; e != nil {
		server = e.server
	}
	c.browser.mu.Unlock()
	if server != nil {
		server.CloseConnections()
	}
}
func (c *Controller) closeEdge() {
	c.browser.mu.Lock()
	var server *browserproxy.Server
	if e := c.browser.edge; e != nil {
		server = e.server
	}
	c.browser.mu.Unlock()
	if server != nil {
		server.Close()
	}
}
func (c *Controller) loadEdgeTransport() error {
	if c.customPath == "" {
		return nil
	}
	f, err := os.Open(filepath.Join(filepath.Dir(c.customPath), "edge-transport.json"))
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	raw, err := io.ReadAll(io.LimitReader(f, 262145))
	// Reapply may atomically replace this same journal. Windows does not
	// permit that while our non-delete-sharing read handle is still open.
	closeErr := f.Close()
	if err != nil || len(raw) > 262144 {
		return errors.New("invalid saved Edge state")
	}
	if closeErr != nil {
		return closeErr
	}
	var saved edgeSaved
	if err = security.Parse(raw, &saved); err != nil {
		return err
	}
	if len(saved.Ready) > 128 || len(saved.Owned) > 2 || len(saved.ExpectedPAC) > 128*1024 || len(saved.GuardPAC) > 128*1024 {
		return errors.New("invalid saved Edge state")
	}
	if saved.Address != "" {
		addr, err := netip.ParseAddrPort(saved.Address)
		if err != nil || addr.Addr() != netip.MustParseAddr("127.0.0.1") || addr.Port() == 0 {
			return errors.New("invalid saved Edge endpoint")
		}
	} else if saved.ExpectedPAC != "" || saved.Recovery != "" || len(saved.Ready) != 0 {
		return errors.New("incomplete saved Edge transport")
	}
	c.browser.mu.Lock()
	defer c.browser.mu.Unlock()
	e := c.edgeLocked()
	e.saved = saved
	if saved.Address == "" {
		return nil
	} // Guard-only installation also survives a restart.
	if err = c.listenEdge(e); err != nil {
		return err
	}
	e.server.RestoreConfirmed(saved.Ready)
	if len(e.saved.Silent.Profiles) > 0 {
		return c.reapplySilentLocked(true)
	}
	return nil
}

func (c *Controller) forgetEdgeProfile(id string) {
	c.browser.mu.Lock()
	defer c.browser.mu.Unlock()
	if e := c.browser.edge; e != nil && e.server != nil {
		e.server.Forget(id)
		_ = c.saveEdge(e)
	}
}

// A broken Edge port/state must not prevent the existing Chrome listener from
// restoring. Edge stays unready/fail-closed and the GUI can repair only that lane.
func (c *Controller) restoreEdgeTransport() {
	if err := c.loadEdgeTransport(); err != nil {
		c.browser.mu.Lock()
		c.edgeLocked().lastError = "edge.restore: " + edgeErrorCode(err)
		c.browser.mu.Unlock()
	}
}
