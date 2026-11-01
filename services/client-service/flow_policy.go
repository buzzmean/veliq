package clientservice

import (
	"context"
	"github.com/buzzmean/neexitlag/core/flowpolicy"
	"github.com/buzzmean/neexitlag/core/profiles"
	"github.com/buzzmean/neexitlag/core/routing"
	wp "github.com/buzzmean/neexitlag/platform/windows"
	"net"
	"path"
	"sort"
	"strings"
	"time"
)

func presetFor(p profiles.Profile) string {
	if p.AppPreset != "" {
		return p.AppPreset
	}
	for _, exe := range p.Executables {
		switch path.Base(strings.ToLower(strings.ReplaceAll(exe, "\\", "/"))) {
		case "discord.exe":
			return "discord"
		case "chatgpt.exe":
			return "openai"
		case "claude.exe":
			return "anthropic"
		case "telegram.exe":
			return "telegram"
		case "msedge.exe":
			return "openai-web"
		}
	}
	return ""
}

// relayFirstPreset marks applications whose services are blocked or region-locked
// for the user: every flow goes through the relay and never falls back to DIRECT
// (fail-closed), so the real address is not exposed and nothing silently degrades.
const discordVoiceFakeRepeats, discordVoiceFakeCutoff = 6, 2

func relayFirstPreset(preset string) bool {
	switch preset {
	case "openai", "openai-web", "anthropic", "telegram":
		return true
	}
	return false
}
func relayFirstReason(preset string) string {
	switch preset {
	case "anthropic":
		return "Anthropic relay-first: blocked service, consistent egress"
	case "telegram":
		return "Telegram relay-first: blocked service"
	}
	return "OpenAI consistent egress"
}
func prepareAuto(p *profiles.Profile) {
	if p.Mode != profiles.Auto {
		return
	}
	if browserAuto(*p) && len(p.BrowserRecoveryRules) > 0 {
		if len(p.Rules) == 0 {
			p.Rules = append([]flowpolicy.Rule(nil), p.BrowserRecoveryRules...)
		}
		p.BrowserRecoveryRules = nil
	}
	if p.AppPreset == "" {
		p.AppPreset = presetFor(*p)
	}
	if p.Fallback == "" && (p.AppPreset == "openai" || p.AppPreset == "openai-web" || p.AppPreset == "discord") {
		p.Fallback = flowpolicy.Required
	}
	if p.Identity == nil && p.AppPreset != "" && len(p.Executables) > 0 && strings.ContainsAny(p.Executables[0], "/\\") {
		p.Identity = profiles.IdentityFor(p.Executables[0], p.AppPreset)
	}
}

type groupBinding struct {
	identity   profiles.Identity
	profile    string
	trialPID   uint32
	trialBirth uint64
}

func (c *Controller) matchApplication(id wp.ProcessIdentity) (profiles.Profile, bool) {
	direct, hasDirect := c.Profiles.Match(id)
	possible := false
	for _, p := range c.Profiles.List() {
		if p.Identity != nil {
			for _, h := range p.Identity.Helpers {
				if strings.EqualFold(path.Base(strings.ReplaceAll(id.Path, "\\", "/")), h) {
					possible = true
				}
			}
		}
	}
	if !possible {
		return direct, hasDirect
	}
	c.groupMu.Lock()
	defer c.groupMu.Unlock()
	if b, ok := c.groupBindings[id.PID]; ok && b.identity.CreationTime == id.CreationTime && strings.EqualFold(b.identity.Path, id.Path) {
		for _, p := range c.Profiles.List() {
			if p.ID == b.profile && validGroupBinding(b, p) {
				return p, true
			}
		}
	}
	_, nativeAncestry := c.discovery.(interface {
		Ancestry(wp.ProcessIdentity) ([]wp.ProcessIdentity, error)
	})
	if nativeAncestry || c.groupAt.IsZero() || time.Since(c.groupAt) > time.Second {
		var all []wp.ProcessIdentity
		var err error
		if source, ok := c.discovery.(interface {
			Ancestry(wp.ProcessIdentity) ([]wp.ProcessIdentity, error)
		}); ok {
			all, err = source.Ancestry(id)
		} else {
			all, err = c.discovery.List()
		}
		if err != nil || len(all) > 4096 {
			return direct, hasDirect
		}
		c.groupAll = all
		c.groupAt = time.Now()
		live := map[uint32]profiles.Identity{}
		for _, v := range all {
			live[v.PID] = v
		}
		for pid, b := range c.groupBindings {
			if nativeAncestry {
				if pid == id.PID && b.identity.CreationTime != id.CreationTime {
					delete(c.groupBindings, pid)
				}
				continue
			}
			v, ok := live[pid]
			if !ok || v.CreationTime != b.identity.CreationTime || !strings.EqualFold(v.Path, b.identity.Path) {
				delete(c.groupBindings, pid)
			}
		}
	}
	if b, ok := c.groupBindings[id.PID]; ok && b.identity.CreationTime == id.CreationTime && strings.EqualFold(b.identity.Path, id.Path) {
		for _, p := range c.Profiles.List() {
			if p.ID == b.profile && validGroupBinding(b, p) {
				return p, true
			}
		}
	}
	// Discovery records parent birth identities from the same bounded snapshot.
	for _, v := range c.groupAll {
		if v.PID == id.PID && v.CreationTime == id.CreationTime && strings.EqualFold(v.Path, id.Path) {
			id = v
			break
		}
	}
	for _, p := range customFirst(c.Profiles.List()) {
		if p.GroupMatch(id, c.groupAll) {
			if len(c.groupBindings) >= 4096 {
				for pid := range c.groupBindings {
					delete(c.groupBindings, pid)
					break
				}
			}
			if len(c.groupBindings) < 4096 {
				b := groupBinding{identity: id, profile: p.ID}
				if p.Trial != nil {
					b.trialPID = p.Trial.PID
					b.trialBirth = p.Trial.CreationTime
				}
				c.groupBindings[id.PID] = b
			}
			return p, true
		}
	}
	return direct, hasDirect
}
func (c *Controller) scopedDecision(p profiles.Profile, id wp.ProcessIdentity, t wp.Tuple, base wp.Decision) wp.Decision {
	network := ""
	if n := c.network.Load(); n != nil && n.Error == "" && time.Since(n.ObservedAt) <= 45*time.Second {
		network = n.Fingerprint
	}
	base.Flow.Network = network
	resolve := func(domain string) wp.Decision {
		if network != "" {
			n := c.network.Load()
			if n == nil || n.Fingerprint != network {
				d := base
				d.Block = true
				d.Deferred = false
				d.ResolveDomain = nil
				d.Policy = flowpolicy.Result{Action: flowpolicy.Block, Fallback: flowpolicy.FailBlock, Source: "network_changed", Reason: "network changed before upstream decision"}
				return d
			}
		}
		d := c.evaluateFlow(p, id, t, base, domain, network)
		if (nativeBrowserProfile(p) || riotAuto(p) && t.Destination.Port() == 443) && t.Protocol == "tcp" && t.Destination.Port() != 53 {
			d.OriginDomain = domain
			d.NewConnectionsOnly = true
			d.OpenDeferred = func(ctx context.Context, decision wp.Decision, reason string) (net.Conn, wp.Decision, error) {
				return c.openNativeBrowser(ctx, p, id, t, decision, reason)
			}
		}
		return d
	}
	out := resolve("")
	out = c.browserQUICDecision(p, id, t, out)
	if nativeBrowserProfile(p) && t.Destination.Port() == 53 {
		return c.browserDNSDecision(p, id, t, out, network)
	}
	if t.Protocol == "tcp" && out.Policy.Source != "browser_dns" && (browserAuto(p) || riotAuto(p) && t.Destination.Port() == 443 || flowpolicy.NeedsDomain(p.Rules, "tcp") || p.Mode == profiles.Auto && !c.hasBaseline(p, network) && c.AutoLearned.HasApplication(network, applicationKey(p), "tcp", time.Now())) {
		// The existing redirect accepts the app connection before any upstream is
		// opened. The closure captures a profile snapshot; edits affect new flows.
		out.Deferred = true
		out.ResolveDomain = resolve
	}
	if t.Destination.Addr().Is6() && (out.Deferred || out.ProbeDirect) {
		out.Block = true
		out.ProbeDirect = false
		out.Deferred = false
		out.ResolveDomain = nil
		out.Policy.Action = flowpolicy.Block
		out.Policy.Fallback = flowpolicy.FailBlock
		out.Policy.Source = "unsupported_ipv6_domain_policy"
		out.Policy.Reason = "IPv6 domain/adaptive UDP decision unsupported; no native bypass"
	}
	return out
}
func (c *Controller) evaluateFlow(p profiles.Profile, id wp.ProcessIdentity, t wp.Tuple, d wp.Decision, domain, network string) wp.Decision {
	if browserAuto(p) {
		return applyFlowResult(p, d, c.browserFlow(p, id, t, domain, network), network, c.Local)
	}
	result, matched := flowpolicy.Evaluate(p.Rules, flowpolicy.Input{Protocol: t.Protocol, Destination: t.Destination, Domain: domain, Network: network})
	if !matched && p.Mode == profiles.Auto && !relayFirstPreset(presetFor(p)) && presetFor(p) != "discord" && domain != "" {
		target := domain
		if learned, ok := c.AutoLearned.Lookup(c.learnKey(p, network, t.Protocol, target, t.Destination.Port()), time.Now()); ok {
			if automaticRelayAllowed(p) || learned.Action != flowpolicy.Relay && learned.Action != flowpolicy.RelayRequired {
				result = learned
				matched = true
			}
		}
	}
	if !matched && p.Mode == profiles.Auto && c.hasBaseline(p, network) && p.LocalStrategyID != "" && c.Local.HasApplication(id.Path) {
		for _, local := range c.Local.Config().User {
			if local.ID == p.LocalStrategyID && local.Enabled && strings.EqualFold(strings.ReplaceAll(local.Application, "\\", "/"), strings.ReplaceAll(id.Path, "\\", "/")) {
				result = flowpolicy.Result{Action: flowpolicy.DirectPlus, Strategy: local.ID, Fallback: flowpolicy.FailOpen, Reason: "adopted operator-confirmed configuration on this network; domain guards remain in native engine", Source: "configured_baseline"}
				matched = true
				break
			}
		}
	}
	if !matched && p.Mode == profiles.Auto {
		relay := p.RelayID
		if relay == "" {
			relay = "VPS-01"
		}
		switch preset := presetFor(p); {
		case relayFirstPreset(preset):
			result = flowpolicy.Result{Action: flowpolicy.RelayRequired, RelayID: relay, Fallback: flowpolicy.Required, Reason: relayFirstReason(preset), Source: "preset"}
			matched = true
		case preset == "discord":
			result = flowpolicy.Result{Action: flowpolicy.RelayRequired, RelayID: relay, Fallback: flowpolicy.Required, Reason: "Discord control/update consistent egress", Source: "preset"}
			matched = true
			if t.Protocol == "udp" && t.Destination.Port() >= 1024 {
				result = flowpolicy.Result{Action: flowpolicy.Direct, RelayID: relay, Fallback: flowpolicy.FlowRelay, Reason: "Discord high-port UDP candidate; require bidirectional response", Source: "preset"}
			}
		}
	}
	if matched {
		d.Block = false
		d.Local = nil
		d.LocalStrategyID = ""
		d.Route = routing.Route{}
		d.Policy = result
		d.Network = network
		d.Group = p.ID
		switch result.Action {
		case flowpolicy.Block:
			d.Block = true
		case flowpolicy.Relay, flowpolicy.RelayRequired:
			d.Route = routing.Route{RelayID: result.RelayID}
		case flowpolicy.DirectPlus:
			d.Route = routing.Route{Kind: routing.DirectPlusRoute}
			d.Local = c.Local
			d.LocalStrategyID = result.Strategy
		}
		d.BlockOnFailure = result.Fallback == flowpolicy.Required || result.Fallback == flowpolicy.FailBlock
		d.ProbeDirect = result.Fallback == flowpolicy.FlowRelay
		if d.ProbeDirect && result.Source == "preset" && presetFor(p) == "discord" && t.Protocol == "udp" {
			// Flowseal Discord voice: fake x6 before each of the first two datagrams
			// on the DIRECT socket; adaptive health still falls back to relay.
			d.Flow.UDPFakePrelude, d.Flow.UDPFakeCutoff = discordVoiceFakeRepeats, discordVoiceFakeCutoff
			d.Policy.Reason = "Discord high-port UDP: DIRECT with fake prelude; require bidirectional response, else relay"
		}
	} else {
		if p.Fallback != "" {
			d.BlockOnFailure = p.Fallback == flowpolicy.Required || p.Fallback == flowpolicy.FailBlock
		}
		d.Network = network
		d.Group = p.ID
		d.Policy = flowpolicy.Result{Action: flowpolicy.Action(d.Route.Type()), Strategy: d.LocalStrategyID, RelayID: d.Route.RelayID, Fallback: flowpolicy.FailOpen, Reason: "application default", Source: "profile"}
		if d.BlockOnFailure {
			d.Policy.Fallback = flowpolicy.Required
		}
		if p.Mode == profiles.Auto && !automaticRelayAllowed(p) {
			d.Policy.Source = "auto_direct_default"
			d.Policy.Reason = "games and unregistered applications stay DIRECT; relay requires explicit MANUAL or a flow rule"
		}
	}
	// Only policies with explicit per-flow semantics bypass the legacy selector.
	if matched || p.Fallback != "" || len(p.Rules) > 0 || p.Mode == profiles.Auto && !automaticRelayAllowed(p) {
		d.Flow.PinnedPolicy = &routing.Policy{Route: d.Route, Block: d.Block, BlockOnFailure: d.BlockOnFailure}
	}
	return d
}

func validGroupBinding(b groupBinding, p profiles.Profile) bool {
	if p.Trial == nil {
		return b.trialPID == 0
	}
	return p.Trial.PID == b.trialPID && p.Trial.CreationTime == b.trialBirth && time.Now().Before(p.Trial.Expires)
}

func (c *Controller) pruneTrials(now time.Time) {
	for _, p := range c.Profiles.List() {
		if p.Trial != nil && !now.Before(p.Trial.Expires) {
			c.Profiles.Delete(p.ID)
			c.mu.Lock()
			delete(c.localProfiles, p.ID)
			c.mu.Unlock()
			c.Engine.SetPolicy(p.ID, routing.Policy{})
		}
	}
}

func sameProfileExecutables(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for n := range a {
		if !strings.EqualFold(strings.ReplaceAll(a[n], "\\", "/"), strings.ReplaceAll(b[n], "\\", "/")) {
			return false
		}
	}
	return true
}

// customFirst orders the user's own profiles before built-in ones, the same
// precedence profiles.Registry.Match applies to ordinary matching.
func customFirst(all []profiles.Profile) []profiles.Profile {
	sort.SliceStable(all, func(a, b int) bool { return all[a].Custom && !all[b].Custom })
	return all
}

// dropShadowedBuiltIns removes a built-in relay-first profile when the user's own
// saved profiles already cover the same executable name. The user's profile wins;
// two profiles for one program would make matching ambiguous.
func dropShadowedBuiltIns(registry *profiles.Registry, saved []profiles.Profile) {
	names := map[string]bool{}
	ids := map[string]bool{}
	for _, p := range saved {
		ids[p.ID] = true
		for _, exe := range p.Executables {
			names[path.Base(strings.ToLower(strings.ReplaceAll(exe, "\\", "/")))] = true
		}
	}
	for _, id := range profiles.BuiltInRelayFirstIDs {
		if ids[id] {
			continue // the saved copy replaces the built-in one through Upsert
		}
		for _, p := range registry.List() {
			if p.ID != id {
				continue
			}
			for _, exe := range p.Executables {
				if names[path.Base(strings.ToLower(exe))] {
					registry.Delete(id)
					break
				}
			}
		}
	}
}

// directOnlyFlow is true for traffic that must never reach the relay: DNS to any resolver
// (TCP or UDP port 53) and anything that is not a public Internet destination (the router,
// LAN hosts, loopback, link-local, multicast, CGNAT). Protected-domain data flows go to
// public addresses and are unaffected.
func directOnlyFlow(t wp.Tuple) bool {
	return t.Destination.Port() == 53 || routing.LocalDestination(t.Destination.Addr())
}
