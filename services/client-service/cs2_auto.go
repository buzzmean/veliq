package clientservice

import (
	"encoding/json"
	"errors"
	"net/netip"
	"path"
	"strings"
	"time"

	"github.com/buzzmean/veliq/core/flowpolicy"
	"github.com/buzzmean/veliq/core/gameudp"
	"github.com/buzzmean/veliq/core/profiles"
	"github.com/buzzmean/veliq/core/routing"
	"github.com/buzzmean/veliq/core/security"
	wp "github.com/buzzmean/veliq/platform/windows"
)

// prepareAuto on 0.3.715 creates an identity anchored to this one executable.
// Retain the restriction against group profiles, helpers or versioned matches.
func exactCS2Identity(p profiles.Profile) bool {
	a := p.Identity
	if a == nil || len(p.Executables) != 1 || !gamePath(p.Executables[0]) {
		return false
	}
	image := gameudp.Canonical(p.Executables[0])
	base := path.Base(image)
	return stunGameImage(image) && gameudp.Canonical(a.Executable) == base &&
		gameudp.Canonical(a.Root) == path.Dir(image) && !a.Versioned &&
		a.PackageFamily == "" && a.RelativePath == "" && len(a.Helpers) == 0
}

// A 715 CS2 AUTO profile may still contain custom port or service rules.
// Keep their deny/required floors while eliminating every relay dispatch.
func cs2AutoRuleProfile(p profiles.Profile) bool {
	return p.Mode == profiles.Auto && (p.AppPreset == "" || strings.HasPrefix(p.AppPreset, "game-udp-")) &&
		len(p.Executables) == 1 && stunGameImage(p.Executables[0])
}

func (c *Controller) cs2RouteBlocked(p profiles.Profile, t wp.Tuple, domain string) bool {
	if len(p.Rules) == 0 && len(p.BrowserRecoveryRules) == 0 {
		return false
	}
	input := flowpolicy.Input{Protocol: t.Protocol, Destination: t.Destination, Domain: domain, Network: c.gameMeasurementNetwork()}
	for _, rules := range [][]flowpolicy.Rule{p.Rules, p.BrowserRecoveryRules} {
		matched, ok := flowpolicy.Evaluate(rules, input)
		if ok && cs2RestrictedAction(matched.Action) {
			return true
		}
		for _, rule := range rules {
			if !cs2RestrictedAction(rule.Action) {
				continue
			}
			// A required policy could match a value the native classifier does not
			// have yet. Only deny tuples that match all remaining known selectors.
			unknown := false
			if domain == "" && len(rule.Domains) > 0 {
				rule.Domains = nil
				unknown = true
			}
			if !t.Destination.Addr().IsValid() && len(rule.CIDRs) > 0 {
				rule.CIDRs = nil
				unknown = true
			}
			if input.Network == "" && rule.Network != "" {
				rule.Network = ""
				unknown = true
			}
			if unknown && rule.Matches(input) {
				return true
			}
		}
	}
	return false
}

func cs2RestrictedAction(action flowpolicy.Action) bool {
	return action == flowpolicy.Relay || action == flowpolicy.RelayRequired || action == flowpolicy.Block
}

// The released desktop selects AUTO by setting the profile mode, then disabling
// the old UDP ladder. That second write must not disable ordinary CS2 routing.
// An explicitly enabled local-only profile still requests the legacy mode.
func stunGameImage(image string) bool {
	if !gamePath(image) {
		return false
	}
	base := path.Base(gameudp.Canonical(image))
	if base == "r5apex.exe" {
		return true
	}
	for _, preset := range gameudp.Presets() {
		if strings.EqualFold(base, preset.Executable) {
			return true
		}
	}
	return false
}

func (g *gameEntry) syncCS2Mode(p profiles.Profile) {
	selected := p.ID == g.ProfileID && gameProfileSafe(p) && stunGameImage(g.Path)
	active := g.SteamCS2 && selected && p.Mode == profiles.Auto && !(g.LocalOnly && g.Enabled)
	stun := selected && (p.Mode == profiles.Auto || g.LocalOnly && g.Enabled)
	g.CS2Auto, g.STUNAuto = active, stun
	g.Engine.SetCS2Auto(active)
	g.Engine.SetSTUNAuto(stun)
	g.Engine.SetLocalOnly(stun || !active && g.LocalOnly)
	g.Engine.Configure(g.Path, active || stun || g.Enabled)
}

// The no-relay policy applies even while capture guards and Steam discovery
// settle. A full, explicitly configured CS2 path can use Windows directly in
// that interval. Game learning itself requires the Steam-discovered image.
func (c *Controller) cs2AutoProfile(p profiles.Profile, id wp.ProcessIdentity) bool {
	if id.PID == 0 || id.CreationTime == 0 || p.Mode != profiles.Auto || !gameProfileSafe(p) {
		return false
	}
	image := gameudp.Canonical(id.Path)
	if !strings.HasSuffix(image, "/cs2.exe") || !gamePath(id.Path) {
		return false
	}
	c.games.mu.Lock()
	defer c.games.mu.Unlock()
	g := c.games.items[p.ID]
	if g != nil && gameudp.Canonical(g.Path) == image {
		g.syncCS2Mode(p)
		if g.SteamCS2 {
			return g.CS2Auto
		}
		return cs2AutoRuleProfile(p) && !(g.Enabled && g.LocalOnly)
	}
	return (p.AppPreset == "game-udp-cs2" || p.ID == "game-cs2") && cs2AutoRuleProfile(p) &&
		gamePath(p.Executables[0]) && gameudp.Canonical(p.Executables[0]) == image
}

func cs2DirectDecision(p profiles.Profile, id wp.ProcessIdentity, t wp.Tuple) wp.Decision {
	return wp.Decision{
		NewConnectionsOnly: true, CS2Auto: t.Protocol == "tcp", Group: p.ID, Revision: "cs2-endpoint-auto-v1",
		Flow:   routing.Flow{PID: id.PID, ProcessPath: id.Path, ApplicationID: p.ID, Protocol: t.Protocol, Source: t.Source, Destination: t.Destination, PinnedPolicy: &routing.Policy{}},
		Policy: flowpolicy.Result{Action: flowpolicy.Direct, Fallback: flowpolicy.FailOpen, Source: "cs2_auto", Reason: "CS2 stays on the Windows route"},
	}
}

func (c *Controller) classifyCS2Auto(id wp.ProcessIdentity, t wp.Tuple) (wp.Decision, bool) {
	base := strings.LastIndexAny(id.Path, `/\`)
	if !strings.EqualFold(id.Path[base+1:], "cs2.exe") {
		return wp.Decision{}, false
	}
	p, ok := c.matchApplication(id)
	if !ok || !c.cs2AutoProfile(p, id) {
		return wp.Decision{}, false
	}
	if c.cs2RouteBlocked(p, t, "") {
		d := cs2DirectDecision(p, id, t)
		d.Block, d.BlockOnFailure = true, true
		d.Policy = flowpolicy.Result{Action: flowpolicy.Block, Fallback: flowpolicy.FailBlock, Source: "cs2_auto", Reason: "CS2 profile requires a route excluded by local-only AUTO"}
		return d, true
	}
	if t.Protocol == "tcp" {
		return c.cs2NativeTCP(id, t, p), true
	}
	if gameudp.Eligible(id.Path, id.Path, t.Protocol, t.Destination) {
		if d, ok := c.classifyGameUDP(id, t); ok && d.CS2Auto {
			return d, true
		}
	}
	// Low-port and IPv6 traffic never enters the generic relay/local ladder.
	return cs2DirectDecision(p, id, t), true
}

// The console observer owns outcomes. An authenticated field observer may add
// measured quality to an already confirmed JOINED flow, never assert a timeout.
func (c *Controller) recordCS2Quality(raw json.RawMessage) (any, error) {
	var o gameudp.CS2Outcome
	if err := security.Parse(raw, &o); err != nil {
		return nil, err
	}
	c.games.mu.Lock()
	defer c.games.mu.Unlock()
	lastError := errors.New("CS2_AUTO_NOT_READY")
	for _, g := range c.games.items {
		if !g.CS2Auto || !g.Engine.Ready() {
			continue
		}
		if err := g.Engine.RecordCS2Quality(o, time.Now()); err != nil {
			lastError = err
			continue
		}
		return true, nil
	}
	return nil, lastError
}

type cs2EndpointStatus struct {
	Network     string               `json:"network_fingerprint"`
	Destination netip.AddrPort       `json:"destination"`
	Matched     int                  `json:"matched_count"`
	Truncated   bool                 `json:"truncated"`
	Lost        uint64               `json:"lost"`
	Flows       []gameudp.Evidence   `json:"flows"`
	Observation *gameudp.CS2Endpoint `json:"last_observation,omitempty"`
}

// The regular status view has a per-game cutoff across every peer. Select the
// requested peer before imposing a bound so background queries cannot hide it.
func (c *Controller) cs2EndpointStatus(raw json.RawMessage) (any, error) {
	var q struct {
		ProfileID   string         `json:"profile_id"`
		Destination netip.AddrPort `json:"destination"`
	}
	if err := security.Parse(raw, &q); err != nil {
		return nil, err
	}
	if q.ProfileID == "" || !q.Destination.IsValid() || q.Destination.Port() == 0 {
		return nil, errors.New("CS2_ENDPOINT_REQUIRED")
	}
	network := c.gameMeasurementNetwork()
	c.games.mu.Lock()
	defer c.games.mu.Unlock()
	g := c.games.items[q.ProfileID]
	if network == "" || g == nil || !g.CS2Auto {
		return nil, errors.New("CS2_AUTO_NOT_READY")
	}
	snapshot := g.Engine.Snapshot()
	out := cs2EndpointStatus{Network: network, Destination: q.Destination, Lost: snapshot.Lost, Flows: []gameudp.Evidence{}}
	for i := range snapshot.CS2Endpoints {
		row := &snapshot.CS2Endpoints[i]
		if row.Network == network && row.Destination == q.Destination {
			out.Observation = row
			break
		}
	}
	endpoint := q.Destination.String()
	for _, flow := range snapshot.Flows {
		if !flow.CS2Auto || flow.Network != network || flow.Destination != endpoint {
			continue
		}
		out.Matched++
		if len(out.Flows) < 8 {
			flow.Application = ""
			out.Flows = append(out.Flows, flow)
		}
	}
	out.Truncated = out.Matched > len(out.Flows)
	return out, nil
}
