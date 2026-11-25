package clientservice

import (
	"github.com/buzzmean/veliq/core/flowpolicy"
	"github.com/buzzmean/veliq/core/profiles"
)

// Generic probe scores describe the probe target, not arbitrary game servers.
// Only registered blocked-service/browser policies may choose relay implicitly.
// MANUAL and explicit per-flow rules remain deliberate operator choices.
func automaticRelayAllowed(p profiles.Profile) bool {
	return browserAuto(p) || relayFirstPreset(presetFor(p)) || presetFor(p) == "discord"
}

// An explicit profile or rule retains its operator-selected relay.
func implicitRelay(p profiles.Profile, r flowpolicy.Result) bool {
	return p.Mode == profiles.Auto && p.RelayID == "" && r.RuleID == "" && r.Source != "rule"
}

func (c *Controller) applicationAutomaticRelayAllowed(id string) bool {
	for _, p := range c.Profiles.List() {
		if p.ID == id {
			return p.Mode == profiles.Auto && automaticRelayAllowed(p)
		}
	}
	return false
}

type profileRoutingEntry struct {
	ID                    string        `json:"id"`
	Mode                  profiles.Mode `json:"mode"`
	Origin                string        `json:"origin"`
	AutomaticRelayAllowed bool          `json:"automatic_relay_allowed"`
	DefaultRoute          string        `json:"default_route"`
	RelayID               string        `json:"relay_id,omitempty"`
}

type profileRoutingAudit struct {
	Profiles  []profileRoutingEntry `json:"profiles"`
	Truncated bool                  `json:"truncated"`
}

// Metadata only: this is the configured default, never proof of a live flow.
// Existing files do not record whether a local override came from GUI or IPC.
func (c *Controller) profileRoutingAudit() profileRoutingAudit {
	entries := []profileRoutingEntry{}
	all := c.Profiles.List()
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, p := range all {
		if len(entries) == 64 {
			break
		}
		e := profileRoutingEntry{ID: p.ID, Mode: p.Mode, Origin: "built_in", DefaultRoute: "DIRECT", AutomaticRelayAllowed: p.Mode == profiles.Auto && automaticRelayAllowed(p)}
		if _, ok := c.localProfiles[p.ID]; ok {
			e.Origin = "local_override"
		}
		if p.Custom {
			e.Origin = "custom"
		}
		switch p.Mode {
		case profiles.Manual:
			e.DefaultRoute, e.RelayID = "RELAY", p.RelayID
		case profiles.DirectPlus:
			e.DefaultRoute = "DIRECT_PLUS"
		case profiles.Block:
			e.DefaultRoute = "BLOCK"
		case profiles.Auto:
			if browserAuto(p) || len(p.Rules) > 0 {
				e.DefaultRoute = "PER_FLOW"
			} else if e.AutomaticRelayAllowed {
				e.DefaultRoute, e.RelayID = "RELAY_REQUIRED", p.RelayID
				if e.RelayID == "" {
					e.RelayID = "VPS-01"
				}
			}
		}
		entries = append(entries, e)
	}
	return profileRoutingAudit{entries, len(all) > len(entries)}
}
