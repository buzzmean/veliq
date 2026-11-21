// Package flowpolicy evaluates immutable, application-scoped flow decisions.
// A rule is evaluated once per connection; changing configuration never moves TCP.
package flowpolicy

import (
	"errors"
	"net/netip"
	"strings"
)

type Action string

const (
	Direct        Action = "DIRECT"
	DirectPlus    Action = "DIRECT_PLUS"
	Relay         Action = "RELAY"
	RelayRequired Action = "RELAY_REQUIRED"
	Block         Action = "BLOCK"
)

type Fallback string

const (
	FailOpen  Fallback = "FAIL_OPEN_DIRECT"
	Required  Fallback = "RELAY_REQUIRED"
	FlowRelay Fallback = "FLOW_RELAY_FALLBACK"
	FailBlock Fallback = "BLOCK"
)

type PortRange struct {
	First uint16 `json:"first"`
	Last  uint16 `json:"last"`
}
type Rule struct {
	ID       string      `json:"id"`
	Protocol string      `json:"protocol,omitempty"`
	Domains  []string    `json:"domains,omitempty"`
	CIDRs    []string    `json:"cidrs,omitempty"`
	Ports    []PortRange `json:"ports,omitempty"`
	Network  string      `json:"network,omitempty"`
	Action   Action      `json:"action"`
	Strategy string      `json:"strategy,omitempty"`
	RelayID  string      `json:"relay_id,omitempty"`
	Fallback Fallback    `json:"fallback,omitempty"`
}
type Input struct {
	Protocol, Domain, Network string
	Destination               netip.AddrPort
}
type Result struct {
	Action   Action   `json:"action"`
	Strategy string   `json:"strategy,omitempty"`
	RelayID  string   `json:"relay_id,omitempty"`
	Fallback Fallback `json:"fallback"`
	Reason   string   `json:"reason"`
	Source   string   `json:"source"`
	RuleID   string   `json:"rule_id,omitempty"`
}

func (r Rule) Validate() error {
	if len(r.ID) == 0 || len(r.ID) > 64 || len(r.Domains) > 16 || len(r.CIDRs) > 16 || len(r.Ports) > 16 || len(r.Network) > 128 || len(r.Strategy) > 64 || len(r.RelayID) > 128 {
		return errors.New("invalid/bounded flow rule")
	}
	if r.Protocol != "" && r.Protocol != "tcp" && r.Protocol != "udp" {
		return errors.New("invalid rule protocol")
	}
	switch r.Action {
	case Direct, DirectPlus, Relay, RelayRequired, Block:
	default:
		return errors.New("invalid rule action")
	}
	if (r.Action == Relay || r.Action == RelayRequired) && r.RelayID == "" {
		return errors.New("relay rule requires relay")
	}
	if r.Action == DirectPlus && r.Strategy == "" {
		return errors.New("DIRECT+ rule requires strategy")
	}
	switch r.Fallback {
	case "", FailOpen, Required, FlowRelay, FailBlock:
	default:
		return errors.New("invalid flow fallback")
	}
	if r.Fallback == FlowRelay && (r.Action != Direct || r.Protocol != "udp" || r.RelayID == "") {
		return errors.New("flow relay fallback requires UDP and relay")
	}
	for _, p := range r.Ports {
		if p.First == 0 || p.Last < p.First {
			return errors.New("invalid port range")
		}
	}
	for _, s := range r.CIDRs {
		if _, e := netip.ParsePrefix(s); e != nil {
			return e
		}
	}
	for _, d := range r.Domains {
		if len(d) == 0 || len(d) > 253 || strings.ContainsAny(d, " /\\\t\r\n*") {
			return errors.New("invalid domain suffix")
		}
	}
	return nil
}
func DomainMatches(domain, suffix string) bool {
	domain = strings.ToLower(strings.TrimSuffix(domain, "."))
	suffix = strings.ToLower(strings.TrimSuffix(suffix, "."))
	return domain != "" && (domain == suffix || strings.HasSuffix(domain, "."+suffix))
}
func (r Rule) Matches(i Input) bool {
	if r.Protocol != "" && r.Protocol != i.Protocol || r.Network != "" && r.Network != i.Network {
		return false
	}
	if len(r.Domains) > 0 {
		ok := false
		for _, s := range r.Domains {
			ok = ok || DomainMatches(i.Domain, s)
		}
		if !ok {
			return false
		}
	}
	if len(r.CIDRs) > 0 {
		ok := false
		for _, s := range r.CIDRs {
			p, e := netip.ParsePrefix(s)
			ok = ok || (e == nil && p.Contains(i.Destination.Addr()))
		}
		if !ok {
			return false
		}
	}
	if len(r.Ports) > 0 {
		ok := false
		for _, p := range r.Ports {
			ok = ok || (i.Destination.Port() >= p.First && i.Destination.Port() <= p.Last)
		}
		if !ok {
			return false
		}
	}
	return true
}

// Specific domain/protocol rules outrank endpoint rules, then application defaults.
// Equal specificity is stable configuration order, never map iteration order.
func (r Rule) specificity(i Input) int64 {
	var score int64
	for _, d := range r.Domains {
		if DomainMatches(i.Domain, d) {
			n := int64(len(d))
			v := int64(1)<<50 + n<<40
			if v > score {
				score = v
			}
		}
	}
	if r.Protocol != "" {
		score += 1 << 35
	}
	bits := -1
	for _, s := range r.CIDRs {
		p, err := netip.ParsePrefix(s)
		if err == nil && p.Contains(i.Destination.Addr()) && p.Bits() > bits {
			bits = p.Bits()
		}
	}
	if bits >= 0 {
		score += (1 << 30) + int64(bits)<<20
	}
	narrow := 0
	for _, p := range r.Ports {
		if i.Destination.Port() >= p.First && i.Destination.Port() <= p.Last {
			v := 65536 - int(p.Last-p.First)
			if v > narrow {
				narrow = v
			}
		}
	}
	if narrow > 0 {
		score += (1 << 18) + int64(narrow)
	}
	if r.Network != "" {
		score++
	}
	return score
}
func Evaluate(rules []Rule, i Input) (Result, bool) {
	var best *Rule
	score := int64(-1)
	for n := range rules {
		r := &rules[n]
		if r.Matches(i) && r.specificity(i) > score {
			best = r
			score = r.specificity(i)
		}
	}
	if best == nil {
		return Result{}, false
	}
	f := best.Fallback
	if f == "" {
		f = FailOpen
	}
	if best.Action == RelayRequired {
		f = Required
	}
	return Result{Action: best.Action, Strategy: best.Strategy, RelayID: best.RelayID, Fallback: f, Reason: "application flow rule", Source: "rule", RuleID: best.ID}, true
}
func NeedsDomain(rules []Rule, protocol string) bool {
	for _, r := range rules {
		if len(r.Domains) > 0 && (r.Protocol == "" || r.Protocol == protocol) {
			return true
		}
	}
	return false
}
