package flowpolicy

import (
	"net/netip"
	"testing"
	"time"
)

func TestSpecificityAndDomainBoundaries(t *testing.T) {
	rules := []Rule{{ID: "default", Action: Direct}, {ID: "tcp", Protocol: "tcp", Action: RelayRequired, RelayID: "VPS-01"}, {ID: "domain", Protocol: "tcp", Domains: []string{"example.com"}, Action: DirectPlus, Strategy: "disorder"}}
	for _, r := range rules {
		if e := r.Validate(); e != nil {
			t.Fatal(e)
		}
	}
	i := Input{Protocol: "tcp", Domain: "a.example.com", Destination: netip.MustParseAddrPort("203.0.113.1:443")}
	r, _ := Evaluate(rules, i)
	if r.Action != DirectPlus || r.Strategy != "disorder" {
		t.Fatal(r)
	}
	i.Domain = "notexample.com"
	r, _ = Evaluate(rules, i)
	if r.Action != RelayRequired || r.Fallback != Required {
		t.Fatal(r)
	}
	i.Protocol = "udp"
	r, _ = Evaluate(rules, i)
	if r.Action != Direct {
		t.Fatal(r)
	}
}
func TestLearningScopeQuarantineAndExpiry(t *testing.T) {
	l := NewLearning()
	now := time.Now()
	k := LearnKey{Network: "ISP-a", Application: "Chrome", Protocol: "tcp", Target: "www.youtube.com", Port: 443}
	v := Learned{Key: k, Result: Result{Action: DirectPlus, Strategy: "disorder", Fallback: FailOpen}, Success: true, Observed: now, Expires: now.Add(time.Minute)}
	if e := l.Record(v, now); e != nil {
		t.Fatal(e)
	}
	if _, ok := l.Lookup(k, now); !ok {
		t.Fatal("missing proof")
	}
	for _, change := range []func(*LearnKey){func(k *LearnKey) { k.Network = "ISP-b" }, func(k *LearnKey) { k.Application = "Discord" }, func(k *LearnKey) { k.Target = "other.youtube.com" }, func(k *LearnKey) { k.Port = 8443 }, func(k *LearnKey) { k.Protocol = "udp" }, func(k *LearnKey) { k.Revision = "changed" }} {
		other := k
		change(&other)
		if _, ok := l.Lookup(other, now); ok {
			t.Fatal("cross-scope cache hit", other)
		}
	}
	v.Success = false
	v.Observed = now.Add(time.Second)
	if e := l.Record(v, now.Add(time.Second)); e != nil {
		t.Fatal(e)
	}
	if !l.Quarantined(k, "disorder", now.Add(time.Second)) {
		t.Fatal("missing quarantine")
	}
	if _, ok := l.Lookup(k, now.Add(time.Second)); ok {
		t.Fatal("failure reused as success")
	}
	if l.HasApplication(k.Network, k.Application, k.Protocol, now.Add(2*time.Minute)) {
		t.Fatal("expired history retained")
	}
}
func TestRuleBoundsAndPorts(t *testing.T) {
	r := Rule{ID: "media", Protocol: "udp", Ports: []PortRange{{1024, 65535}}, Action: Direct, RelayID: "VPS-01", Fallback: FlowRelay}
	if e := r.Validate(); e != nil {
		t.Fatal(e)
	}
	for _, p := range []uint16{443, 1023} {
		if r.Matches(Input{Protocol: "udp", Destination: netip.AddrPortFrom(netip.MustParseAddr("203.0.113.1"), p)}) {
			t.Fatal("QUIC/system port called media")
		}
	}
	r.Protocol = "tcp"
	if r.Validate() == nil {
		t.Fatal("TCP flow movement allowed")
	}
}
