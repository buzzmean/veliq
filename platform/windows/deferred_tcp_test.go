package windowsplatform

import (
	"github.com/buzzmean/veliq/core/flowpolicy"
	"github.com/buzzmean/veliq/core/localstrategy"
	"github.com/buzzmean/veliq/core/routing"
	"net"
	"net/netip"
	"testing"
	"time"
)

func TestDeferredHTTPFragmentsPreserveOriginalStream(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	want := "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
	go func() {
		for _, s := range []string{want[:9], want[9:25], want[25:]} {
			b.Write([]byte(s))
		}
	}()
	data, domain, why := ReadDeferredHello(a)
	if string(data) != want || domain != "example.com" || why != "HTTP_HOST" {
		t.Fatal(string(data), domain, why)
	}
}
func TestDeferredIncompleteIsBounded(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	go func() { b.Write([]byte{22, 3, 3, 0, 50}); b.Close() }()
	start := time.Now()
	data, domain, why := ReadDeferredHello(a)
	if len(data) != 5 || domain != "" || why != "CLIENTHELLO_INCOMPLETE" || time.Since(start) > localstrategy.HelloDeadline+time.Second {
		t.Fatal(len(data), domain, why)
	}
}
func TestDelegatedEvidencePreservesAppEndpointAndTransform(t *testing.T) {
	l := NewEvidenceLedger()
	id := ProcessIdentity{PID: 1, CreationTime: 1, Path: "Chrome.exe"}
	original := Tuple{Protocol: "tcp", Source: netip.MustParseAddrPort("192.0.2.1:1200"), Destination: netip.MustParseAddrPort("203.0.113.1:443")}
	up := original
	up.Source = netip.MustParseAddrPort("192.0.2.1:2000")
	l.BeginFlow(id, original)
	l.Record(id, original, "captured", "")
	if !l.BindUpstream(id, up, original) {
		t.Fatal("bind")
	}
	l.BeginFlow(id, up)
	l.RecordBytes(id, up, "direct", "", 40)
	l.RecordLocal(id, up, "disorder", "www.youtube.com", 100)
	l.RecordBytes(id, up, "direct", "", 40)
	l.RecordPolicy(id, up, Decision{Route: routing.Route{Kind: routing.DirectPlusRoute}}, "")
	s := l.Snapshot(id.PID)
	if len(s.Flows) != 1 || s.Flows[0].Source != original.Source.String() || s.Flows[0].Route != "DIRECT_PLUS" || s.Flows[0].Counters.RelayedBytes != 0 || s.Flows[0].Counters.DirectPlusBytes == 0 {
		t.Fatal(s)
	}
}
func TestIndependentDelegatedConnectionsCannotBorrowCounters(t *testing.T) {
	l := NewEvidenceLedger()
	id := ProcessIdentity{PID: 1, CreationTime: 1, Path: "Chrome.exe"}
	a := Tuple{Protocol: "tcp", Source: netip.MustParseAddrPort("192.0.2.1:1200"), Destination: netip.MustParseAddrPort("203.0.113.1:443")}
	b := a
	b.Source = netip.MustParseAddrPort("192.0.2.1:1201")
	ua := a
	ua.Source = netip.MustParseAddrPort("192.0.2.1:2200")
	ub := b
	ub.Source = netip.MustParseAddrPort("192.0.2.1:2201")
	for _, v := range []Tuple{a, b} {
		l.BeginFlow(id, v)
		l.Record(id, v, "captured", "")
	}
	if !l.BindUpstream(id, ua, a) || !l.BindUpstream(id, ub, b) {
		t.Fatal("bind")
	}
	l.RecordLocal(id, ua, "disorder", "www.youtube.com", 100)
	l.RecordBytes(id, ub, "direct", "", 40)
	sa, _ := l.SnapshotQuery(EvidenceQuery{Source: a.Source.String()}, nil)
	sb, _ := l.SnapshotQuery(EvidenceQuery{Source: b.Source.String()}, nil)
	if len(sa.Flows) != 1 || sa.Flows[0].Route != "DIRECT_PLUS" || len(sb.Flows) != 1 || sb.Flows[0].Route != "DIRECT" || sb.Flows[0].Counters.DirectPlus != 0 || sa.Flows[0].Counters.Relayed != 0 {
		t.Fatal(sa, sb)
	}
}
func TestDeferredOpaqueFallbackCannotLeakProtectedFlow(t *testing.T) {
	seen := "not called"
	initial := Decision{Deferred: true, ResolveDomain: func(domain string) Decision {
		seen = domain
		return Decision{BlockOnFailure: true, Policy: flowpolicy.Result{Action: flowpolicy.RelayRequired, Fallback: flowpolicy.Required}}
	}}
	d := ResolveDeferredDecision(initial, "public-name.example", "ECH_OUTER_SNI_ONLY")
	if seen != "" || !d.Block || d.Deferred || d.ResolveDomain != nil || d.Policy.Action != flowpolicy.Block {
		t.Fatal("ECH was guessed into a route", seen, d)
	}
	d = ResolveDeferredDecision(Decision{Deferred: true}, "example.com", "REASSEMBLY_COMPLETE")
	if !d.Block {
		t.Fatal("missing resolver leaked")
	}
}

func TestDeferredOpaqueAuthenticatedRouteIsNotAnOpenFailure(t *testing.T) {
	initial := Decision{Deferred: true, ResolveDomain: func(domain string) Decision {
		if domain != "" {
			t.Fatal("ECH inner name guessed", domain)
		}
		return Decision{Route: routing.Route{RelayID: "VPS-01"}, BlockOnFailure: true, Policy: flowpolicy.Result{Action: flowpolicy.RelayRequired, Fallback: flowpolicy.Required}}
	}}
	d := ResolveDeferredDecision(initial, "cloudflare-ech.com", "ECH_OUTER_SNI_ONLY")
	if d.Block || d.Route.Direct() || d.Route.RelayID != "VPS-01" || !d.BlockOnFailure || d.Deferred {
		t.Fatal(d)
	}
}
