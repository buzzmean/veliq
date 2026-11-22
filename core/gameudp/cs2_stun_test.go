package gameudp

import (
	"net/netip"
	"strings"
	"testing"
	"time"
)

func TestCS2STUNLocksSelectionToEndpointAndLocalOnly(t *testing.T) {
	e := NewLadder(&Budget{})
	e.Configure(app, true)
	e.SetReason("")
	at := time.Unix(1000, 0)
	target := netip.MustParseAddrPort("203.0.113.10:27015")
	key := Key{Network: strings.Repeat("a", 64), Application: app, PID: 77, Birth: 100,
		Source: netip.MustParseAddrPort("192.0.2.1:50000"), Destination: target}
	open := func(destination netip.AddrPort) *Flow {
		t.Helper()
		key.Destination = destination
		flow, err := e.OpenWithQuality(key, at, "test-relay")
		if err != nil {
			t.Fatal(err)
		}
		return flow
	}
	e.SetCS2STUNEndpoint(target)
	if flow := open(target); e.Evidence(flow).FakeTTL != 0 {
		t.Fatal("STUN requires local-only mode")
	}
	e.SetLocalOnly(true)
	flow := open(target)
	if got := e.Evidence(flow); got.Stage != Local || got.FakeTTL != 8 {
		t.Fatal(got)
	}
	oob := []byte{255, 255, 255, 255, 1, 2, 3}
	data := []byte{128, 1, 2, 3, 4, 5, 6}
	for i, datagram := range [][]byte{data, {1}, oob, data, data, data, data} {
		p, n := e.PlanDatagram(flow, datagram, at)
		want := []int{6, 6, 0, 6, 6, 6, 0}[i]
		if n != want || n > 0 && !IsSTUNBinding(p) {
			t.Fatalf("datagram %d: got %d duplicates, want %d", i, n, want)
		}
	}
	other := netip.MustParseAddrPort("203.0.113.10:27016")
	if f := open(other); e.Evidence(f).Stage != Direct {
		t.Fatal("other endpoint must stay direct")
	}
	fresh := open(target)
	e.SetCS2STUNEndpoint(other)
	if _, n := e.PlanDatagram(fresh, data, at); n != 0 {
		t.Fatal("configuration change armed an existing flow")
	}
	if len(e.Snapshot().Learning) != 0 {
		t.Fatal("the scoped primer must not teach other flows")
	}
}

func TestCS2STUNServerPortMatchesMultipleAddresses(t *testing.T) {
	e := NewLadder(&Budget{})
	e.Configure(app, true)
	e.SetReason("")
	e.SetLocalOnly(true)
	e.SetCS2STUNScope(netip.AddrPort{}, []uint16{27015})
	at := time.Unix(1000, 0)
	key := Key{Network: strings.Repeat("a", 64), Application: app, PID: 77, Birth: 100,
		Source: netip.MustParseAddrPort("192.0.2.1:50000")}
	for _, tc := range []struct {
		address   string
		stage     string
		selection string
		repeats   int
	}{
		{"203.0.113.10:27015", Local, "CS2_STUN_SERVER_PORT", cs2STUNRepeats},
		{"198.51.100.20:27015", Local, "CS2_STUN_SERVER_PORT", cs2STUNRepeats},
		{"203.0.113.10:27016", Direct, "CS2_STUN_OTHER_ENDPOINT_DIRECT", 0},
	} {
		key.Destination = netip.MustParseAddrPort(tc.address)
		flow, err := e.OpenWithQuality(key, at, "test-relay")
		if err != nil {
			t.Fatal(err)
		}
		ev := e.Evidence(flow)
		if ev.Stage != tc.stage || ev.Selection != tc.selection {
			t.Fatalf("destination %s: got %s / %s", tc.address, ev.Stage, ev.Selection)
		}
		payload, repeats := e.PlanDatagram(flow, []byte{0xff, 0xff, 0xff, 0xff, 0x71}, at)
		if repeats != tc.repeats || repeats > 0 && !IsSTUNBinding(payload) {
			t.Fatalf("destination %s: got %d STUN datagrams", tc.address, repeats)
		}
	}
}
