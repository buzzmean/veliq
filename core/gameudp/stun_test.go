package gameudp

import (
	"bytes"
	"net/netip"
	"strings"
	"testing"
	"time"
)

func TestSTUNPrimerFramingCutoffsAndScope(t *testing.T) {
	p, err := STUNPayload()
	if err != nil || !IsSTUNBinding(p) {
		t.Fatal(err, p)
	}
	q, err := STUNPayload()
	if err != nil || bytes.Equal(p, q) {
		t.Fatal("transaction entropy", err)
	}
	bad := append([]byte(nil), p...)
	bad[2] = 1
	if IsSTUNBinding(bad) || IsSTUNBinding(p[:19]) || IsSTUNBinding(append(p, 0)) {
		t.Fatal("invalid STUN header accepted")
	}
	e := NewLadder(&Budget{})
	e.Configure(app, true)
	e.SetReason("")
	e.SetLocalOnly(true)
	cfg := Primer{Kind: "stun", Endpoint: "18.157.46.1:7766", TTL: 8, Repeats: 6, Cutoff: 2, DataCutoff: 4}
	if err = e.SetPrimer(&cfg); err != nil {
		t.Fatal(err)
	}
	at := time.Unix(1000, 0)
	key := Key{Network: strings.Repeat("a", 64), Application: app, PID: 77, Birth: 100, Source: netip.MustParseAddrPort("192.0.2.1:50000"), Destination: netip.MustParseAddrPort(cfg.Endpoint)}
	f, err := e.Open(key, at)
	if err != nil {
		t.Fatal(err)
	}
	packets := [][]byte{{32}, {34}, {255, 255, 255, 255, 0, 0, 0}, {128, 1, 2, 3, 4, 5, 6}, {128, 2, 2, 3, 4, 5, 6}, {128, 3, 2, 3, 4, 5, 6}, {128, 4, 2, 3, 4, 5, 6}, {128, 5, 2, 3, 4, 5, 6}, {32}}
	want := []int{6, 6, 0, 6, 6, 6, 6, 0, 0}
	total := 0
	for i, d := range packets {
		payload, k := e.PlanDatagram(f, d, at)
		if k != want[i] {
			t.Fatalf("packet %d: %d", i, k)
		}
		if k > 0 && !IsSTUNBinding(payload) {
			t.Fatal("wrong payload")
		}
		total += k
		for j := 0; j < k; j++ {
			e.FakeSent(f, len(payload)+28, nil)
		}
	}
	if total != 36 {
		t.Fatal(total)
	}
	cfg.DataCutoff = 3
	if err = e.SetPrimer(&cfg); err != nil {
		t.Fatal(err)
	}
	if _, n := e.PlanDatagram(f, packets[3], at); n != 0 {
		t.Fatal("old flow restarted after config change")
	}
	key.Destination = netip.MustParseAddrPort("18.157.46.2:7766")
	other, err := e.Open(key, at)
	if err != nil {
		t.Fatal(err)
	}
	if _, n := e.PlanDatagram(other, packets[3], at); n != 0 {
		t.Fatal("other endpoint primed")
	}
	for _, v := range []Primer{{Kind: "other"}, {Kind: "stun", DataCutoff: 5}, {Kind: "stun", DataCutoff: -1}, {Kind: "stun", Cutoff: 3}, {Kind: "quic-initial", DataCutoff: 1}} {
		cfg := Primer{Kind: v.Kind, Endpoint: "18.157.46.1:7766", TTL: 8, Repeats: 6, Cutoff: 2, DataCutoff: v.DataCutoff}
		if v.Cutoff != 0 {
			cfg.Cutoff = v.Cutoff
		}
		if cfg.Validate() == nil {
			t.Fatal("invalid primer", cfg)
		}
	}
}
