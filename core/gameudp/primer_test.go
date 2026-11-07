package gameudp

import (
	"net/netip"
	"strings"
	"testing"
	"time"
)

func TestPrimerScopeBudgetAndPolicy(t *testing.T) {
	e := NewLadder(&Budget{})
	e.Configure(app, true)
	e.SetReason("")
	p := Primer{Endpoint: "18.157.46.1:7766", TTL: 4, Repeats: 6, Cutoff: 2}
	if e.SetPrimer(&p) == nil {
		t.Fatal("primer without local_only")
	}
	e.SetLocalOnly(true)
	if err := e.SetPrimer(&p); err != nil {
		t.Fatal(err)
	}
	at := time.Unix(1000, 0)
	key := Key{Network: strings.Repeat("a", 64), Application: app, PID: 77, Birth: 100, Source: netip.MustParseAddrPort("192.0.2.1:50000"), Destination: netip.MustParseAddrPort(p.Endpoint)}
	f, err := e.Open(key, at)
	if err != nil {
		t.Fatal(err)
	}
	if f.e.Stage != Local || f.e.FakeTTL != 4 {
		t.Fatal(f.e)
	}
	total := 0
	for i := 0; i < 8; i++ {
		payload, k := e.Plan(f, at)
		total += k
		for j := 0; j < k; j++ {
			e.FakeSent(f, len(payload)+28, nil)
		}
	}
	if total != 12 {
		t.Fatal(total)
	}
	for i := 0; i < 8; i++ {
		now := at.Add(time.Duration(i) * 500 * time.Millisecond)
		e.Outgoing(f, 64, now)
		e.Reply(f, 128, now)
		e.Tick(now)
	}
	if e.Evidence(f).State != "SUSTAINED_REPLIES" || len(e.Snapshot().Learning) != 0 {
		t.Fatal("explicit test polluted ladder", e.Snapshot())
	}
	key.Destination = netip.MustParseAddrPort("18.157.46.2:7766")
	g, err := e.Open(key, at)
	if err != nil || g.e.Stage != Direct {
		t.Fatal("other endpoint changed", err)
	}
	if _, n := e.Plan(g, at); n != 0 {
		t.Fatal("other endpoint primed")
	}
	snap := e.Snapshot()
	snap.Primer.TTL = 16
	if e.Snapshot().Primer.TTL != 4 {
		t.Fatal("mutable snapshot")
	}
	key.Destination = netip.MustParseAddrPort(p.Endpoint)
	h, err := e.Open(key, at)
	if err != nil {
		t.Fatal(err)
	}
	p.TTL = 5
	if err = e.SetPrimer(&p); err != nil {
		t.Fatal(err)
	}
	if _, n := e.Plan(h, at); n != 0 {
		t.Fatal("old flow priming restarted")
	}
	e.SetLocalOnly(false)
	if _, err = e.Open(key, at); err == nil {
		t.Fatal("primer allowed without policy")
	}
	if _, n := e.Plan(h, at); n != 0 {
		t.Fatal("old fake after policy change")
	}
}
func TestPrimerGlobalBudgetAndValidation(t *testing.T) {
	shared := &Budget{}
	at := time.Unix(1000, 0)
	count := 0
	for j := 0; j < 8; j++ {
		e := NewLadder(shared)
		e.Configure(app, true)
		e.SetReason("")
		e.SetLocalOnly(true)
		p := Primer{Endpoint: "18.157.46.1:7766", TTL: 4, Repeats: 16, Cutoff: 4}
		if err := e.SetPrimer(&p); err != nil {
			t.Fatal(err)
		}
		f, err := e.Open(Key{Network: strings.Repeat("a", 64), Application: app, PID: 77, Birth: 100, Source: netip.MustParseAddrPort("192.0.2.1:50000"), Destination: netip.MustParseAddrPort(p.Endpoint)}, at)
		if err != nil {
			t.Fatal(err)
		}
		for i := 0; i < 8; i++ {
			_, n := e.Plan(f, at)
			count += n
		}
	}
	if count != MaxFakePerSecond {
		t.Fatal("shared budget", count)
	}
	for _, p := range []Primer{{Endpoint: "127.0.0.1:27015", TTL: 4, Repeats: 6, Cutoff: 2}, {Endpoint: "18.157.46.1:443", TTL: 4, Repeats: 6, Cutoff: 2}, {Endpoint: "18.157.46.1:7766", TTL: 17, Repeats: 6, Cutoff: 2}, {Endpoint: "18.157.46.1:7766", TTL: 4, Repeats: 17, Cutoff: 2}, {Endpoint: "18.157.46.1:7766", TTL: 4, Repeats: 6, Cutoff: 5}} {
		if p.Validate() == nil {
			t.Fatal("invalid config", p)
		}
	}
}
