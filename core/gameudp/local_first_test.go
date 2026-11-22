package gameudp

import (
	"net/netip"
	"strings"
	"testing"
	"time"
)

func localLadder() *Engine {
	e := NewLadder(nil)
	e.SetStartLocal(true)
	e.Configure(app, true)
	e.SetReason("")
	return e
}

func TestLocalPreferenceStartsOnlyOnNewLocalOnlyFlows(t *testing.T) {
	e := NewLadder(&Budget{})
	e.Configure(app, true)
	e.SetReason("")
	e.PreferLocalWithoutRelay()
	at := time.Unix(1000, 0)
	ordinary := ladderFlow(t, e, at, 50000)
	if e.Evidence(ordinary).Stage != Direct {
		t.Fatal("ordinary UDP did not start DIRECT")
	}
	e.SetLocalOnly(true)
	key := ordinary.key
	key.Source = netip.AddrPortFrom(key.Source.Addr(), 50001)
	local, err := e.OpenWithQuality(key, at, "test-relay")
	if err != nil {
		t.Fatal(err)
	}
	if ev := e.Evidence(local); ev.Stage != Local || ev.Variant != Variants()[0] {
		t.Fatal("local trial missed first variant", ev)
	}
	if _, repeats := e.Plan(local, at); repeats != 12 {
		t.Fatalf("first datagram: got %d copies", repeats)
	}
	if _, repeats := e.Plan(ordinary, at); repeats != 0 || e.Evidence(ordinary).Stage != Direct {
		t.Fatal("existing DIRECT flow changed")
	}
}
func TestPUBGLocalFirstColdFlowK12N2WithoutDirectProbation(t *testing.T) {
	e := localLadder()
	at := time.Unix(1000, 0)
	f := ladderFlow(t, e, at, 50000)
	if f.e.Stage != Local || f.e.Variant != Variants()[0] || f.e.Selection != "LOCAL_FIRST_UNCONFIRMED_ENDPOINT" {
		t.Fatal(f.e)
	}
	total := 0
	for i := 0; i < 5; i++ {
		_, k := e.Plan(f, at)
		if i < 2 && k != 12 || i >= 2 && k != 0 {
			t.Fatal("first packets not K12/N2", i, k)
		}
		total += k
	}
	if total != 24 {
		t.Fatal(total)
	}
	if e.Snapshot().InitialPolicy != "LOCAL_FIRST_UNCONFIRMED_ENDPOINT" {
		t.Fatal(e.Snapshot())
	}
}
func TestPUBGLocalFirstOnlyExactFreshNetworkEndpointCanStayDirect(t *testing.T) {
	at := time.Unix(1000, 0)
	e := localLadder()
	network := strings.Repeat("b", 64)
	// A prior Russian endpoint's success may not hold Frankfurt DIRECT. Include
	// a legacy global DIRECT success deliberately; it must not authorize a new IP.
	learning := []Learning{{Network: network, Application: app, Stage: Direct, Confirmed: true, Expires: at.Add(time.Hour)}, {Network: network, Application: app, Endpoint: "158.160.1.2:7766", Stage: Direct, Confirmed: true, Expires: at.Add(time.Hour)}}
	if err := e.Restore(learning, at); err != nil {
		t.Fatal(err)
	}
	f := ladderFlow(t, e, at, 50000)
	if f.e.Stage != Local {
		t.Fatal("cold Frankfurt inherited DIRECT", f.e)
	}
	key := f.key
	key.Destination = netip.MustParseAddrPort("158.160.1.2:7766")
	good, err := e.Open(key, at)
	if err != nil || good.e.Stage != Direct || good.e.Selection != "CONFIRMED_DIRECT_ENDPOINT" {
		t.Fatal("confirmed direct lost", err)
	}
	if _, n := e.Plan(good, at); n != 0 {
		t.Fatal("confirmed DIRECT primed")
	}
	key.Network = strings.Repeat("c", 64)
	changed, err := e.Open(key, at)
	if err != nil || changed.e.Stage != Local {
		t.Fatal("cross-network DIRECT learned", err)
	}
	key.Network = network
	expired, err := e.Open(key, at.Add(2*time.Hour))
	if err != nil || expired.e.Stage != Local {
		t.Fatal("expired DIRECT kept", err)
	}
	if e.Evidence(good).Stage != Direct {
		t.Fatal("old flow migrated")
	}
}
func TestPUBGLocalFirstBoundedAlternativesThenRelayAndCooldown(t *testing.T) {
	e := localLadder()
	at := time.Unix(1000, 0)
	var first *Flow
	for i, v := range Variants() {
		f := ladderFlow(t, e, at, uint16(50000+i))
		if i == 0 {
			first = f
		}
		if f.e.Stage != Local || f.e.Variant != v {
			t.Fatal(f.e)
		}
		failTrial(e, f, at)
		at = at.Add(8 * time.Second)
	}
	r := ladderFlow(t, e, at, 50100)
	if r.e.Stage != Relay {
		t.Fatal(r.e)
	}
	failTrial(e, r, at)
	if _, err := e.Open(r.key, at.Add(8*time.Second)); err == nil {
		t.Fatal("ladder unbounded")
	}
	fresh := ladderFlow(t, e, at.Add(2*time.Hour), 50101)
	if fresh.e.Stage != Local || fresh.e.Variant != Variants()[0] {
		t.Fatal("cooldown returned to broken DIRECT", fresh.e)
	}
	if first.e.Stage != Local {
		t.Fatal("flow migrated")
	}
}
func TestStartPolicyChangeDoesNotRewriteExistingDirectTuple(t *testing.T) {
	e := NewLadder(nil)
	e.Configure(app, true)
	e.SetReason("")
	at := time.Unix(1000, 0)
	old := ladderFlow(t, e, at, 50000)
	e.SetStartLocal(true)
	fresh := ladderFlow(t, e, at, 50001)
	if old.e.Stage != Direct || fresh.e.Stage != Local {
		t.Fatal("existing tuple migrated")
	}
}

func TestPUBGLegacyGlobalDirectDoesNotFreezeLocalAlternativeProgress(t *testing.T) {
	e := localLadder()
	at := time.Unix(1000, 0)
	if err := e.Restore([]Learning{{Network: strings.Repeat("b", 64), Application: app, Stage: Direct, Confirmed: true, Expires: at.Add(time.Hour)}}, at); err != nil {
		t.Fatal(err)
	}
	f := ladderFlow(t, e, at, 50000)
	failTrial(e, f, at)
	next := ladderFlow(t, e, at.Add(8*time.Second), 50001)
	if next.e.Stage != Local || next.e.Variant != Variants()[1] {
		t.Fatal("legacy global direct froze alternatives", e.Snapshot())
	}
}
