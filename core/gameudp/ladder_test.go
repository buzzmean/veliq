package gameudp

import (
	"net/netip"
	"strings"
	"testing"
	"time"
)

func ladderFlow(t *testing.T, e *Engine, at time.Time, port uint16) *Flow {
	t.Helper()
	f, err := e.Open(Key{Network: strings.Repeat("b", 64), Application: app, PID: 77, Birth: 100, Source: netip.AddrPortFrom(netip.MustParseAddr("192.0.2.1"), port), Destination: netip.MustParseAddrPort("18.157.46.1:7766")}, at)
	if err != nil {
		t.Fatal(err)
	}
	return f
}
func failTrial(e *Engine, f *Flow, at time.Time) {
	prime(e, f, at)
	for i := 0; i <= 7; i++ {
		now := at.Add(time.Duration(i) * time.Second)
		e.Outgoing(f, 50, now)
		e.Tick(now)
	}
}
func TestLadderDirectLocalVariantsRelayThenCooldown(t *testing.T) {
	e := NewLadder(&Budget{})
	e.Configure(app, true)
	e.SetReason("")
	at := time.Unix(1000, 0)
	direct := ladderFlow(t, e, at, 50000)
	if direct.e.Stage != Direct {
		t.Fatal(direct.e)
	}
	if _, k := e.Plan(direct, at); k != 0 {
		t.Fatal("DIRECT primed")
	}
	failTrial(e, direct, at)
	at = at.Add(8 * time.Second)
	for i, v := range Variants() {
		f := ladderFlow(t, e, at, uint16(50001+i))
		if f.e.Stage != Local || f.e.Variant != v {
			t.Fatal(f.e)
		}
		failTrial(e, f, at)
		at = at.Add(8 * time.Second)
	}
	relay := ladderFlow(t, e, at, 50020)
	if relay.e.Stage != Relay {
		t.Fatal(relay.e)
	}
	if _, k := e.Plan(relay, at); k != 0 {
		t.Fatal("relay primed")
	}
	if direct.e.Stage != Direct {
		t.Fatal("existing tuple migrated")
	}
	failTrial(e, relay, at)
	if _, err := e.Open(relay.key, at.Add(8*time.Second)); err == nil {
		t.Fatal("unbounded ladder")
	}
	f := ladderFlow(t, e, at.Add(2*time.Hour), 50021)
	if f.e.Stage != Direct {
		t.Fatal("no cooldown recovery")
	}
}
func TestLadderHealthyDirectNeverUsesLocalOrRelay(t *testing.T) {
	e := NewLadder(nil)
	e.Configure(app, true)
	e.SetReason("")
	at := time.Unix(1000, 0)
	f := ladderFlow(t, e, at, 50000)
	sustain(e, f, at)
	next := ladderFlow(t, e, at.Add(5*time.Second), 50001)
	if next.e.Stage != Direct || len(e.Snapshot().Learning) != 1 || !e.Snapshot().Learning[0].Confirmed {
		t.Fatal(e.Snapshot())
	}
}
func TestEndpointLadderIgnoresLateFailureFromEarlierTrial(t *testing.T) {
	e := NewLadder(nil)
	e.SetEndpointScoped()
	e.Configure(app, true)
	e.SetReason("")
	at := time.Unix(1000, 0)
	direct := ladderFlow(t, e, at, 50000)
	slow := ladderFlow(t, e, at, 50001)
	failTrial(e, direct, at)
	local := ladderFlow(t, e, at.Add(8*time.Second), 50002)
	failTrial(e, local, at.Add(8*time.Second))
	failTrial(e, slow, at.Add(16*time.Second))
	next := ladderFlow(t, e, at.Add(24*time.Second), 50003)
	if next.e.Stage != Local || next.e.Variant != Variants()[1] {
		t.Fatal("late DIRECT failure reset the endpoint ladder", next.e)
	}
}
func TestGlobalBudgetAcrossGames(t *testing.T) {
	b := &Budget{}
	total := 0
	for i := 0; i < 30; i++ {
		e, _, at := fixture(t)
		e.shared = b
		f := ladderFlow(t, e, at, 50000)
		_, k := e.Plan(f, at)
		total += k
	}
	if total > MaxFakePerSecond {
		t.Fatal(total)
	}
}
func TestLadderRestoredLearningIsApplicationAndNetworkScoped(t *testing.T) {
	e := NewLadder(nil)
	e.Configure(app, true)
	e.SetReason("")
	at := time.Unix(1000, 0)
	f := ladderFlow(t, e, at, 50000)
	failTrial(e, f, at)
	v := e.Snapshot().Learning
	copy := NewLadder(nil)
	copy.Configure(app, true)
	copy.SetReason("")
	if err := copy.Restore(v, at.Add(8*time.Second)); err != nil {
		t.Fatal(err)
	}
	if ladderFlow(t, copy, at.Add(9*time.Second), 50001).e.Stage != Local {
		t.Fatal("lost failed DIRECT")
	}
	k := f.key
	k.Network = strings.Repeat("c", 64)
	g, err := copy.Open(k, at.Add(10*time.Second))
	if err != nil || g.e.Stage != Direct {
		t.Fatal("cross-network learning", err)
	}
}
func TestUnverifiedExistingTupleCannotPrimeRelayOrTeachFailure(t *testing.T) {
	e, f, at := fixture(t)
	e.PinUnverifiedDirect(f)
	if e.Evidence(f).Stage != Direct {
		t.Fatal("old tuple not pinned")
	}
	if _, k := e.Plan(f, at); k != 0 {
		t.Fatal("primed old tuple")
	}
	for i := 0; i < 8; i++ {
		e.Outgoing(f, 50, at.Add(time.Duration(i)*time.Second))
	}
	e.Tick(at.Add(7 * time.Second))
	if len(e.Snapshot().Learning) != 0 {
		t.Fatal("unknown tuple taught a trial failure")
	}
}
func TestConfirmedButRareRepliesDoNotHoldDirectForever(t *testing.T) {
	e := NewLadder(nil)
	e.Configure(app, true)
	e.SetReason("")
	at := time.Unix(1000, 0)
	f := ladderFlow(t, e, at, 50000)
	sustain(e, f, at)
	for i := 4; i <= 25; i++ {
		now := at.Add(time.Duration(i) * time.Second)
		e.Outgoing(f, 50, now)
		if i%4 == 0 {
			e.Reply(f, 20, now)
		}
		e.Tick(now)
	}
	if !f.failed || e.Snapshot().Learning[0].Stage != Local {
		t.Fatal("rare keepalive held DIRECT", e.Snapshot())
	}
	old := e.Snapshot().Learning[0]
	e.Tick(at.Add(26 * time.Second))
	if e.Snapshot().Learning[0] != old {
		t.Fatal("trial advanced repeatedly")
	}
}
func TestHarmlessShortReceiveGapDoesNotAdvanceHealthyDirect(t *testing.T) {
	e := NewLadder(nil)
	e.Configure(app, true)
	e.SetReason("")
	at := time.Unix(1000, 0)
	f := ladderFlow(t, e, at, 50000)
	sustain(e, f, at)
	for i := 8; i < 24; i++ {
		now := at.Add(time.Duration(i) * time.Second / 2)
		e.Outgoing(f, 50, now)
		if i != 10 {
			e.Reply(f, 50, now)
		}
		e.Tick(now)
	}
	if f.failed || e.Snapshot().Learning[0].Stage != Direct {
		t.Fatal(e.Snapshot())
	}
}
func TestRelayTransportFailureIsNotLearnedAsGameServerHealth(t *testing.T) {
	e := NewLadder(nil)
	e.Configure(app, true)
	e.SetReason("")
	at := time.Unix(1000, 0)
	if err := e.Restore([]Learning{{Network: strings.Repeat("b", 64), Application: app, Stage: Relay, Tried: 7, Expires: at.Add(time.Minute)}}, at); err != nil {
		t.Fatal(err)
	}
	f := ladderFlow(t, e, at, 50000)
	e.TransportFailed(f, "GAME_RELAY_OPEN_FAILED")
	e.TransportFailed(f, "unsafe message should not replace precise cause")
	v := e.Evidence(f)
	if v.State != "TRANSPORT_FAILED" || v.Reason != "GAME_RELAY_OPEN_FAILED" {
		t.Fatal(v)
	}
	if len(e.Snapshot().Learning) != 1 || e.Snapshot().Learning[0].Confirmed || e.Snapshot().Learning[0].Exhausted {
		t.Fatal("transport error learned as game network health")
	}
}
func TestHealthyOtherGameEndpointCannotHoldBlockedEndpointDirect(t *testing.T) {
	e := NewLadder(nil)
	e.Configure(app, true)
	e.SetReason("")
	at := time.Unix(1000, 0)
	good := ladderFlow(t, e, at, 50000)
	sustain(e, good, at)
	key := good.key
	key.Source = netip.MustParseAddrPort("192.0.2.1:50001")
	key.Destination = netip.MustParseAddrPort("18.157.29.51:7923")
	bad, err := e.Open(key, at.Add(4*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	for i := 4; i <= 11; i++ {
		now := at.Add(time.Duration(i) * time.Second)
		e.Outgoing(good, 50, now)
		e.Reply(good, 50, now)
		e.Outgoing(bad, 50, now)
		e.Tick(now)
	}
	next, err := e.Open(key, at.Add(12*time.Second))
	if err != nil || e.Evidence(next).Stage != Local {
		t.Fatal("unrelated responder held failed server DIRECT", err, e.Snapshot())
	}
	stillGood, err := e.Open(good.key, at.Add(12*time.Second))
	if err != nil || e.Evidence(stillGood).Stage != Direct {
		t.Fatal("working game endpoint inherited unnecessary workaround", err, e.Snapshot())
	}
}
func TestHealthyEndpointChurnDoesNotEvictFailureLadder(t *testing.T) {
	e := NewLadder(nil)
	at := time.Unix(1000, 0)
	network := strings.Repeat("a", 64)
	key := learnKey(network, app)
	e.putLearning(key, Learning{Network: network, Application: app, Stage: Local, Expires: at.Add(10 * time.Minute)}, at)
	for i := 0; i < 50; i++ {
		dst := netip.AddrPortFrom(netip.AddrFrom4([4]byte{18, 157, 1, byte(i + 1)}), 7766).String()
		e.putLearning(endpointKey(network, app, dst), Learning{Endpoint: dst, Network: network, Application: app, Stage: Direct, Confirmed: true, Expires: at.Add(LearnTTL)}, at)
	}
	if len(e.learning) > MaxNetworks || e.learning[key].Stage != Local {
		t.Fatal("QoS cache churn erased blocked path learning")
	}
}
func TestNetworkChangeStopsOldFlowTrainingWithoutMigratingIt(t *testing.T) {
	e, f, at := fixture(t)
	e.SetNetwork(strings.Repeat("b", 64))
	if _, k := e.Plan(f, at); k != 0 {
		t.Fatal("old first flight continued on a different network")
	}
	for i := 0; i < 8; i++ {
		e.Outgoing(f, 50, at.Add(time.Duration(i)*time.Second))
		e.Tick(at.Add(time.Duration(i) * time.Second))
	}
	if len(e.Snapshot().Learning) != 0 {
		t.Fatal("new path taught old fingerprint")
	}
	if _, err := e.Open(f.key, at.Add(8*time.Second)); err == nil {
		t.Fatal("stale classifier fingerprint accepted")
	}
	if e.Evidence(f).Stage != Local {
		t.Fatal("existing flow migrated")
	}
}
