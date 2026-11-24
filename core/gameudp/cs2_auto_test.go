package gameudp

import (
	"encoding/json"
	"net/netip"
	"strings"
	"testing"
	"time"
)

func cs2Fixture() (*Engine, Key, time.Time) {
	e := NewLadder(nil)
	k := Key{Network: strings.Repeat("b", 64), Application: `C:\Games\CS2\cs2.exe`, PID: 40, Birth: 100,
		Source: netip.MustParseAddrPort("192.0.2.1:35000"), Destination: netip.MustParseAddrPort("203.0.113.10:27015")}
	e.SetCS2Auto(true)
	e.Configure(k.Application, true)
	e.SetNetwork(k.Network)
	e.SetReason("")
	return e, k, time.Unix(1700000000, 0)
}

func openCS2(t *testing.T, e *Engine, k Key, at time.Time, want string) *Flow {
	t.Helper()
	f, err := e.OpenCS2(k, at)
	if err != nil || e.Evidence(f).Stage != want {
		t.Fatalf("open wanted %s: %+v %v", want, e.Evidence(f), err)
	}
	if p, count := e.Plan(f, at); p != nil || count != 0 {
		t.Fatal("CS2 AUTO generated traffic")
	}
	return f
}

func outcomeCS2(f *Flow, outcome string) CS2Outcome {
	return CS2Outcome{FlowID: f.e.ID, Started: f.e.Started, PID: f.key.PID, Birth: f.key.Birth,
		Destination: f.key.Destination, Outcome: outcome}
}

func advanceCS2Source(k Key, n uint16) Key {
	k.Source = netip.AddrPortFrom(k.Source.Addr(), k.Source.Port()+n)
	return k
}

func TestCS2AutoOnlyEarlyGameTimeoutArmsOneFreshLocalSocket(t *testing.T) {
	e, k, at := cs2Fixture()
	f := openCS2(t, e, k, at, Direct)
	for i := 0; i < 12; i++ {
		stamp := at.Add(time.Duration(i) * time.Second)
		e.Outgoing(f, 100, stamp)
		e.Tick(stamp)
	}
	second := at.Add(12 * time.Second)
	openCS2(t, e, advanceCS2Source(k, 1), second, Direct)
	q := outcomeCS2(f, "TIMEOUT")
	q.Phase = "NO_REPLY_OBSERVED"
	if err := e.RecordCS2Outcome(q, second); err != nil {
		t.Fatal(err)
	}
	other := k
	other.Destination = netip.AddrPortFrom(k.Destination.Addr(), 27016)
	openCS2(t, e, other, second, Direct)
	openCS2(t, e, k, second, Direct)
	trial := openCS2(t, e, advanceCS2Source(k, 3), second, LocalSocket)
	openCS2(t, e, advanceCS2Source(k, 4), second, Direct)
	if f.e.Stage != Direct || trial.e.Selection != "CS2_LOCAL_SOCKET_TRIAL" {
		t.Fatal(f.e, trial.e)
	}
	e.Outgoing(trial, 20, second)
	e.Reply(trial, 30, second)
	if err := e.RecordCS2Outcome(outcomeCS2(trial, "JOINED"), second); err != nil {
		t.Fatal(err)
	}
	openCS2(t, e, advanceCS2Source(k, 5), second.Add(6*time.Second), LocalSocket)
	openCS2(t, e, advanceCS2Source(k, 6), second.Add(cs2EvidenceTTL), Direct)
}
func TestCS2AutoRefusalCapacityAndAmbiguousOutcomesDoNotTeachFailover(t *testing.T) {
	for _, outcome := range []string{"FULL", "DENIED", "UNKNOWN", "JOINED"} {
		e, k, at := cs2Fixture()
		f := openCS2(t, e, k, at, Direct)
		e.Outgoing(f, 20, at)
		e.Reply(f, 30, at)
		if err := e.RecordCS2Outcome(outcomeCS2(f, outcome), at); err != nil {
			t.Fatal(outcome, err)
		}
		openCS2(t, e, advanceCS2Source(k, 1), at.Add(8*time.Second), Direct)
		if err := e.RecordCS2Outcome(outcomeCS2(f, "TIMEOUT"), at.Add(2*time.Second)); err == nil {
			t.Fatal("contradictory event accepted", outcome)
		}
	}
}

func TestCS2AutoRequiresFlowIdentityLivenessAndGameOutcome(t *testing.T) {
	e, k, at := cs2Fixture()
	f := openCS2(t, e, k, at, Direct)
	q := outcomeCS2(f, "TIMEOUT")
	now := at.Add(2 * time.Second)
	if e.RecordCS2Outcome(q, now) == nil {
		t.Fatal("no original datagram")
	}
	e.Outgoing(f, 20, at)
	for _, bad := range []func(*CS2Outcome){
		func(v *CS2Outcome) { v.PID++ }, func(v *CS2Outcome) { v.Birth++ }, func(v *CS2Outcome) { v.Started = v.Started.Add(time.Second) },
		func(v *CS2Outcome) { v.Destination = netip.MustParseAddrPort("203.0.113.99:27015") }, func(v *CS2Outcome) { v.FlowID++ },
		func(v *CS2Outcome) { v.Outcome = "JOINED" }, func(v *CS2Outcome) { v.Outcome = "OTHER" },
	} {
		mod := q
		bad(&mod)
		if err := e.RecordCS2Outcome(mod, now); err == nil {
			t.Fatal("accepted", mod)
		}
	}
	if e.RecordCS2Outcome(q, now.Add(2*time.Minute)) == nil {
		t.Fatal("accepted stale result")
	}
	e.SetNetwork(strings.Repeat("c", 64))
	if e.RecordCS2Outcome(q, now) == nil {
		t.Fatal("accepted former network")
	}
	e.SetNetwork(k.Network)
	f = openCS2(t, e, advanceCS2Source(k, 1), now, Direct)
	e.PinUnverifiedDirect(f)
	e.Outgoing(f, 30, now)
	if e.RecordCS2Outcome(outcomeCS2(f, "TIMEOUT"), now.Add(3*time.Second)) == nil {
		t.Fatal("accepted existing unverified flow")
	}
}

func TestCS2AutoPreservesJoinPhaseAndQualityWithoutChangingTransport(t *testing.T) {
	e, k, at := cs2Fixture()
	f := openCS2(t, e, k, at, Direct)
	end := at.Add(45 * time.Second)
	e.Outgoing(f, 20, end)
	e.Reply(f, 30, end)
	q := outcomeCS2(f, "JOINED")
	q.Quality = &CS2Quality{RTTMS: 43, JitterMS: 6, LossPct: 2, Samples: 40, StableSeconds: 40}
	if e.RecordCS2Quality(q, end) == nil {
		t.Fatal("manual metrics taught join")
	}
	join := q
	join.Quality = nil
	join.Phase = "INGAME"
	if err := e.RecordCS2Outcome(join, end); err != nil {
		t.Fatal(err)
	}
	if err := e.RecordCS2Quality(q, end); err != nil {
		t.Fatal(err)
	}
	q.Quality.RTTMS = 5
	e.Tick(end.Add(3 * time.Minute))
	rows := e.Snapshot().CS2Endpoints
	if len(rows) != 1 || rows[0].Quality.RTTMS != 43 || rows[0].Phase != "INGAME" || rows[0].Stage != Direct {
		t.Fatal(rows)
	}
	rows[0].Quality.RTTMS = 10
	if e.Snapshot().CS2Endpoints[0].Quality.RTTMS != 43 {
		t.Fatal("mutable snapshot")
	}
	openCS2(t, e, advanceCS2Source(k, 2), end.Add(4*time.Minute), Direct)
}
func TestCS2AutoQualityMissingMetricsAreNotZero(t *testing.T) {
	for _, raw := range []string{
		`{"rtt_ms":10,"loss_pct":0,"samples":30,"stable_seconds":30}`,
		`{"rtt_ms":10,"loss_pct":null,"jitter_ms":0,"samples":30,"stable_seconds":30}`,
		`{"rtt_ms":10,"loss_pct":0,"jitter_ms":0,"samples":30,"stable_second":30}`,
	} {
		var q CS2Quality
		if json.Unmarshal([]byte(raw), &q) == nil {
			t.Fatal("accepted missing measurement")
		}
	}
	var q CS2Quality
	if err := json.Unmarshal([]byte(`{"rtt_ms":10,"jitter_ms":0,"loss_pct":0,"samples":30,"stable_seconds":30}`), &q); err != nil || !q.valid() {
		t.Fatal(q, err)
	}
}

func TestCS2AutoNeverUsesRemoteOrLegacyCandidate(t *testing.T) {
	e, k, at := cs2Fixture()
	e.SetStartLocal(true)
	e.learning[learnKey(k.Network, k.Application)] = Learning{Stage: Relay, Network: k.Network, Application: k.Application, Expires: at.Add(time.Hour)}
	f, err := e.OpenWithQuality(k, at, "healthy-remote")
	if err != nil || e.Evidence(f).Stage != Direct {
		t.Fatal(err, e.Evidence(f))
	}
	// A definite local send failure can qualify the next fresh socket.
	e.CS2LocalFailure(f, at)
	unverified := openCS2(t, e, advanceCS2Source(k, 1), at, LocalSocket)
	e.PinUnverifiedDirect(unverified)
	trial := openCS2(t, e, advanceCS2Source(k, 2), at, LocalSocket)
	e.CS2LocalFailure(trial, at)
	f = openCS2(t, e, advanceCS2Source(k, 3), at, Direct)
	e.CS2LocalFailure(f, at)
	openCS2(t, e, advanceCS2Source(k, 4), at.Add(time.Minute), Direct)
}

func TestCS2AutoLaterSignonAndMidstreamFailureNeverTryLocalSocket(t *testing.T) {
	for _, stage := range []string{"", "TRANSPORT_ONLY", "SERVER_ACCEPTED", "SIGNONSTATE_CONNECTED", "SIGNONSTATE_SPAWN", "SIGNONSTATE_FULL"} {
		e, k, at := cs2Fixture()
		f := openCS2(t, e, k, at, Direct)
		e.Outgoing(f, 12, at)
		e.Reply(f, 33, at)
		e.CS2LocalFailure(f, at)
		o := outcomeCS2(f, "TIMEOUT")
		o.Phase = stage
		if err := e.RecordCS2Outcome(o, at.Add(3*time.Second)); err != nil {
			t.Fatal(err)
		}
		openCS2(t, e, advanceCS2Source(k, 1), at.Add(4*time.Second), Direct)
	}
}

func TestCS2AutoLateNativeReplyCancelsLocalTrial(t *testing.T) {
	e, k, at := cs2Fixture()
	f := openCS2(t, e, k, at, Direct)
	e.Outgoing(f, 12, at)
	timeout := at.Add(10 * time.Second)
	q := outcomeCS2(f, "TIMEOUT")
	q.Phase = "NO_REPLY_OBSERVED"
	if err := e.RecordCS2Outcome(q, timeout); err != nil {
		t.Fatal(err)
	}
	e.Reply(f, 40, timeout.Add(time.Second))
	openCS2(t, e, advanceCS2Source(k, 1), timeout.Add(2*time.Second), Direct)
	e.Tick(timeout.Add(3 * time.Minute))
	openCS2(t, e, advanceCS2Source(k, 2), timeout.Add(3*time.Minute), Direct)
}

func TestCS2AutoStaleClassifierCannotClaimLocalSocket(t *testing.T) {
	e, k, at := cs2Fixture()
	f := openCS2(t, e, k, at, Direct)
	e.CS2LocalFailure(f, at)
	stale, err := e.OpenWithQuality(advanceCS2Source(k, 1), at, "relay-from-old-policy")
	if err != nil || e.Evidence(stale).Stage != Direct {
		t.Fatal(err, e.Evidence(stale))
	}
	openCS2(t, e, advanceCS2Source(k, 2), at, LocalSocket)
}

func TestCS2AutoEndpointHistoryIsBounded(t *testing.T) {
	e, k, at := cs2Fixture()
	for i := 0; i < cs2MaxEndpoints+2; i++ {
		k.Destination = netip.AddrPortFrom(k.Destination.Addr(), uint16(27015+i))
		f := openCS2(t, e, k, at.Add(time.Duration(i)*time.Second), Direct)
		e.CS2LocalFailure(f, at.Add(time.Duration(i)*time.Second))
	}
	if n := len(e.Snapshot().CS2Endpoints); n != cs2MaxEndpoints {
		t.Fatal(n)
	}
	e.Tick(at.Add(cs2EvidenceTTL + time.Minute))
	if n := len(e.Snapshot().CS2Endpoints); n != 0 {
		t.Fatal(n)
	}
}

func TestCS2RestoreRejectsStaleAndInUseRoutes(t *testing.T) {
	e, k, at := cs2Fixture()
	row := CS2Preference{Network: k.Network, Destination: k.Destination, Stage: LocalSocket, ConfirmedAt: at.Add(-cs2EvidenceTTL)}
	if err := e.RestoreCS2Preferences(k.Application, []CS2Preference{row}, at); err != nil {
		t.Fatal(err)
	}
	f := openCS2(t, e, k, at, Direct)
	row.ConfirmedAt = at
	if err := e.RestoreCS2Preferences(k.Application, []CS2Preference{row}, at); err != nil {
		t.Fatal(err)
	}
	openCS2(t, e, advanceCS2Source(k, 1), at, Direct)
	if f.e.Stage != Direct {
		t.Fatal("live socket moved")
	}
	row.Stage = Relay
	if err := e.RestoreCS2Preferences(k.Application, []CS2Preference{row}, at); err == nil {
		t.Fatal("accepted relay")
	}
}
