package gameudp

import (
	"net/netip"
	"testing"
	"time"
)

func TestLocalOnlyExhaustionPersistsWithoutRelay(t *testing.T) {
	e := NewLadder(nil)
	e.SetLocalOnly(true)
	e.Configure(app, true)
	e.SetReason("")
	at := time.Unix(1000, 0)
	direct := ladderFlow(t, e, at, 50000)
	failTrial(e, direct, at)
	at = at.Add(8 * time.Second)
	for i := range Variants() {
		f := ladderFlow(t, e, at, uint16(50001+i))
		if f.e.Stage != Local {
			t.Fatal(f.e)
		}
		failTrial(e, f, at)
		at = at.Add(8 * time.Second)
	}
	if _, err := e.Open(direct.key, at); err == nil || err.Error() != "GAME_UDP_LOCAL_ONLY_EXHAUSTED" {
		t.Fatal(err)
	}
	copy := NewLadder(nil)
	copy.SetLocalOnly(true)
	copy.Configure(app, true)
	copy.SetReason("")
	if err := copy.Restore(e.Snapshot().Learning, at); err != nil {
		t.Fatal(err)
	}
	if _, err := copy.Open(direct.key, at); err == nil {
		t.Fatal("restart lost local exhaustion")
	}
	for _, l := range e.Snapshot().Learning {
		if l.Stage == Relay || !l.LocalOnly || !l.Exhausted {
			t.Fatal(l)
		}
	}
	if f := ladderFlow(t, copy, at.Add(2*time.Hour), 50100); f.e.Stage != Direct {
		t.Fatal(f.e)
	}
	if direct.e.Stage != Direct {
		t.Fatal("existing flow migrated")
	}
}
func TestLocalOnlyRejectsOldRelayLearningAndOldFlowObservations(t *testing.T) {
	e := NewLadder(nil)
	e.Configure(app, true)
	e.SetReason("")
	at := time.Unix(1000, 0)
	f := ladderFlow(t, e, at, 50000)
	cache := Learning{Stage: Relay, Network: f.key.Network, Application: app, Expires: at.Add(time.Hour)}
	if err := e.Restore([]Learning{cache}, at); err != nil {
		t.Fatal(err)
	}
	relay := ladderFlow(t, e, at, 50001)
	if relay.e.Stage != Relay {
		t.Fatal("fixture not relay")
	}
	e.SetLocalOnly(true)
	next := ladderFlow(t, e, at, 50002)
	if next.e.Stage != Direct {
		t.Fatal("old relay cache escaped", next.e)
	}
	sustain(e, relay, at)
	if relay.e.Stage != Relay {
		t.Fatal("existing flow migrated")
	}
	for _, l := range e.Snapshot().Learning {
		if l.LocalOnly && l.Stage == Relay {
			t.Fatal("old flow taught relay")
		}
	}
	cache.LocalOnly = true
	if err := e.Restore([]Learning{cache}, at); err == nil {
		t.Fatal("invalid local-only relay learning accepted")
	}
}

// Synthetic cadence regression based on the reported CS2 totals/span. This is
// not the original capture/fixture: exact intermediate packet times are absent.
func TestCS2SixReplyBurstThenContinuingTXIsNotHealthy(t *testing.T) {
	e := NewLadder(nil)
	e.SetLocalOnly(true)
	e.Configure(app, true)
	e.SetReason("")
	at := time.Unix(1000, 0)
	f := ladderFlow(t, e, at, 50000)
	for i := 0; i < 6; i++ {
		now := at.Add(time.Duration(i) * 386681 * time.Microsecond / 5)
		e.Outgoing(f, 50, now)
		e.Reply(f, 26, now)
	}
	for i := 6; i < 2065; i++ {
		now := at.Add(386681*time.Microsecond + time.Duration(i-5)*10890*time.Millisecond/2059)
		e.Outgoing(f, 50, now)
		e.Tick(now)
	}
	if f.learned || f.e.State != "INSUFFICIENT_REPLIES" || f.e.Replies != 6 || f.e.Outgoing != 2065 {
		t.Fatal(f.e)
	}
	next := ladderFlow(t, e, at.Add(12*time.Second), 50001)
	if next.e.Stage != Local {
		t.Fatal(next.e)
	}
	if f.e.Stage != Direct {
		t.Fatal("existing stalled flow migrated")
	}
}

func TestLocalOnlyLearningIsEndpointScopedAndHealthyDirectReusable(t *testing.T) {
	e := NewLadder(nil)
	e.SetLocalOnly(true)
	e.Configure(app, true)
	e.SetReason("")
	at := time.Unix(1000, 0)
	f := ladderFlow(t, e, at, 50000)
	failTrial(e, f, at)
	other := f.key
	other.Destination = netip.MustParseAddrPort("18.157.46.2:7766")
	healthy, err := e.Open(other, at.Add(8*time.Second))
	if err != nil || healthy.e.Stage != Direct {
		t.Fatal("failure crossed endpoint", err)
	}
	sustain(e, healthy, at.Add(8*time.Second))
	restored := NewLadder(nil)
	restored.SetLocalOnly(true)
	restored.Configure(app, true)
	restored.SetReason("")
	if err := restored.Restore(e.Snapshot().Learning, at.Add(12*time.Second)); err != nil {
		t.Fatal(err)
	}
	next, err := restored.Open(other, at.Add(13*time.Second))
	if err != nil || next.e.Stage != Direct || next.e.Selection != "CONFIRMED_DIRECT_ENDPOINT" {
		t.Fatal("healthy direct lost", err)
	}
	if f := ladderFlow(t, restored, at.Add(13*time.Second), 50001); f.e.Stage != Local {
		t.Fatal("failed endpoint reset", f.e)
	}
}
