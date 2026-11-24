package gameudp

import (
	"net/netip"
	"testing"
	"time"
)

func TestSTUN687AutoCutoffsAndPinnedDirect(t *testing.T) {
	e, k, at := cs2Fixture()
	e.SetSTUNAuto(true)
	f, err := e.OpenCS2(k, at)
	if err != nil || e.Evidence(f).Stage != Local {
		t.Fatal(err)
	}
	if e.Evidence(f).FakeTTL != 8 {
		t.Fatal(e.Evidence(f))
	}
	packets := [][]byte{{32}, {34}, {255, 255, 255, 255, 0, 0, 0}, {128, 1, 2, 3, 4, 5, 6}, {128, 1, 2, 3, 4, 5, 6}, {128, 1, 2, 3, 4, 5, 6}, {128, 1, 2, 3, 4, 5, 6}, {128, 1, 2, 3, 4, 5, 6}}
	want := []int{6, 6, 0, 6, 6, 6, 6, 0}
	for i, d := range packets {
		p, n := e.PlanDatagram(f, d, at)
		if n != want[i] || n > 0 && !IsSTUNBinding(p) {
			t.Fatalf("packet %d: count %d", i, n)
		}
	}
	other := advanceCS2Source(k, 1)
	other.Destination = netip.MustParseAddrPort("203.0.113.9:27015")
	if otherFlow, err := e.OpenCS2(other, at); err != nil || e.Evidence(otherFlow).Stage != Local {
		t.Fatal(err)
	}
	e.SetSTUNAuto(false)
	if _, n := e.PlanDatagram(f, packets[3], at); n != 0 {
		t.Fatal("disabled strategy sent decoys")
	}
	// Positive game evidence keeps an ordinary direct endpoint on its proven route.
	f = openCS2(t, e, k, at, Direct)
	e.Outgoing(f, 10, at)
	e.Reply(f, 10, at)
	if err := e.RecordCS2Outcome(outcomeCS2(f, "JOINED"), at.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	e.SetSTUNAuto(true)
	openCS2(t, e, advanceCS2Source(k, 2), at.Add(2*time.Second), Direct)
}
