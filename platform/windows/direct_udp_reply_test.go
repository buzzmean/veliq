package windowsplatform

import (
	"encoding/json"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/buzzmean/veliq/core/flowpolicy"
)

func directUDPFixture(t *testing.T, port uint16, bound bool) (*EvidenceLedger, ProcessIdentity, Tuple, uint64) {
	t.Helper()
	l := NewEvidenceLedger()
	id := ProcessIdentity{PID: 42, CreationTime: 1234, Path: "game.exe"}
	tuple := Tuple{Protocol: "udp", Source: netip.MustParseAddrPort("192.0.2.1:45000"), Destination: netip.AddrPortFrom(netip.MustParseAddr("203.0.113.2"), port)}
	l.BeginFlow(id, tuple)
	l.RecordBytes(id, tuple, "captured", "", 100)
	l.RecordPolicy(id, tuple, Decision{Policy: flowpolicy.Result{Action: flowpolicy.Direct}}, "")
	flowID := l.NoteDirectUDP(id, tuple, bound)
	l.RecordBytes(id, tuple, "direct", "", 100)
	return l, id, tuple, flowID
}

func TestDirectUDPReplyCountsExistingFlowWithoutMutatingRoute(t *testing.T) {
	l, id, tuple, generation := directUDPFixture(t, 28017, true)
	before := l.Snapshot(id.PID).Flows[0]
	cursor := l.ChangeMarker()
	first, last := time.Now(), time.Now().Add(time.Second)
	if !l.RecordDirectUDPReply(id, tuple, generation, 80, first) || !l.RecordDirectUDPReply(id, tuple, generation, 120, last) {
		t.Fatal("bound replies not recorded")
	}
	after := l.Snapshot(id.PID).Flows[0]
	if after.Counters.DirectReplyPackets != 2 || after.Counters.DirectReplyBytes != 200 || after.Counters.Direct != 1 || after.Counters.Relayed != 0 || after.Counters.Dropped != 0 || after.Route != before.Route || after.Policy != before.Policy {
		t.Fatal("passive accounting changed routing or counters", after)
	}
	if !after.DirectUDPReply.FirstReply.Equal(first) || !after.DirectUDPReply.LastReply.Equal(last) || !before.DirectUDPReply.FirstReply.IsZero() {
		t.Fatal("timestamps or snapshot isolation lost")
	}
	page, err := l.ChangePage(ChangeQuery{Cursor: cursor})
	if err != nil || len(page.Flows) != 1 || page.Flows[0].Counters.DirectReplyPackets != 2 || page.Counters.DirectReplyPackets != 2 {
		t.Fatal("changed flow not available to journal consumers", page, err)
	}
}

func TestDirectUDPReplyRejectsStaleIdentityTupleAndGeneration(t *testing.T) {
	l, id, tuple, generation := directUDPFixture(t, 28017, true)
	changed := id
	changed.CreationTime++
	otherTuple := tuple
	otherTuple.Destination = netip.MustParseAddrPort("203.0.113.3:28017")
	if l.RecordDirectUDPReply(changed, tuple, generation, 80, time.Now()) || l.RecordDirectUDPReply(id, otherTuple, generation, 80, time.Now()) || l.RecordDirectUDPReply(id, tuple, generation+1, 80, time.Now()) {
		t.Fatal("cross identity/tuple/generation reply accepted")
	}
	l.BeginFlow(id, tuple)
	if l.RecordDirectUDPReply(id, tuple, generation, 80, time.Now()) {
		t.Fatal("retired generation accepted")
	}
	if l.Snapshot(0).Counters.DirectReplyPackets != 0 {
		t.Fatal("rejected input changed lifetime totals")
	}
}

func TestDirectUDPReplyCoverageReportsUnavailablePartialAndObserved(t *testing.T) {
	l, id, tuple, generation := directUDPFixture(t, 28017, true)
	for _, tc := range []struct {
		name, state, reason string
		observer            UDPReplyObserverStatus
	}{
		{"unavailable", "UNAVAILABLE", "RECEIVE_FAILED", UDPReplyObserverStatus{Reason: "RECEIVE_FAILED", NativeError: 5}},
		{"ready", "OBSERVING", "PASSIVE_DIRECT_NO_REPLY_OBSERVED", UDPReplyObserverStatus{Available: true, StartedAt: time.Now().Add(-time.Minute)}},
		{"late", "PARTIAL", "OBSERVER_STARTED_AFTER_FLOW", UDPReplyObserverStatus{Available: true, StartedAt: time.Now().Add(time.Minute)}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out := l.Snapshot(id.PID)
			decorateDirectUDPReplies(out.Flows, tc.observer)
			if x := out.Flows[0].DirectUDPReply; x.State != tc.state || x.Reason != tc.reason {
				t.Fatal(x)
			}
		})
	}
	l.RecordDirectUDPReply(id, tuple, generation, 80, time.Now())
	out := l.Snapshot(id.PID)
	decorateDirectUDPReplies(out.Flows, UDPReplyObserverStatus{Available: true, StartedAt: time.Now().Add(-time.Minute)})
	if out.Flows[0].DirectUDPReply.Reason != "PASSIVE_DIRECT_REPLY_OBSERVED" {
		t.Fatal(out.Flows[0].DirectUDPReply)
	}
	raw, _ := json.Marshal(out.Flows[0].DirectUDPReply)
	var data map[string]any
	json.Unmarshal(raw, &data)
	if data["first_reply"] == nil || data["last_reply"] == nil {
		t.Fatal("reply timestamps absent", string(raw))
	}
}

func TestDirectUDPReplyUnboundAndExistingFilterExclusions(t *testing.T) {
	for _, tc := range []struct {
		port   uint16
		bound  bool
		reason string
	}{{53, true, "OUTSIDE_EXISTING_SNIFF_FILTER"}, {28017, false, "NATIVE_ENDPOINT_NOT_BOUND"}} {
		l, id, tuple, generation := directUDPFixture(t, tc.port, tc.bound)
		if l.RecordDirectUDPReply(id, tuple, generation, 80, time.Now()) {
			t.Fatal("unobserved scope accepted")
		}
		out := l.Snapshot(id.PID)
		decorateDirectUDPReplies(out.Flows, UDPReplyObserverStatus{Available: true, StartedAt: time.Now().Add(-time.Minute)})
		if out.Flows[0].DirectUDPReply.Reason != tc.reason || out.Flows[0].DirectUDPReply.State != "UNAVAILABLE" {
			t.Fatal(out.Flows[0].DirectUDPReply)
		}
	}
}

func TestDirectUDPReplyConcurrentSnapshotsAndCounters(t *testing.T) {
	l, id, tuple, generation := directUDPFixture(t, 28017, true)
	var wg sync.WaitGroup
	for worker := 0; worker < 4; worker++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 100; i++ {
				l.RecordDirectUDPReply(id, tuple, generation, 80, time.Now())
				out := l.Snapshot(id.PID)
				decorateDirectUDPReplies(out.Flows, UDPReplyObserverStatus{Available: true, StartedAt: time.Now().Add(-time.Minute)})
				json.Marshal(out)
				l.ChangePage(ChangeQuery{Cursor: ChangeCursor{LedgerID: l.ChangeMarker().LedgerID}})
			}
		}()
	}
	wg.Wait()
	if l.Snapshot(id.PID).Flows[0].Counters.DirectReplyPackets != 400 {
		t.Fatal("reply count lost")
	}
}

func TestDirectUDPReplyNoAllocationAndLateIdentityCoverage(t *testing.T) {
	l, id, tuple, generation := directUDPFixture(t, 28017, true)
	at := time.Now()
	if allocs := testing.AllocsPerRun(100, func() { l.RecordDirectUDPReply(id, tuple, generation, 80, at) }); allocs != 0 {
		t.Fatalf("steady reply accounting allocates %.1f objects", allocs)
	}
	l2, id2, tuple2, _ := directUDPFixture(t, 28017, false)
	l2.NoteDirectUDP(id2, tuple2, true)
	out := l2.Snapshot(id2.PID)
	decorateDirectUDPReplies(out.Flows, UDPReplyObserverStatus{Available: true, StartedAt: time.Now().Add(-time.Minute)})
	if out.Flows[0].DirectUDPReply.State != "PARTIAL" || out.Flows[0].DirectUDPReply.Reason != "IDENTITY_BOUND_AFTER_FIRST_PACKET" {
		t.Fatal(out.Flows[0].DirectUDPReply)
	}
}

func TestDirectUDPReplyMetadataIncludedBeforePageSizeAndCursorLimits(t *testing.T) {
	l := NewEvidenceLedger()
	id := ProcessIdentity{PID: 42, CreationTime: 1234, Path: "game.exe"}
	start := l.ChangeMarker()
	for i := 0; i < 40; i++ {
		tuple := Tuple{Protocol: "udp", Source: netip.AddrPortFrom(netip.MustParseAddr("192.0.2.1"), uint16(45000+i)), Destination: netip.MustParseAddrPort("203.0.113.2:28017")}
		l.BeginFlow(id, tuple)
		l.RecordBytes(id, tuple, "direct", "", 80)
		l.RecordPolicy(id, tuple, Decision{Policy: flowpolicy.Result{Action: flowpolicy.Direct, Reason: strings.Repeat("X", 4500)}}, "")
	}
	observer := UDPReplyObserverStatus{Available: true, Reason: "PASSIVE_SNIFF", StartedAt: time.Now().Add(-time.Minute)}
	snapshot, err := l.snapshotQueryWithUDPObserver(EvidenceQuery{PID: id.PID}, nil, &observer)
	raw, _ := json.Marshal(snapshot)
	if err != nil || len(raw) >= 60000 || !snapshot.Truncated || snapshot.UDPReplyObserver == nil {
		t.Fatal("decorated snapshot exceeds byte limit", len(raw), err)
	}
	seen := map[uint64]bool{}
	for pageNumber := 0; pageNumber < 10; pageNumber++ {
		page, err := l.changePageWithUDPObserver(ChangeQuery{Cursor: start}, &observer)
		raw, _ := json.Marshal(page)
		if err != nil || len(raw) > 58000 || len(page.Flows) == 0 || page.UDPReplyObserver == nil {
			t.Fatal("decorated page exceeds byte limit", len(raw), err)
		}
		for _, flow := range page.Flows {
			if seen[flow.FlowID] {
				t.Fatal("duplicate cursor record")
			}
			seen[flow.FlowID] = true
		}
		start = page.Cursor
		if !page.More {
			break
		}
	}
	if len(seen) != 40 {
		t.Fatal("decorated pagination lost flows", len(seen))
	}
}
