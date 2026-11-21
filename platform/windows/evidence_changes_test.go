package windowsplatform

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"testing"
	"time"

	"github.com/buzzmean/neexitlag/core/flowpolicy"
	"github.com/buzzmean/neexitlag/core/transport"
)

func drainChanges(t *testing.T, l *EvidenceLedger, cursor *ChangeCursor, seen map[uint64]FlowEvidence) {
	t.Helper()
	for i := 0; i < 200; i++ {
		p, err := l.ChangePage(ChangeQuery{*cursor})
		if err != nil || p.EvidenceLost {
			t.Fatal("incomplete cursor", p, err)
		}
		raw, _ := json.Marshal(p)
		if len(raw) > 60000 || len(p.Flows) > 32 {
			t.Fatal("frame bound", len(raw), len(p.Flows))
		}
		for _, v := range p.Flows {
			seen[v.FlowID] = v
		}
		*cursor = p.Cursor
		if !p.More {
			return
		}
	}
	t.Fatal("pagination did not terminate")
}
func TestChangeCursorKeepsLongLivedUpdatesAndReusedTuples(t *testing.T) {
	l := NewEvidenceLedger()
	cursor := l.ChangeMarker()
	seen := map[uint64]FlowEvidence{}
	id := ProcessIdentity{PID: 42, CreationTime: 1, Path: "protected.exe"}
	tuple := testTuple()
	for i := 0; i < 80; i++ {
		tup := tuple
		tup.Source = netip.AddrPortFrom(tuple.Source.Addr(), uint16(2000+i))
		l.BeginFlow(id, tup)
		l.RecordBytes(id, tup, "relay", "VPS-01", 10)
	}
	drainChanges(t, l, &cursor, seen)
	if len(seen) != 80 {
		t.Fatal(len(seen))
	}
	// This existing flow's later DIRECT byte must not vanish behind an advanced birth marker.
	first := tuple
	first.Source = netip.AddrPortFrom(tuple.Source.Addr(), 2000)
	l.RecordBytes(id, first, "direct", "", 1)
	drainChanges(t, l, &cursor, seen)
	leaks := 0
	for _, v := range seen {
		if v.Counters.DirectBytes > 0 {
			leaks++
		}
	}
	if leaks != 1 {
		t.Fatal("late leak lost", leaks)
	}
	l.BeginFlow(id, first)
	l.RecordBytes(id, first, "relay", "VPS-01", 5)
	drainChanges(t, l, &cursor, seen)
	if len(seen) != 81 {
		t.Fatal("tuple reuse lost final evidence", len(seen))
	}
}
func TestChangeCursorSurvivesBoundedHistoryChurnAndReportsLag(t *testing.T) {
	l := NewEvidenceLedger()
	cursor := l.ChangeMarker()
	stale := cursor
	seen := map[uint64]FlowEvidence{}
	id := ProcessIdentity{PID: 42, CreationTime: 1, Path: "app.exe"}
	tuple := testTuple()
	for i := 0; i < 3200; i++ {
		tup := tuple
		tup.Source = netip.AddrPortFrom(tuple.Source.Addr(), uint16(2000+i))
		l.BeginFlow(id, tup)
		l.RecordBytes(id, tup, "relay", "VPS-01", 1)
		if i%40 == 0 {
			drainChanges(t, l, &cursor, seen)
		}
	}
	drainChanges(t, l, &cursor, seen)
	if len(seen) != 3200 || len(l.flows) > 1024 || len(l.retired) > 1024 {
		t.Fatal(len(seen), len(l.flows), len(l.retired))
	}
	if p, err := l.ChangePage(ChangeQuery{stale}); err != nil || !p.EvidenceLost {
		t.Fatal("lag falsely complete", p, err)
	}
	if _, err := NewEvidenceLedger().ChangePage(ChangeQuery{cursor}); err == nil {
		t.Fatal("restart cursor accepted")
	}
}
func TestRetainedLatePacketKeepsDirectPlusMetadata(t *testing.T) {
	l := NewEvidenceLedger()
	cursor := l.ChangeMarker()
	id := ProcessIdentity{PID: 1, CreationTime: 1, Path: "chrome.exe"}
	tuple := testTuple()
	l.RecordLocal(id, tuple, "disorder", "youtube.com", 100)
	original := l.Snapshot(1).Flows[0].FlowID
	for i := 0; i < 1024; i++ {
		other := tuple
		other.Source = netip.AddrPortFrom(tuple.Source.Addr(), uint16(2000+i))
		l.RecordBytes(id, other, "relay", "R", 1)
	}
	l.RecordBytes(id, tuple, "direct", "", 1)
	seen := map[uint64]FlowEvidence{}
	drainChanges(t, l, &cursor, seen)
	v := seen[original]
	if v.Route != "DIRECT_PLUS" || v.Strategy != "disorder" || v.Counters.DirectPlusBytes != 100 || v.Counters.DirectBytes != 1 {
		t.Fatal(v)
	}
}
func TestRelayQueueAndOpenEvidenceAttributesActualStall(t *testing.T) {
	l := NewEvidenceLedger()
	id := ProcessIdentity{PID: 1, CreationTime: 1, Path: "media.exe"}
	tuple := testTuple()
	l.RecordBytes(id, tuple, "captured", "", 1)
	l.RecordPolicy(id, tuple, Decision{Policy: flowpolicy.Result{Action: flowpolicy.RelayRequired}}, "")
	l.RecordUDPQueue(id, tuple, 32, true, true, 700*time.Millisecond)
	l.RecordUDPQueue(id, tuple, 32, false, true, time.Second)
	l.RecordRelayOpen(id, tuple, time.Now().Add(-750*time.Millisecond), &transport.OpenError{Reason: "stream_capacity", Cause: transport.ErrCapacity})
	v := l.Snapshot(1).Flows[0]
	if v.UDPQueue.DropsDuringOpen != 1 || v.UDPQueue.DropsAfterOpen != 1 || v.UDPQueue.HighWater != 32 || v.UDPQueue.MaxWaitMS != 1000 || v.RelayOpen.FailureReason != "stream_capacity" || v.RelayOpen.DurationMS < 750 {
		t.Fatal(fmt.Sprintf("%+v %+v", v.UDPQueue, v.RelayOpen))
	}
	if v.Counters.Relayed != 0 || v.Counters.Direct != 0 {
		t.Fatal("diagnostics manufactured packets")
	}
}

func TestChangeCursorConcurrentLongLivedCounterUpdates(t *testing.T) {
	l := NewEvidenceLedger()
	cursor := l.ChangeMarker()
	id := ProcessIdentity{PID: 1, CreationTime: 1, Path: "protected.exe"}
	tuple := testTuple()
	l.RecordBytes(id, tuple, "relay", "VPS-01", 1)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 1000; i++ {
			l.RecordBytes(id, tuple, "direct", "", 1)
		}
	}()
	seen := map[uint64]FlowEvidence{}
	for {
		drainChanges(t, l, &cursor, seen)
		select {
		case <-done:
			drainChanges(t, l, &cursor, seen)
			for _, v := range seen {
				if v.Counters.DirectBytes != 1000 {
					t.Fatal("concurrent update lost", v.Counters)
				}
			}
			return
		default:
		}
	}
}
