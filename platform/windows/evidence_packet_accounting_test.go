package windowsplatform

import (
	"net/netip"
	"testing"
)

func TestPacketAccountingKeepsCanonicalEndpointsAcrossAliasAndPIDReuse(t *testing.T) {
	l := NewEvidenceLedger()
	id := ProcessIdentity{PID: 42, CreationTime: 10, Path: "app.exe"}
	original := Tuple{Protocol: "tcp", Source: netip.MustParseAddrPort("192.0.2.1:45000"), Destination: netip.MustParseAddrPort("203.0.113.2:443")}
	l.BeginFlow(id, original)
	l.RecordBytes(id, original, "captured", "", 100)
	upstream := original
	upstream.Source = netip.MustParseAddrPort("192.0.2.1:45001")
	if !l.BindUpstream(id, upstream, original) {
		t.Fatal("valid internal alias refused")
	}
	l.RecordBytes(id, upstream, "relay", "VPS-01", 50)
	first := l.Snapshot(id.PID).Flows[0]
	if first.Source != original.Source.String() || first.Destination != original.Destination.String() || first.UpstreamSource != upstream.Source.String() || first.Counters.RelayedBytes != 50 {
		t.Fatal("alias replaced canonical endpoint", first)
	}
	reused := id
	reused.CreationTime++
	l.RecordBytes(reused, upstream, "direct", "", 75)
	other := original
	other.Destination = netip.MustParseAddrPort("198.51.100.3:8443")
	l.RecordBytes(id, other, "direct", "", 25)
	out := l.Snapshot(id.PID)
	if len(out.Flows) != 3 {
		t.Fatal("PID/tuple records merged", len(out.Flows))
	}
	for _, flow := range out.Flows {
		if flow.CreationTime == reused.CreationTime && flow.Source != upstream.Source.String() {
			t.Fatal("reused PID inherited prior endpoint")
		}
		if flow.Destination == other.Destination.String() && flow.Source != original.Source.String() {
			t.Fatal("new tuple inherited endpoint")
		}
	}
	oldID := first.FlowID
	l.BeginFlow(id, original)
	l.RecordBytes(id, original, "direct", "", 10)
	for _, flow := range l.Snapshot(id.PID).Flows {
		if flow.Source == original.Source.String() && flow.Destination == original.Destination.String() && flow.FlowID == oldID {
			t.Fatal("flow generation reused")
		}
	}
}

func TestPacketAccountingOnlyCopiesHotAttachOnStateTransition(t *testing.T) {
	l := NewEvidenceLedger()
	id := ProcessIdentity{PID: 42, CreationTime: 10, Path: "app.exe"}
	tuple := testTuple()
	l.BeginFlow(id, tuple)
	l.RecordBytes(id, tuple, "captured", "", 100)
	l.RecordHotAttach(id, tuple, 2, "HOT_ATTACH_NEW_FLOW", "revision")
	before := l.Snapshot(id.PID).Flows[0]
	l.RecordBytes(id, tuple, "direct", "", 100)
	if before.HotAttach.State != "HOT_ATTACH_NEW_FLOW" {
		t.Fatal("transition mutated previous snapshot")
	}
	transition := l.Snapshot(id.PID).Flows[0]
	if transition.HotAttach.State != "HOT_ATTACH_ROUTE_USED" {
		t.Fatal("actual route usage not recorded")
	}
	cursor := l.ChangeMarker()
	allocs := testing.AllocsPerRun(100, func() { l.RecordBytes(id, tuple, "captured", "", 1200); l.RecordBytes(id, tuple, "direct", "", 1200) })
	if allocs != 0 {
		t.Fatalf("steady packet accounting allocates %.1f objects", allocs)
	}
	after := l.Snapshot(id.PID).Flows[0]
	if after.Counters.DirectBytes != 100+101*1200 || after.Counters.CapturedBytes != 100+101*1200 {
		t.Fatal("packet counters lost", after.Counters)
	}
	changes, err := l.ChangePage(ChangeQuery{Cursor: cursor})
	if err != nil || len(changes.Flows) != 1 || changes.Cursor.AfterUpdate <= cursor.AfterUpdate {
		t.Fatal("long-lived flow updates suppressed", changes, err)
	}
}
