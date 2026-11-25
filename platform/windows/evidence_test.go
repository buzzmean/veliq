package windowsplatform

import (
	"encoding/binary"
	"errors"
	"github.com/buzzmean/veliq/core/routing"
	"net/netip"
	"testing"
	"time"
)

type discoveryFixture struct{ identity ProcessIdentity }

func (d *discoveryFixture) Lookup(uint32) (ProcessIdentity, error) {
	if d.identity.PID == 0 {
		return ProcessIdentity{}, errors.New("exited")
	}
	return d.identity, nil
}
func (d *discoveryFixture) List() ([]ProcessIdentity, error) {
	return []ProcessIdentity{d.identity}, nil
}
func TestCachePIDReuseAndCleanup(t *testing.T) {
	d := &discoveryFixture{ProcessIdentity{PID: 10, Path: `C:\A.exe`, CreationTime: 1}}
	c := NewProcessCache(d, func(i ProcessIdentity) bool { return i.CreationTime == d.identity.CreationTime })
	a, e := c.Lookup(10)
	if e != nil || a.CreationTime != 1 {
		t.Fatal(a, e)
	}
	d.identity = ProcessIdentity{PID: 10, Path: `C:\B.exe`, CreationTime: 2}
	b, e := c.Lookup(10)
	if e != nil || b.Path != d.identity.Path || b.CreationTime != 2 {
		t.Fatal("PID reuse", b, e)
	}
	c.Cleanup(time.Now().Add(3 * time.Minute))
	if len(c.entries) != 0 {
		t.Fatal("idle cache not cleaned")
	}
	d.identity = ProcessIdentity{}
	if _, e = c.Lookup(10); e == nil {
		t.Fatal("exited process reused")
	}
}
func TestUDPOwnerAmbiguityAndWildcard(t *testing.T) {
	row := func(ip [4]byte, pid uint32) []byte {
		b := make([]byte, 12)
		copy(b, ip[:])
		binary.BigEndian.PutUint16(b[4:6], 55000)
		binary.LittleEndian.PutUint32(b[8:], pid)
		return b
	}
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, 1)
	b = append(b, row([4]byte{}, 42)...)
	source := netip.MustParseAddrPort("192.0.2.9:55000")
	if pid, e := udpOwner(b, source); e != nil || pid != 42 {
		t.Fatal(pid, e)
	}
	binary.LittleEndian.PutUint32(b, 2)
	b = append(b, row([4]byte{192, 0, 2, 9}, 43)...)
	if _, e := udpOwner(b, source); e == nil {
		t.Fatal("ambiguous owner routed")
	}
	if _, e := udpOwner(b[:7], source); e == nil {
		t.Fatal("truncated owner table")
	}
}
func TestServiceExclusionAndEvidence(t *testing.T) {
	id := ProcessIdentity{PID: 20, Path: `C:\service.exe`, CreationTime: 99}
	tuple := Tuple{Protocol: "udp", Source: netip.MustParseAddrPort("192.0.2.1:55000"), Destination: netip.MustParseAddrPort("198.51.100.2:4433")}
	called := false
	d, bypass := ClassifyCapture(id, tuple, 20, func(ProcessIdentity, Tuple) Decision {
		called = true
		return Decision{Route: routing.Route{RelayID: "bad"}}
	})
	if called || !bypass || !d.Route.Direct() {
		t.Fatal("service entered relay classification")
	}
	l := NewEvidenceLedger()
	l.Record(id, tuple, "captured", "")
	l.Record(id, tuple, "self", "")
	l.Record(id, tuple, "direct", "")
	l.Record(ProcessIdentity{}, Tuple{}, "reinject", "")
	s := l.Snapshot(20)
	if s.Counters.Captured != 1 || s.Counters.LoopPrevented != 1 || s.Counters.Reinject != 1 || len(s.Flows) != 1 || s.Flows[0].Route != "DIRECT" {
		t.Fatal(s)
	}
	id.CreationTime = 100
	l.Record(id, tuple, "relay", "FRA-01")
	if len(l.Snapshot(20).Flows) != 2 {
		t.Fatal("PID reuse evidence merged")
	}
	l.Cleanup(time.Now().Add(6 * time.Minute))
	if len(l.Snapshot(0).Flows) != 0 || l.Snapshot(0).Counters.Relayed != 1 {
		t.Fatal("evidence cleanup changed totals")
	}
}
func TestIPv4OwnershipThroughDualStackAndCrossFamilyAmbiguity(t *testing.T) {
	source := netip.MustParseAddrPort("192.0.2.9:55000")
	b := make([]byte, 32)
	binary.LittleEndian.PutUint32(b, 1)
	binary.BigEndian.PutUint16(b[24:26], source.Port())
	binary.LittleEndian.PutUint32(b[28:32], 42)
	owners, e := udpOwners(b, source, true)
	if e != nil {
		t.Fatal(e)
	}
	if pid, e := uniqueUDPOwner(owners); e != nil || pid != 42 {
		t.Fatal("dual-stack wildcard owner", pid, e)
	}
	owners[43] = true
	if _, e = uniqueUDPOwner(owners); e == nil {
		t.Fatal("cross-family port ambiguity accepted")
	}
	ip := netip.MustParseAddr("::ffff:192.0.2.9").As16()
	copy(b[4:20], ip[:])
	owners, e = udpOwners(b, source, true)
	if e != nil || !owners[42] {
		t.Fatal("mapped IPv4 owner", owners, e)
	}
}

func TestTargetDiagnosticsAndLiveRelayPrioritization(t *testing.T) {
	l := NewEvidenceLedger()
	id := ProcessIdentity{PID: 42, CreationTime: 10, Path: "chrome.exe"}
	target := testTuple()
	l.RecordBytes(id, target, "relay", "VPS-01", 100)
	l.RecordDomain(id, target, "www.youtube.com")
	for i := 0; i < 50; i++ {
		other := target
		other.Source = netip.AddrPortFrom(other.Source.Addr(), uint16(3000+i))
		other.Destination = netip.MustParseAddrPort("198.51.100.2:443")
		l.RecordBytes(id, other, "direct", "", 60)
	}
	if !l.Snapshot(42).Truncated {
		t.Fatal("fixture did not truncate")
	}
	scoped := l.snapshotTarget(42, target.Destination.String(), nil)
	if scoped.Truncated || len(scoped.Flows) != 1 || scoped.Flows[0].Domain != "www.youtube.com" || scoped.Flows[0].Route != "RELAY" {
		t.Fatal(scoped)
	}
	live := l.snapshot(42, map[evidenceKey]bool{{id.PID, id.CreationTime, target}: true})
	if !live.Truncated || !live.Flows[0].Active || live.Flows[0].Route != "RELAY" {
		t.Fatal("live relay disappeared behind newer idle flows", live)
	}
}

func TestTrialMarkersFilterBeforeSnapshotBounds(t *testing.T) {
	l := NewEvidenceLedger()
	id := ProcessIdentity{PID: 42, CreationTime: 10, Path: "chrome.exe"}
	target := testTuple()
	for i := 0; i < 70; i++ {
		old := target
		old.Source = netip.AddrPortFrom(old.Source.Addr(), uint16(3000+i))
		l.RecordBytes(id, old, "relay", "VPS-01", 100)
	}
	// A born flow cannot become current merely because its first record is late.
	delayed := target
	delayed.Source = netip.AddrPortFrom(target.Source.Addr(), 6000)
	l.BeginFlow(id, delayed)
	marker := l.Marker()
	l.RecordBytes(id, delayed, "direct", "", 60)
	current := target
	current.Source = netip.AddrPortFrom(target.Source.Addr(), 7000)
	l.BeginFlow(id, current)
	l.RecordBytes(id, current, "relay", "VPS-01", 10655)
	l.RecordDomain(id, current, "www.youtube.com")
	reusedPID := id
	reusedPID.CreationTime++
	for i := 0; i < 40; i++ {
		other := target
		other.Source = netip.AddrPortFrom(other.Source.Addr(), uint16(8000+i))
		l.RecordBytes(reusedPID, other, "direct", "", 60)
	}
	q := EvidenceQuery{PID: id.PID, CreationTime: id.CreationTime, Destination: target.Destination.String(), Since: &marker}
	out, err := l.SnapshotQuery(q, nil)
	if err != nil || out.Truncated || len(out.Flows) != 1 || out.Flows[0].Counters.RelayedBytes != 10655 || out.Flows[0].FlowID <= marker.AfterFlowID || out.Flows[0].StartedAt.IsZero() || out.Flows[0].Source != current.Source.String() {
		t.Fatal(out, err)
	}
	q.Domain = "www.youtube.com"
	out, err = l.SnapshotQuery(q, nil)
	if err != nil || len(out.Flows) != 1 {
		t.Fatal(out, err)
	}
	q.Source = "192.0.2.99:1"
	out, err = l.SnapshotQuery(q, nil)
	if err != nil || len(out.Flows) != 0 {
		t.Fatal("source filter", out, err)
	}
	q.Source = ""
	q.Domain = "other.example"
	out, err = l.SnapshotQuery(q, nil)
	if err != nil || len(out.Flows) != 0 {
		t.Fatal("domain filter", out, err)
	}
	// Reuse of the SAME endpoint retires the previous birth/strategy evidence.
	l.BeginFlow(id, current)
	l.RecordBytes(id, current, "direct", "", 60)
	next := l.Marker()
	if next.AfterFlowID <= out.Marker.AfterFlowID {
		t.Fatal("flow ID reused")
	}
}
func TestTrialMarkerRejectsRestartFutureAndEvidenceLoss(t *testing.T) {
	l := NewEvidenceLedger()
	m := l.Marker()
	q := EvidenceQuery{Since: &m}
	if _, err := NewEvidenceLedger().SnapshotQuery(q, nil); err == nil {
		t.Fatal("restart accepted old marker")
	}
	future := m
	future.AfterFlowID++
	if _, err := l.SnapshotQuery(EvidenceQuery{Since: &future}, nil); err == nil {
		t.Fatal("future marker accepted")
	}
	id := ProcessIdentity{PID: 42, CreationTime: 10, Path: "chrome.exe"}
	tuple := testTuple()
	for i := 0; i < 1025; i++ {
		tuple.Source = netip.AddrPortFrom(tuple.Source.Addr(), uint16(10000+i))
		l.Record(id, tuple, "direct", "")
	}
	out, err := l.SnapshotQuery(q, nil)
	if err != nil || !out.Truncated || !out.EvidenceLost {
		t.Fatal("silent evidence overflow", out, err)
	}
}

func TestAdaptiveHealthEvidenceDoesNotInventPacketSuccess(t *testing.T) {
	l := NewEvidenceLedger()
	id := ProcessIdentity{PID: 41, Path: "media.exe", CreationTime: 9}
	tuple := testTuple()
	l.RecordBytes(id, tuple, "captured", "", 100)
	l.RecordBytes(id, tuple, "direct_reply", "", 20)
	l.RecordUDPHealth(id, tuple, routing.UDPHealthEvidence{State: routing.DirectProbation, ProbationReplies: 1, ProbationReplyBytes: 20})
	first := l.Snapshot(id.PID)
	l.RecordUDPHealth(id, tuple, routing.UDPHealthEvidence{State: routing.FlowRelayFallback, Reason: routing.DirectInsufficientReplies, ProbationReplies: 1, ProbationReplyBytes: 20, ProbationDurationMS: 3000})
	after := l.Snapshot(id.PID)
	if first.Flows[0].UDPHealth.State != routing.DirectProbation || after.Flows[0].UDPHealth.State != routing.FlowRelayFallback || after.Flows[0].FallbackReason != routing.DirectInsufficientReplies {
		t.Fatal(first, after)
	}
	if first.Counters != after.Counters || after.Counters.Relayed != 0 || after.Counters.Replies != 0 {
		t.Fatal("state manufactured traffic", after)
	}
}
