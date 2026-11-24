package windowsplatform

import (
	"encoding/binary"
	"net/netip"
	"testing"

	"github.com/buzzmean/veliq/core/flowpolicy"
	"github.com/buzzmean/veliq/core/routing"
)

func TestHotAttachResetUsesExactSequenceAndNoPayload(t *testing.T) {
	p := localTCPPacket(24, []byte("private payload"))
	binary.BigEndian.PutUint32(p[24:], 100)
	binary.BigEndian.PutUint32(p[28:], 500)
	for _, outbound := range []bool{true, false} {
		reset, err := hotTCPReset(p, outbound)
		if err != nil {
			t.Fatal(err)
		}
		tuple, flags, payload, err := ParseTCP(reset)
		original, _, _, _ := ParseTCP(p)
		if err != nil || flags != 4 || payload != 0 || len(reset) != 40 {
			t.Fatal(err, flags, payload)
		}
		want := uint32(100)
		if outbound {
			want = 500
			if tuple.Source != original.Destination || tuple.Destination != original.Source {
				t.Fatal("foreign tuple")
			}
		}
		if binary.BigEndian.Uint32(reset[24:]) != want {
			t.Fatal("wrong reset sequence")
		}
	}
	p[33] = 4
	if _, err := hotTCPReset(p, true); err == nil {
		t.Fatal("RST loop")
	}
}
func TestHotAttachRequiredAndDirectPlusOnly(t *testing.T) {
	for _, d := range []Decision{{Route: routing.Route{RelayID: "VPS-01"}}, {Route: routing.Route{Kind: routing.DirectPlusRoute}}, {Deferred: true}, {ProbeDirect: true}, {Block: true}} {
		if !needsHotAttach(d) {
			t.Fatal("selected route bypassed")
		}
	}
	if needsHotAttach(Decision{}) {
		t.Fatal("unrelated DIRECT app touched")
	}
}
func TestHotAttachNativeTCPDecodeBoundAndFullTuple(t *testing.T) {
	raw := make([]byte, 28)
	binary.LittleEndian.PutUint32(raw, 1)
	binary.LittleEndian.PutUint32(raw[4:], 5)
	copy(raw[8:12], []byte{192, 0, 2, 1})
	copy(raw[16:20], []byte{203, 0, 113, 2})
	binary.BigEndian.PutUint16(raw[12:], 1234)
	binary.BigEndian.PutUint16(raw[20:], 443)
	binary.LittleEndian.PutUint32(raw[24:], 42)
	rows, err := decodeOwnedTCP(raw)
	if err != nil || len(rows) != 1 || rows[0].PID != 42 || rows[0].Tuple.Destination != netip.MustParseAddrPort("203.0.113.2:443") {
		t.Fatal(rows, err)
	}
	binary.LittleEndian.PutUint32(raw, hotAttachLimit+1)
	if _, err = decodeOwnedTCP(raw); err == nil {
		t.Fatal("unbounded native table")
	}
}
func TestHotAttachEvidenceKeepsTransitionDistinctFromFailure(t *testing.T) {
	l := NewEvidenceLedger()
	id := ProcessIdentity{PID: 5, CreationTime: 9, Path: "app.exe"}
	tuple := Tuple{Protocol: "tcp", Destination: netip.MustParseAddrPort("203.0.113.2:443")}
	l.BeginFlow(id, tuple)
	l.RecordHotAttach(id, tuple, 1, "HOT_ATTACH_PREEXISTING", "revision")
	l.RecordDrop(id, tuple, "HOT_ATTACH_PENDING", false)
	f := l.Snapshot(5).Flows[0]
	if f.RequiredBlocked || f.FailureCause != "" || f.HotAttach == nil || f.HotAttach.State != "HOT_ATTACH_PREEXISTING" {
		t.Fatal(f)
	}
	l.BeginFlow(id, tuple)
	l.RecordHotAttach(id, tuple, 1, "HOT_ATTACH_NEW_FLOW", "revision")
	l.RecordLocal(id, tuple, "configured-disorder", "www.youtube.com", 100)
	f = l.Snapshot(5).Flows[0]
	if f.Route != "DIRECT_PLUS" || f.HotAttach.State != "HOT_ATTACH_TRANSFORM_APPLIED" {
		t.Fatal(f)
	}
}

func TestHotAttachNativeResetIsNotPacketAndSeparatesOldDirectPolicy(t *testing.T) {
	l := NewEvidenceLedger()
	id := ProcessIdentity{PID: 7, CreationTime: 8, Path: "edge.exe"}
	tuple := Tuple{Protocol: "tcp", Source: netip.MustParseAddrPort("192.0.2.1:1234"), Destination: netip.MustParseAddrPort("203.0.113.2:443")}
	l.BeginFlow(id, tuple)
	l.RecordBytes(id, tuple, "direct", "", 50)
	old := l.Snapshot(7).Flows[0].FlowID
	d := Decision{Policy: flowpolicy.Result{Action: flowpolicy.RelayRequired, Fallback: flowpolicy.Required}, Revision: "new"}
	l.RecordHotReset(id, tuple, 2, d)
	v := l.Snapshot(7).Flows[0]
	if v.FlowID == old || v.Counters.Captured != 0 || v.Counters.DirectBytes != 0 || v.Route != "HOT_ATTACH" || v.Policy.Fallback != flowpolicy.Required {
		t.Fatal(v)
	}
	if l.Snapshot(7).Counters.DirectBytes != 50 {
		t.Fatal("lifetime bytes erased")
	}
	l.RecordHotReset(id, tuple, 2, d)
	if l.Snapshot(7).Flows[0].FlowID != v.FlowID {
		t.Fatal("duplicate reset fragmented metadata")
	}
}

func TestHotAttachNeverResetsFreshCurrentConnections(t *testing.T) {
	id := ProcessIdentity{PID: 10, CreationTime: 20}
	d := Decision{Revision: "active"}
	for _, mode := range []string{"opening", "relay", "direct"} {
		e := &tcpEntry{identity: id, decision: d, mode: mode, hotEpoch: 0}
		if !freshHotTCP(e, id, d) {
			t.Fatal("fresh SYN/relay/direct+ was reset by sweep", mode)
		}
	}
	for _, mode := range []string{"closed", "hot_attach"} {
		if freshHotTCP(&tcpEntry{identity: id, decision: d, mode: mode}, id, d) {
			t.Fatal("old quarantine treated as current")
		}
	}
	old := &tcpEntry{identity: id, decision: Decision{Revision: "previous"}, mode: "direct"}
	if freshHotTCP(old, id, d) {
		t.Fatal("old DIRECT skipped activation")
	}
}

func TestHotAttachIPv6ResetIsOnlyTransportControl(t *testing.T) {
	p := make([]byte, 60)
	p[0] = 0x60
	p[6] = 6
	p[7] = 64
	binary.BigEndian.PutUint16(p[4:], 20)
	a, b := netip.MustParseAddr("2001:db8::1").As16(), netip.MustParseAddr("2001:db8::2").As16()
	copy(p[8:24], a[:])
	copy(p[24:40], b[:])
	binary.BigEndian.PutUint16(p[40:], 50000)
	binary.BigEndian.PutUint16(p[42:], 443)
	p[52] = 0x50
	p[53] = 16
	binary.BigEndian.PutUint32(p[48:], 999)
	reset, err := hotTCPReset(p, true)
	if err != nil {
		t.Fatal(err)
	}
	tuple, flags, err := ParseIPv6Transport(reset)
	if err != nil || flags != 4 || tuple.Source.Port() != 443 || tuple.Destination.Port() != 50000 || binary.BigEndian.Uint32(reset[44:]) != 999 {
		t.Fatal(tuple, flags, err)
	}
	p[53] = 2
	binary.BigEndian.PutUint32(p[44:], 123)
	reset, err = hotTCPReset(p, true)
	if err != nil || reset[53] != 20 || binary.BigEndian.Uint32(reset[48:]) != 124 {
		t.Fatal("SYN_SENT reset invalid", err)
	}
}
