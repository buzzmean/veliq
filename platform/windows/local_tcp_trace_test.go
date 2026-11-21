package windowsplatform

import (
	"encoding/binary"
	"encoding/json"
	"net/netip"
	"strings"
	"testing"
)

func TestLocalTCPTraceSeparatesRemoteResetAndClientCloseWithoutPayload(t *testing.T) {
	l := NewEvidenceLedger()
	id := ProcessIdentity{PID: 42, CreationTime: 1, Path: "chrome.exe"}
	tuple := Tuple{Protocol: "tcp", Source: netip.MustParseAddrPort("192.0.2.1:6000"), Destination: netip.MustParseAddrPort("198.51.100.1:443")}
	l.BeginFlow(id, tuple)
	p := localTCPPacket(0x12, nil)
	p[8] = 52
	l.RecordLocalTCPPacket(id, tuple, p, true)
	p = localTCPPacket(0x14, nil)
	p[8] = 117
	l.RecordLocalTCPPacket(id, tuple, p, true)
	p = localTCPPacket(0x11, nil)
	p[8] = 128
	l.RecordLocalTCPPacket(id, tuple, p, false)
	k := evidenceKey{id.PID, id.CreationTime, tuple}
	v := l.flows[k]
	trace := v.LocalTCP
	if trace == nil || trace.RemoteRST != 1 || trace.ClientFIN != 1 || trace.FirstClose != "REMOTE_PACKET" || trace.SYNACKTTL != 52 || trace.RemoteTerminalTTL != 117 || trace.FirstCloseTTL != 117 {
		t.Fatal(trace)
	}
	snapshot := cloneFlow(v)
	snapshot.LocalTCP.FirstClose = "mutated"
	if l.flows[k].LocalTCP.FirstClose != "REMOTE_PACKET" {
		t.Fatal("snapshot alias")
	}
	raw, _ := json.Marshal(trace)
	if strings.Contains(string(raw), "Next") || strings.Contains(string(raw), "SequenceSeen") {
		t.Fatal("sequence state exported")
	}
}

func TestEarlyFailureEvidenceNeedsSYNRelativeSequence(t *testing.T) {
	l := NewEvidenceLedger()
	id := ProcessIdentity{PID: 12, CreationTime: 1, Path: "chrome.exe"}
	tu := Tuple{Protocol: "tcp", Source: netip.MustParseAddrPort("192.0.2.1:6000"), Destination: netip.MustParseAddrPort("198.51.100.1:443")}
	l.BeginFlow(id, tu)
	p := localTCPPacket(0x14, nil)
	l.RecordLocalTCPPacket(id, tu, p, true)
	k := evidenceKey{id.PID, id.CreationTime, tu}
	if l.flows[k].LocalTCP.RemoteRSTRelativeKnown {
		t.Fatal("hot attach inferred seq")
	}
	syn := localTCPPacket(0x12, nil)
	l.RecordLocalTCPPacket(id, tu, syn, true)
	rst := localTCPPacket(0x14, nil)
	binary.BigEndian.PutUint32(rst[24:], binary.BigEndian.Uint32(syn[24:])+2)
	l.RecordLocalTCPPacket(id, tu, rst, true)
	tr := l.flows[k].LocalTCP
	if !tr.RemoteRSTRelativeKnown || tr.RemoteRSTRelative != 1 {
		t.Fatal(tr)
	}
}
