//go:build windows

package windowsplatform

import (
	"strings"
	"testing"
	"time"

	"github.com/buzzmean/neexitlag/core/gameudp"
	"github.com/buzzmean/neexitlag/core/routing"
)

func TestNativeUDPReplyIncludesDirectPlusWithoutGameEngine(t *testing.T) {
	for _, route := range []routing.Route{{}, {Kind: routing.DirectPlusRoute}} {
		b, _ := captureFixture(t)
		p, tuple := gamePacket()
		id := ProcessIdentity{PID: 17, CreationTime: 20, Path: `C:\Games\cs2.exe`}
		f := &captureFlow{identity: id, decision: Decision{Route: route}, lastSeen: time.Unix(1, 0)}
		b.flows[tuple] = f
		b.evidence.RecordBytes(id, tuple, "captured", "", uint64(len(p)))
		reply, err := ReplyUDP(p, []byte{9, 8, 7})
		if err != nil {
			t.Fatal(err)
		}
		now := time.Now()
		for i := 0; i < 3; i++ {
			b.recordNativeUDPReply(reply, now)
		}
		v := b.evidence.Snapshot(id.PID).Flows[0]
		if v.Counters.DirectReplyPackets != 3 || v.Counters.DirectReplyBytes != uint64(3*len(reply)) || v.Counters.ReplyBytes != 0 || v.Counters.RelayedBytes != 0 || !f.lastSeen.Equal(now) {
			t.Fatal(v.Counters, f.lastSeen)
		}
	}
}

func TestNativeUDPReplyRejectsRetiredRelayAdaptiveBlockedAndUnknown(t *testing.T) {
	for _, change := range []func(*captureFlow){
		func(f *captureFlow) { f.retired = true },
		func(f *captureFlow) { f.decision.Route.RelayID = "VPS-01" },
		func(f *captureFlow) { f.decision.ProbeDirect = true },
		func(f *captureFlow) { f.decision.Block = true },
		func(f *captureFlow) { f.identity.PID = 0 },
		func(f *captureFlow) { f.identity.CreationTime = 0 },
		func(f *captureFlow) { f.identity.Path = "" },
		func(f *captureFlow) { f.datagram = &captureTestUDP{} },
	} {
		b, _ := captureFixture(t)
		p, tuple := gamePacket()
		id := ProcessIdentity{PID: 17, CreationTime: 20, Path: `C:\Games\cs2.exe`}
		f := &captureFlow{identity: id}
		change(f)
		b.flows[tuple] = f
		b.evidence.RecordBytes(id, tuple, "captured", "", uint64(len(p)))
		reply, _ := ReplyUDP(p, []byte{9, 8, 7})
		b.recordNativeUDPReply(reply, time.Now())
		if b.evidence.Snapshot(id.PID).Flows[0].Counters.DirectReplyPackets != 0 {
			t.Fatal("incorrect attribution")
		}
	}
}

func TestNativeUDPReplyPreservesGameEvidence(t *testing.T) {
	b, _ := captureFixture(t)
	p, tuple := gamePacket()
	id := ProcessIdentity{PID: 17, CreationTime: 20, Path: `C:\Games\cs2.exe`}
	e := gameudp.New()
	e.Configure(id.Path, true)
	e.SetReason("")
	now := time.Now()
	game, err := e.Open(gameudp.Key{Network: strings.Repeat("a", 64), Application: id.Path, PID: id.PID, Birth: id.CreationTime, Source: tuple.Source, Destination: tuple.Destination}, now)
	if err != nil {
		t.Fatal(err)
	}
	b.flows[tuple] = &captureFlow{identity: id, game: game, decision: Decision{GameUDP: e}}
	b.evidence.RecordBytes(id, tuple, "captured", "", uint64(len(p)))
	reply, _ := ReplyUDP(p, []byte{9, 8, 7})
	b.recordNativeUDPReply(reply, now)
	v := b.evidence.Snapshot(id.PID).Flows[0]
	if v.Counters.DirectReplyPackets != 1 || v.GameUDP == nil || v.GameUDP.Replies != 1 || v.GameUDP.ReplyBytes != 3 || !v.GameUDP.LastReply.Equal(now) {
		t.Fatal(v)
	}
	delete(b.flows, tuple)
	b.recordNativeUDPReply(reply, now.Add(time.Second))
	b.recordNativeUDPReply([]byte{1, 2, 3}, now)
	if b.evidence.Snapshot(id.PID).Flows[0].Counters.DirectReplyPackets != 1 {
		t.Fatal("unknown reply counted")
	}
}
