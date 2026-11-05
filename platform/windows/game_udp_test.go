package windowsplatform

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/buzzmean/neexitlag/core/flowpolicy"
	"github.com/buzzmean/neexitlag/core/gameudp"
	"github.com/buzzmean/neexitlag/core/routing"
)

func gamePacket() ([]byte, Tuple) {
	p := make([]byte, 32)
	p[0] = 0x45
	p[8] = 64
	p[9] = 17
	binary.BigEndian.PutUint16(p[2:4], 32)
	copy(p[12:16], []byte{192, 0, 2, 1})
	copy(p[16:20], []byte{18, 157, 46, 1})
	binary.BigEndian.PutUint16(p[20:22], 50000)
	binary.BigEndian.PutUint16(p[22:24], 7766)
	binary.BigEndian.PutUint16(p[24:26], 12)
	copy(p[28:], []byte{1, 2, 3, 4})
	t, _, _ := ParseUDP(p)
	return p, t
}
func TestGamePacketChecksumsAndOriginalUnchanged(t *testing.T) {
	p, tuple := gamePacket()
	before := append([]byte(nil), p...)
	data, _ := gameudp.Generate(gameudp.Variants()[0], nil)
	q, err := GameUDPPacket(p, data)
	if err != nil {
		t.Fatal(err)
	}
	qt, qp, err := ParseUDP(q)
	if err != nil || qt != tuple || !bytes.Equal(qp, data) || !bytes.Equal(p, before) {
		t.Fatal("packet mutation", err)
	}
	sum := func(p []byte) uint32 {
		s := uint32(0)
		for i := 0; i < len(p); i += 2 {
			if i+1 < len(p) {
				s += uint32(binary.BigEndian.Uint16(p[i : i+2]))
			} else {
				s += uint32(p[i]) << 8
			}
		}
		return s
	}
	fold := func(s uint32) uint16 {
		for s>>16 != 0 {
			s = (s & 65535) + (s >> 16)
		}
		return uint16(s)
	}
	if fold(sum(q[:20])) != 65535 || fold(sum(q[12:20])+17+uint32(len(q)-20)+sum(q[20:])) != 65535 {
		t.Fatal("checksum")
	}
	p[6] = 0x20
	if _, err := GameUDPPacket(p, data); err == nil {
		t.Fatal("fragment accepted")
	}
}
func TestGameSenderOrderCutoffAndFailedDecoyPreservesOriginal(t *testing.T) {
	for _, fail := range []bool{false, true} {
		p, tuple := gamePacket()
		id := ProcessIdentity{PID: 17, CreationTime: 20, Path: `C:\Games\game.exe`}
		e := gameudp.New()
		e.Configure(id.Path, true)
		e.SetReason("")
		at := time.Unix(1000, 0)
		f, err := e.Open(gameudp.Key{Network: strings.Repeat("a", 64), Application: id.Path, PID: id.PID, Birth: id.CreationTime, Source: tuple.Source, Destination: tuple.Destination}, at)
		if err != nil {
			t.Fatal(err)
		}
		ledger := NewEvidenceLedger()
		ledger.BeginFlow(id, tuple)
		fakes, originals := 0, 0
		send := func(q []byte) error {
			if bytes.Equal(q, p) {
				originals++
				return nil
			}
			if originals >= 2 {
				t.Fatal("after cutoff")
			}
			if fail {
				return errors.New("fixture send")
			}
			fakes++
			return nil
		}
		for i := 0; i < 5; i++ {
			if err := SendGameUDP(e, f, id, tuple, p, send, ledger, at); err != nil {
				t.Fatal(err)
			}
		}
		if originals != 5 || (!fail && fakes != 24) || (fail && fakes != 0) {
			t.Fatal(fakes, originals)
		}
		s := ledger.Snapshot(17)
		if len(s.Flows) != 1 {
			t.Fatal(s)
		}
		flow := s.Flows[0]
		if flow.Counters.Relayed != 0 || flow.Counters.GameFakePackets != uint64(fakes) {
			t.Fatal(flow)
		}
		if !fail && flow.Route != "DIRECT_PLUS" {
			t.Fatal("ACK/pass-through overwrote real transform", flow.Route)
		}
	}
}
func TestGameBindingDoesNotRelayUntilDirectAndAllLocalTrialsFailed(t *testing.T) {
	e := gameudp.NewLadder(nil)
	id := ProcessIdentity{PID: 17, CreationTime: 20, Path: `C:\Games\game.exe`}
	e.Configure(id.Path, true)
	e.SetReason("")
	_, tuple := gamePacket()
	at := time.Unix(1000, 0)
	base := Decision{GameUDP: e, GameRelayID: "VPS-01", Network: strings.Repeat("a", 64), Flow: routing.Flow{PID: id.PID, Protocol: "udp", ProcessPath: id.Path, Source: tuple.Source, Destination: tuple.Destination, PinnedPolicy: &routing.Policy{}}}
	for trial := 0; trial < 8; trial++ {
		tuple.Source = netip.AddrPortFrom(tuple.Source.Addr(), uint16(50000+trial))
		d, f, err := BindGameUDP(base, id, tuple, at)
		if err != nil {
			t.Fatal(err)
		}
		if trial < 7 && !d.Route.Direct() {
			t.Fatal("premature relay", trial)
		}
		if trial == 7 {
			if d.Route.RelayID != "VPS-01" || !d.BlockOnFailure || d.Flow.PinnedPolicy == nil || !d.Flow.PinnedPolicy.BlockOnFailure {
				t.Fatal("relay not pinned fail closed", d)
			}
		}
		for n := 0; n < e.Evidence(f).Variant.Cutoff; n++ {
			p, k := e.Plan(f, at)
			for j := 0; j < k; j++ {
				e.FakeSent(f, len(p)+28, nil)
			}
		}
		for sec := 0; sec <= 7; sec++ {
			now := at.Add(time.Duration(sec) * time.Second)
			e.Outgoing(f, 20, now)
			e.Tick(now)
		}
		at = at.Add(8 * time.Second)
	}
}
func TestReflectGuardInitialFenceForeignAndClose(t *testing.T) {
	g := &gameGuardState{}
	foreign := reflectRecord{key: reflectKey{1, 22, 0}, filter: []byte("fixture filter object")}
	g.event(foreign, 8, 7)
	if g.snapshot().Ready {
		t.Fatal("initial enumeration not fenced")
	}
	g.event(reflectRecord{key: reflectKey{2, 7, 0}, flags: 5, priority: gameReplyPriority}, 8, 7)
	if !g.snapshot().Ready || g.snapshot().ForeignHandles != 1 {
		t.Fatal(g.snapshot())
	}
	g.mu.Lock()
	g.foreign[foreign.key].matched = true
	g.mu.Unlock()
	if !g.snapshot().Conflict {
		t.Fatal("overlap hidden")
	}
	g.event(foreign, 9, 7)
	if g.snapshot().Conflict || g.snapshot().ForeignHandles != 0 {
		t.Fatal(g.snapshot())
	}
	g.event(reflectRecord{key: reflectKey{3, 23, 0}, flags: 1}, 8, 7)
	if g.snapshot().ForeignHandles != 0 {
		t.Fatal("read-only sniffer blocks game")
	}
}
func TestReflectNativeAddressLayoutAndBounds(t *testing.T) {
	var a [80]byte
	a[8] = 4
	a[9] = 8
	binary.LittleEndian.PutUint64(a[16:24], 123)
	binary.LittleEndian.PutUint32(a[24:28], 44)
	binary.LittleEndian.PutUint32(a[28:32], 0)
	binary.LittleEndian.PutUint64(a[32:40], 5)
	priority := int16(gameReplyPriority)
	binary.LittleEndian.PutUint16(a[40:42], uint16(priority))
	r, event, err := decodeGameReflect(a, []byte("object"))
	if err != nil || event != 8 || r.key.PID != 44 || r.key.Opened != 123 || r.priority != gameReplyPriority || r.flags != 5 {
		t.Fatal(r, event, err)
	}
	if _, _, err := decodeGameReflect(a, make([]byte, 16385)); err == nil {
		t.Fatal("unbounded reflect object")
	}
	a[8] = 3
	if _, _, err := decodeGameReflect(a, nil); err == nil {
		t.Fatal("wrong layer")
	}
}
func TestGameNativeFirstFlightProofIsOncePerFlowNotPerPacketCache(t *testing.T) {
	a := NewAssociations(4)
	_, tuple := gamePacket()
	id := ProcessIdentity{PID: 17, CreationTime: 20, Path: `C:\Games\game.exe`}
	a.Put(Association{Identity: id, Tuple: tuple})
	if a.MarkGameFirstFlight(tuple, id) {
		t.Fatal("unproven existing socket")
	}
	a.Put(Association{Identity: id, Tuple: tuple, Endpoint: 1})
	if !a.MarkGameFirstFlight(tuple, id) || a.MarkGameFirstFlight(tuple, id) {
		t.Fatal("cutoff restarted")
	}
	a.Put(Association{Identity: id, Tuple: tuple})
	if a.MarkGameFirstFlight(tuple, id) {
		t.Fatal("owner fallback restarted cutoff")
	}
	a.Delete(tuple, 1)
	a.Put(Association{Identity: id, Tuple: tuple, Endpoint: 2})
	if !a.MarkGameFirstFlight(tuple, id) {
		t.Fatal("genuine new flow not eligible")
	}
}
func TestGameEvidenceDoesNotRegressAcrossConcurrentPublishers(t *testing.T) {
	ledger := NewEvidenceLedger()
	_, tuple := gamePacket()
	id := ProcessIdentity{PID: 17, CreationTime: 20, Path: `C:\Games\game.exe`}
	ledger.BeginFlow(id, tuple)
	ledger.RecordBytes(id, tuple, "captured", "", 32)
	ledger.RecordGameUDP(id, tuple, gameudp.Evidence{ID: 1, Sequence: 2, Replies: 1})
	ledger.RecordGameUDP(id, tuple, gameudp.Evidence{ID: 1, Sequence: 1, Replies: 0})
	s := ledger.Snapshot(id.PID)
	if len(s.Flows) != 1 || s.Flows[0].GameUDP.Replies != 1 {
		t.Fatal("stale snapshot overwrote reply")
	}
	s.Flows[0].GameUDP.Replies = 10
	if ledger.Snapshot(id.PID).Flows[0].GameUDP.Replies != 1 {
		t.Fatal("external reader mutated ledger")
	}
}

func TestGameGuardPollingAndCaptureRestartDoNotReplaceMutex(t *testing.T) {
	g := &gameGuardState{}
	var wg sync.WaitGroup
	for i := 0; i < 3; i++ {
		wg.Add(1)
		go func(mode int) {
			defer wg.Done()
			for n := 0; n < 100; n++ {
				switch mode {
				case 0:
					g.reset()
				case 1:
					g.snapshot()
				case 2:
					g.event(reflectRecord{key: reflectKey{2, 7, 0}, flags: 5, priority: gameReplyPriority}, 8, 7)
				}
			}
		}(i)
	}
	wg.Wait()
}

func TestPUBGColdFirstDatagramBoundToLocalAndPrimedBeforeOriginal(t *testing.T) {
	e := gameudp.NewLadder(nil)
	id := ProcessIdentity{PID: 17, CreationTime: 20, Path: `C:\Steam\PUBG\TslGame.exe`}
	e.SetStartLocal(true)
	e.Configure(id.Path, true)
	e.SetReason("")
	p, tuple := gamePacket()
	at := time.Unix(1000, 0)
	base := Decision{GameUDP: e, GameRelayID: "VPS-01", Network: strings.Repeat("a", 64), Flow: routing.Flow{PID: id.PID, ProcessPath: id.Path, Protocol: "udp", Source: tuple.Source, Destination: tuple.Destination, PinnedPolicy: &routing.Policy{}}}
	d, f, err := BindGameUDP(base, id, tuple, at)
	if err != nil || !d.Route.Direct() || d.Policy.Action != flowpolicy.DirectPlus || e.Evidence(f).Stage != gameudp.Local {
		t.Fatal("cold DIRECT or relay delay", d, err)
	}
	ledger := NewEvidenceLedger()
	ledger.BeginFlow(id, tuple)
	fakes, originals := 0, 0
	send := func(q []byte) error {
		if bytes.Equal(q, p) {
			originals++
			if originals <= 2 && fakes != originals*12 {
				t.Error("original sent before decoys")
			}
		} else {
			fakes++
		}
		return nil
	}
	for i := 0; i < 5; i++ {
		if err := SendGameUDP(e, f, id, tuple, p, send, ledger, at); err != nil {
			t.Fatal(err)
		}
	}
	if fakes != 24 || originals != 5 {
		t.Fatal(fakes, originals)
	}
	s := ledger.Snapshot(id.PID)
	if len(s.Flows) != 1 || s.Flows[0].Counters.Relayed != 0 || s.Flows[0].Counters.GameFakePackets != 24 {
		t.Fatal("wrong evidence", s)
	}
}

func TestGameLocalOnlyBindingNeverAdmitsRelayIncludingExhaustion(t *testing.T) {
	e := gameudp.NewLadder(nil)
	e.SetLocalOnly(true)
	id := ProcessIdentity{PID: 17, CreationTime: 20, Path: `C:\Games\cs2.exe`}
	e.Configure(id.Path, true)
	e.SetReason("")
	_, tuple := gamePacket()
	at := time.Unix(1000, 0)
	base := Decision{GameUDP: e, GameRelayID: "VPS-01", Network: strings.Repeat("a", 64), Flow: routing.Flow{PID: id.PID, Protocol: "udp", ProcessPath: id.Path, Source: tuple.Source, Destination: tuple.Destination, PinnedPolicy: &routing.Policy{}}}
	for trial := 0; trial < 9; trial++ {
		tuple.Source = netip.AddrPortFrom(tuple.Source.Addr(), uint16(50000+trial))
		d, f, err := BindGameUDP(base, id, tuple, at)
		if !d.Route.Direct() || d.BlockOnFailure || d.Policy.RelayID != "" || !d.Flow.PinnedPolicy.Route.Direct() {
			t.Fatal("relay admission possible", d)
		}
		if trial >= 7 {
			if err == nil || f != nil || d.GameUDP != nil {
				t.Fatal("exhaustion missing", err)
			}
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		for n := 0; n < e.Evidence(f).Variant.Cutoff; n++ {
			p, k := e.Plan(f, at)
			for j := 0; j < k; j++ {
				e.FakeSent(f, len(p)+28, nil)
			}
		}
		for sec := 0; sec <= 7; sec++ {
			now := at.Add(time.Duration(sec) * time.Second)
			e.Outgoing(f, 20, now)
			e.Tick(now)
		}
		at = at.Add(8 * time.Second)
	}
}
