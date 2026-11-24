//go:build windows

package windowsplatform

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
	"unsafe"

	"github.com/buzzmean/veliq/core/gameudp"
	"github.com/buzzmean/veliq/core/routing"
)

func cs2FlowEvent(id ProcessIdentity, t Tuple, endpoint uint64, ipv6 bool) [80]byte {
	var event [80]byte
	event[8], event[9] = 2, 1 // FLOW_ESTABLISHED
	if ipv6 {
		event[10] |= 16
	}
	d := event[16:]
	binary.LittleEndian.PutUint64(d, endpoint)
	binary.LittleEndian.PutUint32(d[16:], id.PID)
	for offset, ip := range map[int]netip.Addr{20: t.Source.Addr(), 36: t.Destination.Addr()} {
		raw := ip.As4()
		binary.LittleEndian.PutUint32(d[offset:], binary.BigEndian.Uint32(raw[:]))
		binary.LittleEndian.PutUint32(d[offset+4:], 0xffff)
	}
	binary.LittleEndian.PutUint16(d[52:], t.Source.Port())
	binary.LittleEndian.PutUint16(d[54:], t.Destination.Port())
	d[56] = 17
	return event
}

func TestCS2AutoNativeFlowLayoutScope(t *testing.T) {
	_, tuple := gamePacket()
	id := ProcessIdentity{PID: 7, Path: `C:\Steam\cs2.exe`, CreationTime: 11}
	for _, ipv6 := range []bool{false, true} {
		event := cs2FlowEvent(id, tuple, 1, ipv6)
		if got := cs2IPv4FlowTuple(event[16:], ipv6); got != tuple {
			t.Fatal(got, tuple)
		}
	}
	for _, offset := range []int{20, 36} {
		event := cs2FlowEvent(id, tuple, 1, true)
		event[16+offset+15] = 0x20 // true IPv6, not a mapped peer
		if got := cs2IPv4FlowTuple(event[16:], true); got.Destination.IsValid() {
			t.Fatal(got)
		}
	}
	for _, tc := range []struct {
		name string
		auto bool
	}{
		{"another.exe", true}, {"cs2.exe", false},
	} {
		b, _ := captureFixture(t)
		owner := id
		owner.Path = filepath.Join(`C:\Steam`, tc.name)
		b.cache = NewProcessCache(&discoveryFixture{owner}, func(ProcessIdentity) bool { return true })
		b.trackFlowEvent(cs2FlowEvent(owner, tuple, 17, true), func(ProcessIdentity, Tuple) Decision { return Decision{CS2Auto: tc.auto} })
		if len(b.associations.items) != 0 {
			t.Fatal(tc, "unselected mapped flow was enrolled")
		}
	}
}

// Real Windows process identity, a fresh source port and the OS UDP socket
// path. The packet writer is a fixture; all network I/O goes to loopback.
func TestCS2AutoNativeFreshSocketUsesLocalUDP(t *testing.T) {
	exe := filepath.Join(t.TempDir(), "cs2.exe")
	raw, err := os.ReadFile(os.Args[0])
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(exe, raw, 0700); err != nil {
		t.Fatal(err)
	}
	id := nativeGameIdentityExecutable(t, exe)
	b, generic := captureFixture(t)
	b.Engine.SetExactRelay("VPS-01", "configured-address", generic)
	e := gameudp.NewLadder(nil)
	e.Configure(id.Path, true)
	e.SetCS2Auto(true)
	e.SetReason("")
	packet, tuple := gamePacket()
	// The production path uses the game endpoint for both tuples. Translate
	// the routing destination only in this fixture: every OS socket is loopback.
	peer, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	osDest := peer.LocalAddr().(*net.UDPAddr).AddrPort()
	osDest = netip.AddrPortFrom(osDest.Addr().Unmap(), osDest.Port())
	var original atomic.Int32
	replies := make(chan []byte, 4)
	b.packetWriter = func(q []byte, a [80]byte) error {
		if a[10]&2 != 0 {
			if !bytes.Equal(q, packet) {
				t.Error("AUTO modified an application packet")
			}
			original.Add(1)
		} else {
			_, data, err := ParseUDP(q)
			if err == nil {
				replies <- append([]byte(nil), data...)
			}
		}
		return nil
	}
	classify := func(owner ProcessIdentity, key Tuple) Decision {
		if owner.PID != id.PID || key != tuple {
			return Decision{}
		}
		return Decision{Revision: "cs2-auto", Network: strings.Repeat("a", 64),
			GameUDP: e, CS2Auto: true, GameRelayID: "VPS-01", GameQualityRelayID: "VPS-01", GameQualityRelayAddress: "configured-address",
			Route: routing.Route{RelayID: "VPS-01"}, ProbeDirect: true,
			Flow: routing.Flow{PID: id.PID, ProcessPath: id.Path, ApplicationID: "cs2", Protocol: "udp", Source: tuple.Source, Destination: osDest, PinnedPolicy: &routing.Policy{}},
		}
	}
	var outbound [80]byte
	outbound[10] = 2
	// No fresh FLOW proof yet. The real CS2 owner is already known, and
	// the first datagram leaves unchanged on the ordinary Windows route.
	b.associations.Put(Association{Identity: id, Tuple: tuple})
	b.processUDP(nil, packet, outbound, classify)
	one := cs2FlowEvent(id, tuple, 101, false)
	b.trackFlowEvent(one, classify)
	b.mu.Lock()
	first := b.flows[tuple]
	b.mu.Unlock()
	if first == nil || first.game == nil || first.endpoint != 101 || original.Load() != 1 {
		t.Fatal("late FLOW ownership not recorded")
	}
	ev := e.Evidence(first.game)
	if ev.Stage != gameudp.Direct || ev.Fakes != 0 {
		t.Fatal(ev)
	}
	time.Sleep(time.Until(ev.Started.Add(time.Second)))
	if err = e.RecordCS2Outcome(gameudp.CS2Outcome{FlowID: ev.ID, Started: ev.Started, PID: id.PID, Birth: id.CreationTime, Destination: tuple.Destination, Outcome: "TIMEOUT", Phase: "NO_REPLY_OBSERVED"}, time.Now()); err != nil {
		t.Fatal(err)
	}
	b.processUDP(nil, packet, outbound, classify)
	if original.Load() != 2 || e.Evidence(first.game).Stage != gameudp.Direct {
		t.Fatal("live flow changed route")
	}
	one[9] = 2
	b.trackFlowEvent(one, classify)
	nextPacket := append([]byte(nil), packet...)
	binary.BigEndian.PutUint16(nextPacket[20:], tuple.Source.Port()+1)
	secondTuple, payload, err := ParseUDP(nextPacket)
	if err != nil {
		t.Fatal(err)
	}
	tuple = secondTuple
	two := cs2FlowEvent(id, tuple, 102, true)
	b.trackFlowEvent(two, classify)
	b.trackFlowEvent(one, classify) // old socket report cannot retire the new session
	b.processUDP(nil, nextPacket, outbound, classify)
	_ = peer.SetReadDeadline(time.Now().Add(5 * time.Second))
	received := make([]byte, 65535)
	n, source, err := peer.ReadFromUDP(received)
	if err != nil || !bytes.Equal(received[:n], payload) || n != 4 {
		t.Fatal("loopback server did not receive the real UDP payload", n, err)
	}
	reply := bytes.Repeat([]byte("local echo"), 200)
	if _, err = peer.WriteToUDP(reply, source); err != nil {
		t.Fatal(err)
	}
	select {
	case real := <-replies:
		if !bytes.Equal(real, reply) {
			t.Fatal("loopback reply changed")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("missing loopback reply")
	}
	captureWait(t, func() bool {
		for _, flow := range b.evidence.Snapshot(id.PID).Flows {
			if flow.GameUDP != nil && flow.GameUDP.ID != ev.ID && flow.Counters.DirectReplyBytes > 0 {
				return flow.Route == gameudp.LocalSocket && flow.GameUDP.Stage == gameudp.LocalSocket && flow.Counters.DirectBytes == 4 && flow.Counters.DirectReplyBytes == uint64(len(reply)) && flow.Counters.RelayedBytes == 0 && flow.Counters.ReplyBytes == 0 && flow.Counters.GameFakePackets == 0 && flow.RelayOpen == nil
			}
		}
		return false
	})
	if original.Load() != 2 {
		t.Fatal("original packet also escaped on native game socket", original.Load())
	}
	_ = peer.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
	if _, _, err = peer.ReadFromUDP(received); !os.IsTimeout(err) {
		t.Fatal("unexpected duplicate or invalid fixture", err)
	}
	generic.mu.Lock()
	opened := len(generic.flows)
	generic.mu.Unlock()
	if opened != 0 {
		t.Fatal("CS2 AUTO opened a relay", opened)
	}
	two[9] = 2
	b.trackFlowEvent(two, classify)
	if _, ok := b.associations.Get(tuple, id); ok {
		t.Fatal("closed socket retained its proof")
	}
}

// The driver's actual FLOW metadata for a single ordinary loopback datagram.
// SNIFF|RECV_ONLY cannot redirect, modify, drop or reinject any packet.
func TestCS2AutoSignedDriverFlowTuple(t *testing.T) {
	dir := os.Getenv("NEEXITLAG_TEST_DRIVER_DIR")
	if dir == "" {
		t.Skip("requires signed driver on a native Windows runner")
	}
	raw, err := os.ReadFile(filepath.Join(dir, "pins.json"))
	if err != nil {
		t.Fatal(err)
	}
	var pins DriverFiles
	if err := json.Unmarshal(raw, &pins); err != nil {
		t.Fatal(err)
	}
	pins.Directory = dir
	d, err := loadDivert(pins)
	if err != nil {
		t.Fatal(err)
	}
	defer d.dll.Release()

	server, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	dest := server.LocalAddr().(*net.UDPAddr)
	filter := fmt.Sprintf("outbound and udp and processId == %d and remotePort == %d", os.Getpid(), dest.Port)
	h, err := d.openHandle(filter, 2, 1|4)
	if err != nil {
		t.Fatal(err)
	}
	defer d.close.Call(h)

	// Open the socket after the observer. Its assigned source port comes from
	// Windows and is compared independently to the decoded event.
	client, err := net.DialUDP("udp4", nil, dest)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if _, err = client.Write([]byte{42}); err != nil {
		t.Fatal(err)
	}
	if err := server.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	var payload [8]byte
	n, source, err := server.ReadFromUDP(payload[:])
	if err != nil || n != 1 || payload[0] != 42 {
		t.Fatalf("loopback exchange: %d, %v", n, err)
	}
	want := Tuple{"udp", source.AddrPort(), dest.AddrPort()}
	want.Source = netip.AddrPortFrom(want.Source.Addr().Unmap(), want.Source.Port())
	want.Destination = netip.AddrPortFrom(want.Destination.Addr().Unmap(), want.Destination.Port())

	expired := make(chan struct{})
	timer := time.AfterFunc(8*time.Second, func() { d.shutdown.Call(h, 3); close(expired) })
	defer func() {
		if !timer.Stop() {
			<-expired
		}
	}()
	var a [80]byte
	ok, _, err := d.recv.Call(h, 0, 0, 0, uintptr(unsafe.Pointer(&a[0])))
	if ok == 0 {
		t.Fatalf("read-only FLOW event: %v", err)
	}
	data := a[16:]
	if a[8] != 2 || a[9] != 1 || binary.LittleEndian.Uint32(data[16:]) != uint32(os.Getpid()) || binary.LittleEndian.Uint64(data) == 0 || data[56] != 17 {
		t.Fatal("unexpected native FLOW owner, endpoint, event or protocol")
	}
	if got := cs2IPv4FlowTuple(data, a[10]&16 != 0); got != want {
		t.Fatalf("driver tuple %v does not match actual socket %v", got, want)
	}
}
