package windowsplatform

import (
	"encoding/binary"
	"github.com/buzzmean/veliq/core/routing"
	"net/netip"
	"testing"
	"time"
)

func tcpPacket(t *testing.T, tuple Tuple) []byte {
	t.Helper()
	p := make([]byte, 45)
	p[0] = 0x45
	p[9] = 6
	p[32] = 0x50
	p[33] = 2
	binary.BigEndian.PutUint16(p[2:4], uint16(len(p)))
	s, d := tuple.Source.Addr().As4(), tuple.Destination.Addr().As4()
	copy(p[12:16], s[:])
	copy(p[16:20], d[:])
	binary.BigEndian.PutUint16(p[20:22], tuple.Source.Port())
	binary.BigEndian.PutUint16(p[22:24], tuple.Destination.Port())
	copy(p[40:], "hello")
	return p
}
func testTuple() Tuple {
	return Tuple{"tcp", netip.MustParseAddrPort("192.0.2.2:50001"), netip.MustParseAddrPort("203.0.113.4:443")}
}
func TestTCPReflectionPreservesTLSBytesAndSequence(t *testing.T) {
	tuple := testTuple()
	p := tcpPacket(t, tuple)
	binary.BigEndian.PutUint32(p[24:28], 0xabc123)
	reflected, e := ReflectTCP(p, netip.MustParseAddrPort("203.0.113.4:20001"), netip.MustParseAddrPort("192.0.2.2:51000"))
	if e != nil {
		t.Fatal(e)
	}
	got, flags, n, e := ParseTCP(reflected)
	if e != nil || flags != 2 || n != 5 || got.Source.Port() != 20001 || got.Destination.Port() != 51000 || string(reflected[40:]) != "hello" || binary.BigEndian.Uint32(reflected[24:28]) != 0xabc123 {
		t.Fatalf("bad reflection %v %v", got, e)
	}
	restored, e := ReflectTCP(reflected, tuple.Source, tuple.Destination)
	if e != nil {
		t.Fatal(e)
	}
	got, _, _, _ = ParseTCP(restored)
	if got != tuple {
		t.Fatal(got)
	}
}
func TestTCPMalformedNeverRedirected(t *testing.T) {
	for _, edit := range []func([]byte){func(p []byte) { p[0] = 0x60 }, func(p []byte) { p[6] = 0x20 }, func(p []byte) { p[32] = 0xf0 }, func(p []byte) { p[2] = 1 }, func(p []byte) { p[9] = 17 }} {
		p := tcpPacket(t, testTuple())
		edit(p)
		if _, _, _, e := ParseTCP(p); e == nil {
			t.Fatal("accepted malformed")
		}
	}
}
func TestTCPBoundedStateCollisionPinAndCleanup(t *testing.T) {
	s := newTCPState(2)
	now := time.Now()
	tuple := testTuple()
	id := ProcessIdentity{PID: 42, CreationTime: 5, Path: "test.exe"}
	s.mu.Lock()
	defer s.mu.Unlock()
	a := s.add(tuple, id, Decision{}, "opening", now)
	other := tuple
	other.Destination = netip.MustParseAddrPort("203.0.113.4:80")
	b := s.add(other, id, Decision{}, "opening", now)
	if a == nil || b == nil || a.virtual == b.virtual {
		t.Fatal("collision")
	}
	third := other
	third.Source = netip.MustParseAddrPort("192.0.2.2:50002")
	if s.add(third, id, Decision{}, "direct", now) != nil {
		t.Fatal("unbounded")
	}
	a.mode = "relay"
	s.expire(now.Add(10 * time.Second))
	b.last = now.Add(-20 * time.Second)
	s.expire(now.Add(11 * time.Second))
	if s.entries[tuple] != a || s.entries[other].mode != "closed" {
		t.Fatal("active evicted / opening leaked")
	}
	s.expire(now.Add(3 * time.Hour))
	s.expire(now.Add(3*time.Hour + 5*time.Minute))
	if len(s.entries) != 0 || len(s.ports) != 0 {
		t.Fatal("state leaked")
	}
}
func TestTCPOwnerRequiresFullTuple(t *testing.T) {
	tuple := testTuple()
	b := make([]byte, 28)
	binary.LittleEndian.PutUint32(b, 1)
	s, d := tuple.Source.Addr().As4(), tuple.Destination.Addr().As4()
	copy(b[8:12], s[:])
	copy(b[16:20], d[:])
	binary.BigEndian.PutUint16(b[12:14], tuple.Source.Port())
	binary.BigEndian.PutUint16(b[20:22], tuple.Destination.Port())
	binary.LittleEndian.PutUint32(b[24:], 42)
	owners, e := tcpOwners(b, tuple, false)
	if e != nil || !owners[42] {
		t.Fatal(owners, e)
	}
	tuple.Destination = netip.MustParseAddrPort("203.0.113.4:80")
	owners, e = tcpOwners(b, tuple, false)
	if e != nil || len(owners) != 0 {
		t.Fatal("wrong tuple attributed")
	}
	if _, e = tcpOwners(b[:27], tuple, false); e == nil {
		t.Fatal("truncated")
	}
}
func TestTCPEvidenceProtocolAndBytes(t *testing.T) {
	l := NewEvidenceLedger()
	id := ProcessIdentity{PID: 42, CreationTime: 1, Path: "selected.exe"}
	l.RecordBytes(id, testTuple(), "captured", "", 60)
	l.RecordBytes(id, testTuple(), "relay", "VPS-01", 0)
	l.AddBytes(id, testTuple(), "relay", "VPS-01", 123)
	s := l.Snapshot(42)
	if len(s.Flows) != 1 || s.Flows[0].Protocol != "tcp" || s.Flows[0].IPVersion != "IPv4" || s.Flows[0].Counters.Relayed != 1 || s.Flows[0].Counters.RelayedBytes != 123 || s.Flows[0].Route != "RELAY" {
		t.Fatalf("%+v", s)
	}
}
func TestIPv6SocketGuardSelectedOnly(t *testing.T) {
	var a [80]byte
	a[8] = 3
	a[9] = 4
	a[10] = 16
	data := a[16:]
	binary.LittleEndian.PutUint32(data[16:20], 42)
	data[56] = 6
	ip := netip.MustParseAddr("2001:db8::1234").As16()
	for i := 0; i < 4; i++ {
		binary.LittleEndian.PutUint32(data[36+(3-i)*4:], binary.BigEndian.Uint32(ip[i*4:]))
	}
	binary.LittleEndian.PutUint16(data[54:56], 443)
	pid, tuple, e := DecodeSocketEvent(a)
	if e != nil || pid != 42 || tuple.Destination.String() != "[2001:db8::1234]:443" {
		t.Fatal(pid, tuple, e)
	}
	selected := ProcessIdentity{PID: 42, CreationTime: 1, Path: "chrome.exe"}
	classify := func(id ProcessIdentity, t Tuple) Decision {
		if id.PID == 42 {
			return Decision{Route: routing.Route{RelayID: "VPS-01"}}
		}
		return Decision{}
	}
	if !(&IPv6Guard{}).Block(selected, tuple, 2, classify(selected, tuple), 1, time.Now()) {
		t.Fatal("selected IPv6 leaked")
	}
	if (&IPv6Guard{}).Block(selected, tuple, 2, classify(selected, tuple), 42, time.Now()) {
		t.Fatal("service blocked")
	}
	selected.PID = 43
	if (&IPv6Guard{}).Block(selected, tuple, 2, classify(selected, tuple), 1, time.Now()) {
		t.Fatal("unselected blocked")
	}
}

func TestNewTCPSynReusesTupleWithoutInheritingOldRoute(t *testing.T) {
	s := newTCPState(4)
	now := time.Now()
	tuple := testTuple()
	old := s.add(tuple, ProcessIdentity{}, Decision{Route: routing.Route{RelayID: "A"}}, "opening", now)
	old.initialSequence = 123
	if s.existing(tuple, 2, 123, now) != old {
		t.Fatal("retransmission changed route")
	}
	if s.existing(tuple, 16, 456, now) != old {
		t.Fatal("established packet changed route")
	}
	if s.existing(tuple, 2, 456, now) != nil || s.ports[old.virtual] != old || old.mode != "closed" {
		t.Fatal("new connection inherited old policy or virtual port reused")
	}
	replacement := s.add(tuple, ProcessIdentity{}, Decision{}, "direct", now)
	replacement.initialSequence = 456
	if replacement == nil || replacement.decision.Route.RelayID != "" {
		t.Fatal("new route not used")
	}
	s.expire(now.Add(5 * time.Minute))
	if len(s.ports) != 0 {
		t.Fatal("retired virtual port leaked")
	}
}

func TestSocketDualStackChromeOwnerMatchesIPv4SYN(t *testing.T) {
	var a [80]byte
	a[8] = 3
	a[9] = 4
	a[10] = 16
	data := a[16:]
	binary.LittleEndian.PutUint32(data[16:20], 777)
	data[56] = 6
	tuple := testTuple()
	for _, part := range []struct {
		offset int
		addr   netip.Addr
	}{{20, tuple.Source.Addr()}, {36, tuple.Destination.Addr()}} {
		ip := part.addr.As16()
		for i := 0; i < 4; i++ {
			binary.LittleEndian.PutUint32(data[part.offset+(3-i)*4:], binary.BigEndian.Uint32(ip[i*4:]))
		}
	}
	binary.LittleEndian.PutUint16(data[52:54], tuple.Source.Port())
	binary.LittleEndian.PutUint16(data[54:56], tuple.Destination.Port())
	pid, socketTuple, err := DecodeSocketEvent(a)
	if err != nil || pid != 777 || socketTuple != tuple {
		t.Fatalf("dual-stack NetworkService association misses IPv4 SYN: pid=%d tuple=%v want=%v err=%v", pid, socketTuple, tuple, err)
	}
	associations := NewAssociations(4)
	id := ProcessIdentity{PID: 777, CreationTime: 17, Path: `C:\Apps\chrome.exe`}
	associations.Put(Association{Identity: id, Tuple: socketTuple})
	if _, ok := associations.Get(tuple, id); !ok {
		t.Fatal("utility child lost at SOCKET to NETWORK boundary")
	}
	reused := id
	reused.CreationTime++
	if _, ok := associations.Get(tuple, reused); ok {
		t.Fatal("reused utility PID inherited old identity")
	}
}
