package localstrategy

import (
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"github.com/buzzmean/veliq/core/optimizer"
	"github.com/buzzmean/veliq/core/protocol"
	"net"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"
	"unsafe"
)

func profile() Profile {
	return Profile{ID: "test", Name: "test", Version: 1, Protocol: "tcp", Ports: []uint16{443}, Application: "chosen.exe", IPs: []string{"203.0.113.0/24"}, Strategy: "tcp-split-1", Cutoff: 2, Enabled: true}
}
func metadata() Metadata {
	return Metadata{Application: `C:\test\chosen.exe`, Protocol: "tcp", Destination: netip.MustParseAddrPort("203.0.113.9:443")}
}
func packet(proto byte, payload []byte) []byte {
	h := 40
	if proto == 17 {
		h = 28
	}
	p := make([]byte, h+len(payload))
	p[0] = 0x45
	p[8] = 64
	p[9] = proto
	p[4] = 7
	p[6] = 0x40
	binary.BigEndian.PutUint16(p[2:], uint16(len(p)))
	copy(p[12:16], []byte{192, 0, 2, 4})
	copy(p[16:20], []byte{203, 0, 113, 9})
	binary.BigEndian.PutUint16(p[20:], 50000)
	binary.BigEndian.PutUint16(p[22:], 443)
	if proto == 6 {
		p[32] = 0x50
		p[33] = 0x18
		binary.BigEndian.PutUint32(p[24:], 0xfffffffe)
	} else {
		binary.BigEndian.PutUint16(p[24:], uint16(len(p)-20))
	}
	copy(p[h:], payload)
	checksumTransport(p)
	return p
}
func engine(t *testing.T, p Profile) *LocalStrategyEngine {
	t.Helper()
	e := New()
	if err := e.Reload(Config{Version: 1, Enabled: true, User: []Profile{p}}); err != nil {
		t.Fatal(err)
	}
	return e
}
func TestMatchingAndAtomicReload(t *testing.T) {
	p := profile()
	p.Domains = []string{"example.test", "*.example.org"}
	p.ExcludeDomains = []string{"private.example.org"}
	p.ExcludeIPs = []string{"203.0.113.8/32"}
	e := engine(t, p)
	for _, tc := range []struct {
		domain, ip, app string
		want            bool
	}{{"example.test", "198.51.100.1:443", "chosen.exe", true}, {"a.example.org", "198.51.100.1:443", "chosen.exe", true}, {"example.org", "198.51.100.1:443", "chosen.exe", false}, {"private.example.org", "203.0.113.9:443", "chosen.exe", false}, {"example.test", "203.0.113.8:443", "chosen.exe", false}, {"example.test", "203.0.113.9:443", "control.exe", false}, {"", "203.0.113.9:443", "chosen.exe", false}, {"evil-example.test", "198.51.100.1:443", "chosen.exe", false}} {
		m := metadata()
		m.Domain = tc.domain
		m.Application = tc.app
		m.Destination = netip.MustParseAddrPort(tc.ip)
		if got := e.Match(m); got != tc.want {
			t.Errorf("%+v = %v", tc, got)
		}
	}
	old := e.Config()
	bad := old
	bad.User = append(bad.User, old.User[0])
	if e.Reload(bad) == nil {
		t.Fatal("duplicate accepted")
	}
	if len(e.Config().User) != 1 {
		t.Fatal("partial reload")
	}
	old.User[0].IPs[0] = "0.0.0.0/0"
	if e.Reload(old) == nil {
		t.Fatal("global CIDR accepted")
	}
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for n := 0; n < 100; n++ {
				e.Match(metadata())
				e.Config()
			}
		}()
	}
	for i := 0; i < 20; i++ {
		e.Reload(Config{Version: 1, Enabled: true, User: []Profile{p}})
	}
	wg.Wait()
}
func TestTCPPreservesStreamAndChecksums(t *testing.T) {
	for _, strategy := range []string{"tcp-split-1", "tcp-split-5"} {
		p := profile()
		p.Strategy = strategy
		e := engine(t, p)
		raw := packet(6, []byte("GET / HTTP/1.1\r\nHost: example.test\r\n\r\n"))
		original := append([]byte(nil), raw...)
		state := &State{}
		r := e.Process(raw, state, metadata())
		if !r.Modified || len(r.Packets) != 2 {
			t.Fatal(r)
		}
		var stream []byte
		seq := binary.BigEndian.Uint32(raw[24:])
		for _, q := range r.Packets {
			h := 20 + int(q[32]>>4)*4
			if binary.BigEndian.Uint32(q[24:]) != seq {
				t.Fatal("sequence")
			}
			seq += uint32(len(q) - h)
			stream = append(stream, q[h:]...)
			if finish(sum(q[:20])) != 0 || finish(sum(q[12:20])+6+uint32(len(q)-20)+sum(q[20:])) != 0 {
				t.Fatal("checksum")
			}
			if !bytes.Equal(q[12:24], raw[12:24]) {
				t.Fatal("destination changed")
			}
		}
		if !bytes.Equal(stream, raw[40:]) || !bytes.Equal(raw, original) {
			t.Fatal("payload changed")
		}
		if r.Packets[0][33]&8 != 0 || r.Packets[1][33]&8 == 0 {
			t.Fatal("PSH")
		}
		e.Commit(r, len(raw))
		e.Process(raw, state, metadata())
		if e.Process(raw, state, metadata()).Modified {
			t.Fatal("cutoff")
		}
		if e.Metrics().Modified != 1 || e.Metrics().RelayAvoided != 0 {
			t.Fatal(e.Metrics())
		}
	}
}
func TestUDPFragmentReassembly(t *testing.T) {
	p := profile()
	p.Protocol = "udp"
	p.Strategy = "udp-fragment-24"
	e := engine(t, p)
	m := metadata()
	m.Protocol = "udp"
	raw := packet(17, bytes.Repeat([]byte{42}, 1200))
	r := e.Process(raw, &State{}, m)
	if !r.Modified {
		t.Fatal("not fragmented")
	}
	var body []byte
	for i, q := range r.Packets {
		if finish(sum(q[:20])) != 0 {
			t.Fatal("IP checksum")
		}
		off := binary.BigEndian.Uint16(q[6:])
		if int(off&8191)*8 != len(body) || off&0x4000 != 0 || ((off&0x2000 != 0) != (i == 0)) {
			t.Fatal("fragment flags/offset")
		}
		body = append(body, q[20:]...)
		if len(q) > len(raw) {
			t.Fatal("MTU")
		}
	}
	if !bytes.Equal(body, raw[20:]) {
		t.Fatal("UDP datagram corrupted")
	}
	if finish(sum(raw[12:20])+17+uint32(len(body))+sum(body)) != 0 {
		t.Fatal("UDP checksum")
	}
}
func TestUnsupportedAndReloadFailOpen(t *testing.T) {
	p := profile()
	e := engine(t, p)
	raw := packet(6, []byte("hello world"))
	raw[33] |= 2
	if e.Process(raw, &State{}, metadata()).Modified {
		t.Fatal("SYN payload modified")
	}
	raw[33] &= ^byte(2)
	st := &State{}
	if !e.Process(raw, st, metadata()).Modified {
		t.Fatal("expected split")
	}
	e.Reload(e.Config())
	if e.Process(raw, st, metadata()).Modified {
		t.Fatal("live flow reconfigured")
	}
	st.Disable()
	if e.Process(raw, st, metadata()).Strategy != "" {
		t.Fatal("failed state retained")
	}
	raw[0] = 0x46
	if e.Process(raw, &State{}, metadata()).Modified {
		t.Fatal("options")
	}
}
func TestTLSAndHTTPDomain(t *testing.T) {
	if got := PacketDomain([]byte("GET / HTTP/1.1\r\nHost: A.Example.Test:443\r\n\r\n")); got != "a.example.test" {
		t.Fatal(got)
	}
	a, b := net.Pipe()
	defer b.Close()
	go func() { defer a.Close(); tls.Client(a, &tls.Config{ServerName: "tls.example.test"}).Handshake() }()
	buf := make([]byte, 16384)
	b.SetReadDeadline(time.Now().Add(time.Second))
	n, err := b.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	if got := PacketDomain(buf[:n]); got != "tls.example.test" {
		t.Fatal(got)
	}
	for i := 0; i < n; i++ {
		PacketDomain(buf[:i])
	}
}
func TestCacheTTLQuarantineAndAuto(t *testing.T) {
	now := time.Now()
	k := TargetKey{Network: "network", Application: "chosen.exe", Destination: "203.0.113.9:443", Protocol: "tcp", Version: 1}
	c := NewCache(1)
	good := optimizer.RouteMeasurement{RouteID: "test", Available: true, Samples: 10, RTT: 20 * time.Millisecond, Stability: 1, ObservedAt: now}
	bad := good
	bad.Available = false
	for i := 0; i < 3; i++ {
		if err := c.Record(k, "split", bad, false, now); err != nil {
			t.Fatal(err)
		}
	}
	if c.Record(k, "split", good, true, now) == nil {
		t.Fatal("quarantine ignored")
	}
	if len(c.Candidates(k, now)) != 0 {
		t.Fatal("quarantine")
	}
	later := now.Add(6 * time.Minute)
	good.ObservedAt = later
	if err := c.Record(k, "split", good, true, later); err != nil {
		t.Fatal(err)
	}
	other := k
	other.Network = "changed"
	if len(c.Candidates(other, later)) != 0 {
		t.Fatal("network leak")
	}
	v := c.Candidates(k, later)
	if len(v) != 1 {
		t.Fatal(v)
	}
	direct := good
	direct.Loss = .1
	relay := good
	relay.RTT = 24 * time.Millisecond
	if got := Recommend(direct, v, relay, later); got != "split" {
		t.Fatal(got)
	}
	direct.Loss = 0
	if got := Recommend(direct, v, relay, later); got != "DIRECT" {
		t.Fatal(got)
	}
	direct.Loss = .1
	v[0].Measurement.RTT = time.Second
	if got := Recommend(direct, v, relay, later); got != "RELAY" {
		t.Fatal(got)
	}
	c.Cleanup(later.Add(16 * time.Minute))
	if len(c.items) != 0 {
		t.Fatal("cleanup")
	}
}

var benchmarkSink int

func BenchmarkPacketPaths(b *testing.B) {
	p := profile()
	e := New()
	e.Reload(Config{Version: 1, Enabled: true, User: []Profile{p}})
	raw := packet(6, bytes.Repeat([]byte{7}, 1000))
	m := metadata()
	for _, name := range []string{"DIRECT", "DIRECT_PLUS_initial", "DIRECT_PLUS_after_cutoff", "RELAY_packaging_only"} {
		b.Run(name, func(b *testing.B) {
			b.ReportAllocs()
			state := State{done: true}
			for i := 0; i < b.N; i++ {
				switch name {
				case "DIRECT":
					benchmarkSink = int(raw[9])
				case "DIRECT_PLUS_initial":
					state = State{}
					e.Process(raw, &state, m)
				case "RELAY_packaging_only":
					encoded, _ := protocol.EncodeDatagrams(1, uint32(i), raw[40:])
					benchmarkSink = len(encoded)
				default:
					e.Process(raw, &state, m)
				}
			}
		})
	}
}
func FuzzPacketParser(f *testing.F) {
	f.Add(packet(6, []byte("hello")))
	f.Add(packet(17, []byte("hello")))
	f.Fuzz(func(t *testing.T, p []byte) {
		PacketDomain(p)
		transform(p, "tcp-split-1")
		transform(p, "udp-fragment-24")
	})
}

func TestBoundsExclusionPrecedenceAndFailSafe(t *testing.T) {
	p := profile()
	a := p
	a.ID = "exclude"
	a.ExcludeIPs = []string{"203.0.113.9"}
	e := New()
	if err := e.Reload(Config{Version: 1, Enabled: true, User: []Profile{p, a}}); err != nil {
		t.Fatal(err)
	}
	raw := packet(6, []byte("hello world"))
	if e.Process(raw, &State{}, metadata()).Modified {
		t.Fatal("another profile bypassed exclusion")
	}
	e = engine(t, p)
	e.Guard = func(Metadata) bool { panic("fault injection") }
	st := &State{}
	if r := e.Process(raw, st, metadata()); !r.Failed {
		t.Fatal("panic not contained")
	}
	if r := e.Process(raw, st, metadata()); r.Modified || r.Strategy != "" {
		t.Fatal("failed state reused")
	}
	if e.Metrics().Errors != 1 {
		t.Fatal(e.Metrics())
	}
	e.Guard = nil
	e.Suspend(true)
	if e.Process(raw, &State{}, metadata()).Modified {
		t.Fatal("conflict not suspended")
	}
	all := make([]Profile, MaxProfiles+1)
	for i := range all {
		all[i] = p
	}
	if e.Reload(Config{Version: 1, User: all}) == nil {
		t.Fatal("unbounded profiles")
	}
	ips, err := NewIPSet([]string{"2001:db8::/32", "203.0.113.9"})
	if err != nil || !ips.Contains(netip.MustParseAddr("2001:db8::1")) || ips.Contains(netip.MustParseAddr("2001:db9::1")) {
		t.Fatal(ips, err)
	}
}
func TestStateDisableAfterCutoffAndOptionSafety(t *testing.T) {
	p := profile()
	p.Cutoff = 1
	e := engine(t, p)
	raw := packet(6, []byte("hello world"))
	st := &State{}
	r := e.Process(raw, st, metadata())
	e.Commit(r, len(raw))
	if e.Metrics().Flows != 1 {
		t.Fatal("flow count before successful send")
	}
	e.Reload(Config{Version: 1})
	if e.Process(raw, st, metadata()).Strategy != "" {
		t.Fatal("disabled cutoff kept local evidence")
	}
	q := make([]byte, len(raw)+4)
	copy(q, raw[:40])
	copy(q[44:], raw[40:])
	q[32] = 0x60
	q[40] = 19
	q[41] = 4
	binary.BigEndian.PutUint16(q[2:], uint16(len(q)))
	if transform(q, "tcp-split-1") != nil {
		t.Fatal("MD5 rewritten")
	}
	q[40] = 29
	if transform(q, "tcp-split-1") != nil {
		t.Fatal("AO rewritten")
	}
}

func TestDataDrivenSplitPosition(t *testing.T) {
	p := profile()
	p.Strategy = "tcp-split"
	p.SplitPosition = 7
	e := engine(t, p)
	raw := packet(6, []byte("hello world"))
	r := e.Process(raw, &State{}, metadata())
	if !r.Modified || len(r.Packets[0]) != 47 || binary.BigEndian.Uint32(r.Packets[1][24:]) != binary.BigEndian.Uint32(raw[24:])+7 {
		t.Fatal("configured position not applied")
	}
	p.SplitPosition = 513
	if e.Reload(Config{Version: 1, Enabled: true, User: []Profile{p}}) == nil {
		t.Fatal("unbounded split offset")
	}
}

// A retained Host must own its storage, not keep the rest of an HTTP request
// (cookies/authorization/body) alive in per-flow state after the packet returns.
func TestHTTPDomainDoesNotRetainRequestStorage(t *testing.T) {
	request := "GET / HTTP/1.1\r\nHost: example.test\r\nAuthorization: " + strings.Repeat("sensitive", 512) + "\r\n\r\n"
	got := httpDomain(request)
	if got != "example.test" {
		t.Fatal(got)
	}
	first := uintptr(unsafe.Pointer(unsafe.StringData(request)))
	host := uintptr(unsafe.Pointer(unsafe.StringData(got)))
	if host >= first && host < first+uintptr(len(request)) {
		t.Fatal("Host retains unrelated HTTP request bytes")
	}
}
