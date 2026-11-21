//go:build windows

package windowsplatform

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/buzzmean/neexitlag/core/flowpolicy"
	"github.com/buzzmean/neexitlag/core/routing"
)

type captureTestUDP struct {
	replies chan []byte
	done    chan struct{}
	once    sync.Once
}

func (d *captureTestUDP) Send(p []byte) error {
	select {
	case <-d.done:
		return errors.New("session lost")
	case d.replies <- append([]byte(nil), p...):
		return nil
	}
}
func (d *captureTestUDP) Receive(ctx context.Context) ([]byte, error) {
	select {
	case <-d.done:
		return nil, errors.New("session lost")
	case <-ctx.Done():
		return nil, ctx.Err()
	case p := <-d.replies:
		return p, nil
	}
}
func (d *captureTestUDP) Close() error { d.once.Do(func() { close(d.done) }); return nil }

type captureTestRelay struct {
	mu    sync.Mutex
	flows []*captureTestUDP
}

func (r *captureTestRelay) OpenDatagram(context.Context, netip.AddrPort) (routing.Datagram, error) {
	d := &captureTestUDP{replies: make(chan []byte, 32), done: make(chan struct{})}
	r.mu.Lock()
	r.flows = append(r.flows, d)
	r.mu.Unlock()
	return d, nil
}
func (r *captureTestRelay) OpenTCP(context.Context, netip.AddrPort) (net.Conn, error) {
	return nil, errors.New("not used")
}
func captureWait(t *testing.T, check func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if check() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("capture condition timeout")
}
func captureFixture(t *testing.T) (*WinDivertBackend, *captureTestRelay) {
	t.Helper()
	r := &captureTestRelay{}
	engine := routing.New(1024)
	engine.SetRelay("VPS-01", r)
	b := NewWinDivert(DriverFiles{}, engine)
	b.ctx, b.cancel = context.WithCancel(context.Background())
	b.packetWriter = func([]byte, [80]byte) error { return nil }
	t.Cleanup(func() { b.cancel(); b.wg.Wait() })
	return b, r
}
func startCaptureTestFlow(t *testing.T, b *WinDivertBackend, port uint16, media bool, dest netip.AddrPort, applications ...string) (Tuple, *captureFlow) {
	t.Helper()
	tuple := Tuple{Protocol: "udp", Source: netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), port), Destination: dest}
	id := ProcessIdentity{PID: uint32(port), CreationTime: 1, Path: "app.exe"}
	application := "test"
	if len(applications) > 0 {
		application = applications[0]
	}
	flow := routing.Flow{Protocol: "udp", Source: tuple.Source, Destination: tuple.Destination, PID: id.PID, ProcessPath: id.Path, ApplicationID: application}
	route := routing.Route{RelayID: "VPS-01"}
	policy := flowpolicy.Result{Action: flowpolicy.RelayRequired, Fallback: flowpolicy.Required}
	if media {
		route = routing.Route{}
		policy = flowpolicy.Result{Action: flowpolicy.Direct, Fallback: flowpolicy.FlowRelay, RelayID: "VPS-01"}
	}
	// Use pinned real routing policy, matching capture's per-flow classification.
	flow.PinnedPolicy = &routing.Policy{Route: route, BlockOnFailure: true}
	raw := make([]byte, 29)
	raw[0] = 0x45
	raw[9] = 17
	binary.BigEndian.PutUint16(raw[2:], 29)
	copy(raw[12:16], []byte{127, 0, 0, 1})
	addr := dest.Addr().As4()
	copy(raw[16:20], addr[:])
	binary.BigEndian.PutUint16(raw[20:], port)
	binary.BigEndian.PutUint16(raw[22:], dest.Port())
	binary.BigEndian.PutUint16(raw[24:], 9)
	f := &captureFlow{opening: true, decision: Decision{Route: route, Flow: flow, Policy: policy, BlockOnFailure: true, ProbeDirect: media}, queue: make(chan queuedDatagram, 32), done: make(chan struct{}), identity: id, template: raw, lastSeen: time.Now()}
	b.mu.Lock()
	if !b.admission.acquire(media) {
		b.mu.Unlock()
		t.Fatal("supported load rejected")
	}
	b.flows[tuple] = f
	b.evidence.BeginFlow(id, tuple)
	b.evidence.RecordPolicy(id, tuple, f.decision, "")
	f.queue <- queuedDatagram{payload: []byte{1}, enqueued: time.Now()}
	b.wg.Add(1)
	go b.forward(tuple, f, nil)
	b.mu.Unlock()
	return tuple, f
}
func TestUDPForwardNativeIdleReopenAndActiveFailure(t *testing.T) {
	b, r := captureFixture(t)
	dest := netip.MustParseAddrPort("1.1.1.1:53")
	tuple, f := startCaptureTestFlow(t, b, 40001, false, dest)
	captureWait(t, func() bool {
		s := b.evidence.Snapshot(f.identity.PID)
		return len(s.Flows) == 1 && s.Flows[0].Counters.ReplyBytes > 0
	})
	b.mu.Lock()
	f.lastSeen = time.Now().Add(-udpDNSIdle)
	b.mu.Unlock()
	captureWait(t, func() bool { b.mu.Lock(); defer b.mu.Unlock(); return b.flows[tuple] == nil && b.admission.total == 0 })
	first := b.evidence.Snapshot(f.identity.PID).Flows[0]
	if first.Route != "RELAY" || first.FailureCause != "" || first.Lifecycle != "UDP_IDLE_EXPIRED" {
		t.Fatal(first)
	}
	if len(b.Engine.Snapshot()) != 0 {
		t.Fatal("Engine tuple stuck after idle close")
	}
	_, next := startCaptureTestFlow(t, b, 40001, false, dest)
	captureWait(t, func() bool {
		s := b.evidence.Snapshot(next.identity.PID)
		return len(s.Flows) == 1 && s.Flows[0].Counters.ReplyBytes > 0
	})
	// A real transport loss drops affected datagrams but future outbound
	// packets reopen the same protected logical flow, without DIRECT or BLOCK.
	r.mu.Lock()
	live := r.flows[len(r.flows)-1]
	before := len(r.flows)
	r.mu.Unlock()
	previous := b.evidence.Snapshot(next.identity.PID).Flows[0].Counters.ReplyBytes
	live.Close()
	captureWait(t, func() bool {
		b.mu.Lock()
		select {
		case next.queue <- queuedDatagram{payload: []byte{2}, enqueued: time.Now()}:
		default:
		}
		b.mu.Unlock()
		r.mu.Lock()
		reopened := len(r.flows) > before
		r.mu.Unlock()
		snap := b.evidence.Snapshot(next.identity.PID)
		return reopened && len(snap.Flows) == 1 && snap.Flows[0].Counters.ReplyBytes > previous
	})
	recovered := b.evidence.Snapshot(next.identity.PID).Flows[0]
	if recovered.Route != "RELAY" || recovered.RequiredBlocked || recovered.Counters.DirectBytes != 0 {
		t.Fatal(recovered)
	}
	b.mu.Lock()
	same := b.flows[tuple] == next
	b.mu.Unlock()
	if !same {
		t.Fatal("logical flow replaced")
	}

}
func TestUDPForwardNativeDNSChurnWithPersistentMedia(t *testing.T) {
	b, _ := captureFixture(t)
	echo, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
	go func() {
		buf := make([]byte, 1500)
		for {
			n, a, e := echo.ReadFrom(buf)
			if e != nil {
				return
			}
			echo.WriteTo(buf[:n], a)
		}
	}()
	dest := netip.MustParseAddrPort(echo.LocalAddr().String())
	// >64 simultaneously held real forward loops; DNS uses a controlled relay
	// double, adaptive media uses a real native UDP socket + local echo target.
	for i := 0; i < 160; i++ {
		startCaptureTestFlow(t, b, uint16(41000+i), false, netip.MustParseAddrPort("1.1.1.1:53"))
	}
	media := map[Tuple]*captureFlow{}
	for i := 0; i < 8; i++ {
		tuple, f := startCaptureTestFlow(t, b, uint16(42000+i), true, dest)
		media[tuple] = f
	}
	captureWait(t, func() bool { return b.evidence.Snapshot(0).Counters.ReplyBytes >= 160 })
	b.mu.Lock()
	for tuple, f := range b.flows {
		if !f.decision.ProbeDirect {
			f.lastSeen = time.Now().Add(-udpDNSIdle)
		} else {
			media[tuple] = f
		}
	}
	b.mu.Unlock()
	// Keep media outbound alive while DNS entries are reclaimed.
	deadline := time.Now().Add(1500 * time.Millisecond)
	for time.Now().Before(deadline) {
		b.mu.Lock()
		for _, f := range media {
			f.lastSeen = time.Now()
			select {
			case f.queue <- queuedDatagram{payload: []byte{2}, enqueued: time.Now()}:
			default:
				t.Error("media queue full")
			}
		}
		b.mu.Unlock()
		time.Sleep(100 * time.Millisecond)
	}
	captureWait(t, func() bool { b.mu.Lock(); defer b.mu.Unlock(); return b.admission.ordinary == 0 })
	for _, v := range captureAllFlows(t, b.evidence) {
		if v.FailureCause != "" || v.Counters.DirectBytes > 0 && v.Policy.Fallback == flowpolicy.Required {
			t.Fatal(v)
		}
	}
	for _, f := range media {
		v := b.evidence.Snapshot(f.identity.PID).Flows[0]
		if v.Counters.DirectReplyBytes == 0 {
			t.Fatal("native media starved", v)
		}
	}
	if b.LocalDrops.Total() != 0 {
		t.Fatal(b.LocalDrops.Snapshot())
	}
}

func captureAllFlows(t *testing.T, l *EvidenceLedger) []FlowEvidence {
	t.Helper()
	c := l.ChangeMarker()
	c.AfterUpdate = 0
	var out []FlowEvidence
	for i := 0; i < 100; i++ {
		p, err := l.ChangePage(ChangeQuery{Cursor: c})
		if err != nil || p.EvidenceLost {
			t.Fatal("incomplete capture", err)
		}
		out = append(out, p.Flows...)
		c = p.Cursor
		if !p.More {
			return out
		}
	}
	t.Fatal("unbounded pages")
	return nil
}

type captureBrokenTCP struct {
	net.Conn
	breakRead bool
}

func (c *captureBrokenTCP) Read(p []byte) (int, error) {
	if c.breakRead {
		return 0, errors.New("test active relay session death")
	}
	n, err := c.Conn.Read(p)
	if n > 0 {
		c.breakRead = true
	}
	return n, err
}
func TestTCPNativePipeNormalCloseAndTailEvidence(t *testing.T) {
	t.Run("normal_FIN_tail", func(t *testing.T) { testTCPNativePipe(t, false) })
	t.Run("midflow_transport_death", func(t *testing.T) { testTCPNativePipe(t, true) })
}
func testTCPNativePipe(t *testing.T, broken bool) {
	b, _ := captureFixture(t)
	pair := func() (net.Conn, net.Conn) {
		l, err := net.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		c, err := net.Dial("tcp4", l.Addr().String())
		if err != nil {
			l.Close()
			t.Fatal(err)
		}
		s, err := l.Accept()
		l.Close()
		if err != nil {
			c.Close()
			t.Fatal(err)
		}
		t.Cleanup(func() { c.Close(); s.Close() })
		return c, s
	}
	app, local := pair()
	up, target := pair()
	if broken {
		up = &captureBrokenTCP{Conn: up}
	}
	id := ProcessIdentity{PID: 88, CreationTime: 5, Path: "msedge.exe"}
	tuple := Tuple{Protocol: "tcp", Source: netip.MustParseAddrPort("127.0.0.1:3001"), Destination: netip.MustParseAddrPort("203.0.113.2:443")}
	d := Decision{Route: routing.Route{RelayID: "VPS-01"}, BlockOnFailure: true, Policy: flowpolicy.Result{Action: flowpolicy.RelayRequired, Fallback: flowpolicy.Required}}
	redirect := &tcpRedirect{b: b, state: newTCPState(16)}
	e := redirect.state.add(tuple, id, d, "relay", time.Now())
	e.local = local
	e.upstream = up
	b.evidence.BeginFlow(id, tuple)
	b.evidence.RecordPolicy(id, tuple, d, "")
	b.evidence.RecordUpstreamOpened(id, tuple, d.Route)
	redirect.wg.Add(1)
	t.Cleanup(func() {
		b.cancel()
		app.Close()
		local.Close()
		up.Close()
		target.Close()
		redirect.wg.Wait()
	})
	go redirect.pipe(e, local, up)
	go func() {
		data := make([]byte, 4)
		if _, err := io.ReadFull(target, data); err == nil {
			target.Write([]byte("pong"))
		}
		target.Close()
	}()
	app.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := app.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	response := make([]byte, 4)
	if _, err := io.ReadFull(app, response); err != nil || string(response) != "pong" {
		t.Fatal(err, string(response))
	}
	app.Close()
	captureWait(t, func() bool { redirect.state.mu.Lock(); defer redirect.state.mu.Unlock(); return e.mode == "closed" })
	for i := 0; i < 7; i++ {
		b.evidence.RecordDrop(id, tuple, tcpPacketDropCause(e.mode), false)
	}
	v := b.evidence.Snapshot(88).Flows[0]
	if v.Counters.RelayedBytes != 4 || v.Counters.ReplyBytes != 4 || v.Counters.Dropped != 7 {
		t.Fatal(v)
	}
	if broken {
		if v.Route != "BLOCK" || !v.RequiredBlocked || v.FailureCause != "TCP_RELAY_READ_FAILED" {
			t.Fatal(v)
		}
	} else if v.Route != "RELAY" || v.FailureCause != "" || v.RequiredBlocked {
		t.Fatal(v)
	}
}
