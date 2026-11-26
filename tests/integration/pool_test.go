package integration

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/buzzmean/veliq/core/routing"
	"github.com/buzzmean/veliq/core/security"
	"github.com/buzzmean/veliq/core/telemetry"
	"github.com/buzzmean/veliq/core/transport"
	"github.com/buzzmean/veliq/services/relay"
	"github.com/buzzmean/veliq/tools/echo"
	"github.com/buzzmean/veliq/tools/labcert"
)

type poolFixture struct {
	pool     *transport.Pool
	server   *relay.Server
	tcp, udp netip.AddrPort
	mu       sync.Mutex
	clients  []*transport.Client
	tickets  [][]byte
	dial     func(context.Context, []byte) (*transport.Client, error)
	issued   atomic.Int64
	factory  transport.SessionFactory
}

func newPoolFixture(t *testing.T, cfg transport.PoolConfig, mutate func(*transport.Client, int) error) *poolFixture {
	return newRenewingPoolFixture(t, cfg, mutate, 0)
}

func newRenewingPoolFixture(t *testing.T, cfg transport.PoolConfig, mutate func(*transport.Client, int) error, lease time.Duration) *poolFixture {
	t.Helper()
	st, ct, err := labcert.Pair()
	if err != nil {
		t.Fatal(err)
	}
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	v := security.NewTicketVerifier(map[string]ed25519.PublicKey{"test": pub}, "VPS-01")
	serverConfig := relay.Config{TLS: st, TicketVerifier: v, Allow: []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")}}
	if lease > 0 {
		serverConfig.Acceptance = &relay.AcceptanceConfig{LeaseDuration: lease}
	}
	r, err := relay.Listen("127.0.0.1:0", serverConfig)
	if err != nil {
		t.Fatal(err)
	}
	x := &poolFixture{server: r}
	t.Cleanup(func() { r.Close() })
	tcp, tc, err := echo.TCP()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(tc)
	x.tcp = netip.MustParseAddrPort(tcp.String())
	udp, uc, err := echo.UDP()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(uc)
	x.udp = netip.MustParseAddrPort(udp.String())
	peer := ct.Certificates[0].PrivateKey.(ed25519.PrivateKey).Public().(ed25519.PublicKey)
	x.dial = func(ctx context.Context, raw []byte) (*transport.Client, error) {
		return transport.DialWithTicket(ctx, r.Addr().String(), ct, raw)
	}
	issue := func(context.Context) ([]byte, error) {
		id, _ := security.NewID()
		now := time.Now()
		return security.Sign("ticket", "test", key, security.Ticket{ID: id, DeviceID: "device", DeviceKey: security.Fingerprint(peer), RelayID: "VPS-01", IssuedAt: now, ExpiresAt: now.Add(time.Minute)})
	}
	x.factory = func(ctx context.Context) (*transport.Client, error) {
		n := int(x.issued.Add(1))
		raw, err := issue(ctx)
		if err != nil {
			return nil, err
		}
		c, err := x.dial(ctx, raw)
		if err != nil {
			return nil, err
		}
		if lease > 0 {
			c.StartRenewal(issue)
		}
		if mutate != nil {
			if err = mutate(c, n); err != nil {
				c.Close()
				return nil, err
			}
		}
		x.mu.Lock()
		x.clients = append(x.clients, c)
		x.tickets = append(x.tickets, raw)
		x.mu.Unlock()
		return c, nil
	}
	p, err := transport.NewPool(context.Background(), cfg, x.factory)
	if err != nil {
		t.Fatal(err)
	}
	x.pool = p
	t.Cleanup(func() { p.Close() })
	return x
}
func assertTCPEcho(t *testing.T, c net.Conn) {
	t.Helper()
	c.SetDeadline(time.Now().Add(2 * time.Second))
	want := []byte("session-isolated-real-echo")
	if _, err := c.Write(want); err != nil {
		t.Fatal(err)
	}
	b := make([]byte, len(want))
	if _, err := io.ReadFull(c, b); err != nil || string(b) != string(want) {
		t.Fatal(string(b), err)
	}
	c.SetDeadline(time.Time{})
}

// Local authenticated relay stress, not simultaneous Windows/Internet acceptance.
func TestPool160SimultaneousRequiredFlowsAndFreshTickets(t *testing.T) {
	x := newPoolFixture(t, transport.DefaultPoolConfig(), nil)
	e := routing.New(512)
	e.SetRelay("VPS-01", x.pool)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	all := make([]io.Closer, 160)
	errs := make(chan error, 160)
	var wg sync.WaitGroup
	for i := range all {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			dst := x.tcp
			udp := i%4 == 0
			if udp {
				dst = x.udp
			}
			f := routing.Flow{PID: uint32(i%4 + 1), ProcessPath: fmt.Sprintf("app-%d.exe", i%4), ApplicationID: fmt.Sprintf("app-%d", i%4), Source: netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(20000+i)), Destination: dst, PinnedPolicy: &routing.Policy{Route: routing.Route{RelayID: "VPS-01"}, BlockOnFailure: true}}
			if udp {
				d, err := e.OpenUDP(ctx, f)
				if err != nil {
					errs <- err
					return
				}
				all[i] = d
				if err = d.Send([]byte("real-UDP")); err != nil {
					errs <- err
					return
				}
				b, err := d.Receive(ctx)
				if err != nil || string(b) != "real-UDP" {
					errs <- fmt.Errorf("UDP: %q %v", b, err)
				}
			} else {
				c, err := e.OpenTCP(ctx, f)
				if err != nil {
					errs <- err
					return
				}
				all[i] = c
				c.SetDeadline(time.Now().Add(5 * time.Second))
				_, err = c.Write([]byte("hello"))
				if err == nil {
					b := make([]byte, 5)
					_, err = io.ReadFull(c, b)
					if err == nil && string(b) != "hello" {
						err = errors.New("wrong TCP echo")
					}
				}
				if err != nil {
					errs <- err
				}
			}
		}(i)
	}
	wg.Wait()
	close(errs)
	for _, c := range all {
		if c != nil {
			defer c.Close()
		}
	}
	for err := range errs {
		t.Error(err)
	}
	if t.Failed() {
		return
	}
	s := x.pool.Snapshot()
	if s.ActiveFlows != 160 || s.HealthySessions < 4 || s.ActiveSessions > 8 || s.OpenFailures != 0 || x.server.Metrics.RejectedFlows.Load() != 0 {
		t.Fatal(s)
	}
	for _, session := range s.Sessions {
		if session.ActiveFlows > 48 {
			t.Fatal("per-session bound exceeded", session)
		}
	}
	for _, f := range e.Snapshot() {
		if f.Route.RelayID != "VPS-01" {
			t.Fatal("required flow leaked", f)
		}
	}
	if got := len(e.Snapshot()); got != 160 {
		t.Fatal("lost flow", got)
	}
	x.mu.Lock()
	raws := append([][]byte(nil), x.tickets...)
	x.mu.Unlock()
	if len(raws) != s.ActiveSessions || int(x.issued.Load()) != len(raws) {
		t.Fatal("fresh ticket per session missing")
	}
	for _, raw := range raws {
		if c, err := x.dial(ctx, raw); err == nil {
			c.Close()
			t.Fatal("one-shot ticket replay accepted")
		}
	}
	for _, c := range all {
		c.Close()
	}
	if x.pool.Snapshot().ActiveFlows != 0 {
		t.Fatal("lease cleanup leak")
	}
	t.Logf("160 held required flows, %d authenticated sessions, 0 open failures/rejections; replay rejected for every session", s.ActiveSessions)
}
func TestPoolSingleSessionFailureIsolatedAndRequiredCapacityClosed(t *testing.T) {
	cfg := transport.DefaultPoolConfig()
	cfg.MaxSessions = 3
	cfg.SessionFlows = 2
	cfg.ProbeReserve = 0
	x := newPoolFixture(t, cfg, nil)
	var poisoned atomic.Int32
	x.pool.SetFailureHandler(func(string) { poisoned.Add(1) })
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	flows := make([]net.Conn, 6)
	for i := range flows {
		c, err := x.pool.OpenTCP(ctx, x.tcp)
		if err != nil {
			t.Fatal(err)
		}
		flows[i] = c
		defer c.Close()
		assertTCPEcho(t, c)
	}
	start := time.Now()
	if c, err := x.pool.OpenTCP(ctx, x.tcp); !errors.Is(err, transport.ErrCapacity) {
		if c != nil {
			c.Close()
		}
		t.Fatal("hard cap ignored", err)
	}
	if time.Since(start) > time.Second {
		t.Fatal("capacity waited instead of bounded rejection")
	}
	e := routing.New(4)
	e.SetRelay("VPS-01", x.pool)
	required := routing.Flow{PID: 123, ProcessPath: "protected.exe", ApplicationID: "protected", Source: netip.MustParseAddrPort("127.0.0.1:29999"), Destination: x.tcp, PinnedPolicy: &routing.Policy{Route: routing.Route{RelayID: "VPS-01"}, BlockOnFailure: true}}
	if leaked, err := e.OpenTCP(ctx, required); !errors.Is(err, transport.ErrCapacity) {
		if leaked != nil {
			leaked.Close()
		}
		t.Fatal("capacity failed open DIRECT", err)
	}
	if len(e.Snapshot()) != 0 {
		t.Fatal("failed required reservation retained")
	}
	x.mu.Lock()
	first := x.clients[0]
	x.mu.Unlock()
	first.Close()
	<-first.Done()
	for i := 2; i < 6; i++ {
		assertTCPEcho(t, flows[i])
	}
	// The failed session's flows stay failed rather than being replayed/migrated.
	flows[0].SetDeadline(time.Now().Add(time.Second))
	if _, err := flows[0].Read(make([]byte, 1)); err == nil {
		t.Fatal("dead flow revived")
	}
	c, err := x.pool.OpenTCP(ctx, x.tcp)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	assertTCPEcho(t, c)
	if poisoned.Load() != 0 {
		t.Fatal("one failed/saturated session poisoned entire relay")
	}
	if s := x.pool.Snapshot(); s.HealthySessions != 3 || s.SessionFailures != 1 || s.ActiveSessions > 3 {
		t.Fatal(s)
	}
}
func TestPoolSaturatedQUICCreditSelectsAnotherSession(t *testing.T) {
	var held []*transport.UDPFlow
	cfg := transport.DefaultPoolConfig()
	cfg.MaxSessions = 3
	x := newPoolFixture(t, cfg, func(c *transport.Client, n int) error {
		if n != 1 {
			return nil
		}
		deadline := time.Now().Add(2 * time.Second)
		for len(held) < 64 {
			f, err := c.OpenUDP(context.Background(), netip.MustParseAddrPort("127.0.0.1:19001"))
			if errors.Is(err, transport.ErrCapacity) && time.Now().Before(deadline) {
				time.Sleep(time.Millisecond)
				continue
			}
			if err != nil {
				return err
			}
			held = append(held, f)
		}
		return nil
	})
	defer func() {
		for _, f := range held {
			f.Close()
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := x.pool.Warm(ctx); err != nil {
		t.Fatal(err)
	}
	var poisoned atomic.Int32
	x.pool.SetFailureHandler(func(string) { poisoned.Add(1) })
	c, err := x.pool.OpenTCP(ctx, x.tcp)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	assertTCPEcho(t, c)
	s := x.pool.Snapshot()
	if s.HealthySessions != 2 || s.StreamCapacityEvents == 0 || s.OpenFailures != 0 || poisoned.Load() != 0 {
		t.Fatal(s, poisoned.Load())
	}
}
func TestPoolRenewableSessionIsNotDrainedByAdmissionAge(t *testing.T) {
	cfg := transport.DefaultPoolConfig()
	cfg.MaxSessions = 3
	cfg.RotateAfter = 500 * time.Millisecond
	x := newPoolFixture(t, cfg, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, err := x.pool.OpenTCP(ctx, x.tcp)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	assertTCPEcho(t, c)
	time.Sleep(550 * time.Millisecond)
	next, err := x.pool.OpenTCP(ctx, x.tcp)
	if err != nil {
		t.Fatal(err)
	}
	defer next.Close()
	assertTCPEcho(t, next)
	assertTCPEcho(t, c)
	s := x.pool.Snapshot()
	if s.ActiveSessions != 1 || s.Sessions[0].Draining || s.Sessions[0].ActiveFlows != 2 {
		t.Fatal(s)
	}
}
func TestClient64StreamCeilingIsExplicit(t *testing.T) {
	_, c, _ := setup(t, 10*time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var held []*transport.UDPFlow
	defer func() {
		for _, f := range held {
			f.Close()
		}
	}()
	for i := 0; i < 64; i++ {
		f, err := c.OpenUDP(ctx, netip.MustParseAddrPort("127.0.0.1:19002"))
		if err != nil {
			t.Fatal(i, err)
		}
		held = append(held, f)
	}
	start := time.Now()
	if f, err := c.OpenUDP(ctx, netip.MustParseAddrPort("127.0.0.1:19002")); !errors.Is(err, transport.ErrCapacity) {
		if f != nil {
			f.Close()
		}
		t.Fatal(err)
	}
	if time.Since(start) > time.Second {
		t.Fatal("single session blocked behind credit")
	}
}

func TestPoolProbeSessionFailureDoesNotPoisonHealthyPeer(t *testing.T) {
	cfg := transport.DefaultPoolConfig()
	cfg.SessionFlows = 1
	cfg.ProbeReserve = 0
	cfg.MaxSessions = 3
	x := newPoolFixture(t, cfg, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	probe, err := x.pool.OpenProbeDatagram(ctx, x.udp)
	if err != nil {
		t.Fatal(err)
	}
	defer probe.Close()
	peer, err := x.pool.OpenTCP(ctx, x.tcp)
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	x.mu.Lock()
	failed := x.clients[0]
	x.mu.Unlock()
	failed.Close()
	<-failed.Done()
	if _, err = probe.Receive(ctx); !errors.Is(err, telemetry.ErrIsolatedSession) {
		t.Fatal("failed probe session misattributed to whole VPS", err)
	}
	assertTCPEcho(t, peer)
}

func TestPoolReservesRealProbeCapacityAtApplicationSaturation(t *testing.T) {
	cfg := transport.DefaultPoolConfig()
	cfg.MaxSessions = 1
	x := newPoolFixture(t, cfg, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var held []routing.Datagram
	defer func() {
		for _, d := range held {
			d.Close()
		}
	}()
	for i := 0; i < 47; i++ {
		d, err := x.pool.OpenDatagram(ctx, x.udp)
		if err != nil {
			t.Fatal(i, err)
		}
		held = append(held, d)
	}
	if d, err := x.pool.OpenDatagram(ctx, x.udp); !errors.Is(err, transport.ErrCapacity) {
		if d != nil {
			d.Close()
		}
		t.Fatal("application reserve ignored", err)
	}
	probe, err := x.pool.OpenProbeDatagram(ctx, x.udp)
	if err != nil {
		t.Fatal("saturation starved health probe", err)
	}
	defer probe.Close()
	if err = probe.Send([]byte("healthy")); err != nil {
		t.Fatal(err)
	}
	b, err := probe.Receive(ctx)
	if err != nil || string(b) != "healthy" {
		t.Fatal(string(b), err)
	}
	if s := x.pool.Snapshot(); s.ActiveFlows != 48 || s.AvailableCapacity != 0 || s.ApplicationMaximumCapacity != 47 || s.MaximumCapacity != 48 {
		t.Fatal(s)
	}
}

func TestPoolSingleFlightCreationSurvivesOneCallerCancellation(t *testing.T) {
	cfg := transport.DefaultPoolConfig()
	cfg.MaxSessions = 2
	entered := make(chan struct{})
	gate := make(chan struct{})
	var once sync.Once
	defer once.Do(func() { close(gate) })
	x := newPoolFixture(t, cfg, func(_ *transport.Client, n int) error {
		if n == 1 {
			close(entered)
			<-gate
		}
		return nil
	})
	first, cancel := context.WithCancel(context.Background())
	defer cancel()
	firstDone := make(chan error, 1)
	go func() {
		d, err := x.pool.OpenDatagram(first, x.udp)
		if d != nil {
			d.Close()
		}
		firstDone <- err
	}()
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("session creation did not begin")
	}
	secondDone := make(chan error, 1)
	go func() {
		ctx, stop := context.WithTimeout(context.Background(), 3*time.Second)
		defer stop()
		d, err := x.pool.OpenDatagram(ctx, x.udp)
		if d != nil {
			d.Close()
		}
		secondDone <- err
	}()
	cancel()
	select {
	case err := <-firstDone:
		if !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("cancelled caller stuck")
	}
	once.Do(func() { close(gate) })
	if err := <-secondDone; err != nil {
		t.Fatal("one caller cancelled shared creation", err)
	}
	if x.issued.Load() != 1 {
		t.Fatal("creation was not single-flight", x.issued.Load())
	}
}

func TestPoolTCPBurstContinuity(t *testing.T) {
	for _, count := range []int{160, 256, 320} {
		t.Run(fmt.Sprint(count), func(t *testing.T) {
			x := newPoolFixture(t, transport.DefaultPoolConfig(), nil)
			e := routing.New(1024)
			e.SetRelay("VPS-01", x.pool)
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			conns := make([]net.Conn, count)
			errs := make(chan error, count)
			// Match production Windows admission: all requests start together,
			// but at most 128 perform upstream setup. The pool deliberately
			// retains its bounded 256-waiter contract even for a 320-flow burst.
			setup := make(chan struct{}, 128)
			var wg sync.WaitGroup
			for i := range conns {
				wg.Add(1)
				go func(i int) {
					defer wg.Done()
					select {
					case setup <- struct{}{}:
					case <-ctx.Done():
						errs <- ctx.Err()
						return
					}
					c, err := e.OpenTCP(ctx, routing.Flow{PID: uint32(i%4 + 1), ApplicationID: fmt.Sprintf("app-%d", i%4), ProcessPath: fmt.Sprintf("app-%d.exe", i%4), Source: netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(30000+i)), Destination: x.tcp, PinnedPolicy: &routing.Policy{Route: routing.Route{RelayID: "VPS-01"}, BlockOnFailure: true}})
					if err != nil {
						<-setup
						errs <- err
						return
					}
					conns[i] = c
					// OPEN ACK is the relay's connect completion, not proof
					// that the target has accepted/readied the socket. A fast
					// zero-RTT Windows echo target otherwise overflows its
					// SOMAXCONN implementation-defined pending-accept backlog.
					// Require real initial application I/O before releasing
					// the test setup window. No retries or discarded failures.
					c.SetDeadline(time.Now().Add(5 * time.Second))
					want := []byte("initial-application-ready")
					if _, err = c.Write(want); err == nil {
						got := make([]byte, len(want))
						_, err = io.ReadFull(c, got)
						if err == nil && string(got) != string(want) {
							err = fmt.Errorf("wrong first application reply: %q", got)
						}
					}
					<-setup
					if err != nil {
						errs <- err
					}
				}(i)
			}
			wg.Wait()
			close(errs)
			defer func() {
				for _, c := range conns {
					if c != nil {
						c.Close()
					}
				}
			}()
			for err := range errs {
				t.Error(err)
			}
			if t.Failed() {
				t.Logf("last relay upstream dial failure: %+v", x.server.Metrics.LastUpstreamDialFailure.Load())
				return
			}
			// Preserve exactly these sockets while filling every other session; repeat
			// traffic after full saturation, not just successful initial OPEN replies.
			for round := 0; round < 3; round++ {
				for _, c := range conns {
					assertTCPEcho(t, c)
				}
			}
			flows := e.Snapshot()
			if len(flows) != count {
				t.Fatal("established connections lost", len(flows))
			}
			for _, f := range flows {
				if f.Route.RelayID != "VPS-01" {
					t.Fatal("DIRECT leak", f)
				}
			}
			s := x.pool.Snapshot()
			if s.ActiveFlows != count || s.OpenFailures != 0 || s.ActiveSessions > 8 || s.ProbeReservePerSession != 1 || s.ApplicationMaximumCapacity != 376 || x.server.Metrics.RejectedFlows.Load() != 0 {
				t.Fatal(s)
			}
			for _, session := range s.Sessions {
				if session.ActiveFlows > 47 {
					t.Fatal("probe reserve consumed", session)
				}
			}
			t.Logf("%d exact TCP sockets retained across 3 bidirectional rounds, %d sessions, no rejects/leaks", count, s.ActiveSessions)
		})
	}
}
