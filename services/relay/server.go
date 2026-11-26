// Package relay implements an authenticated, resource-bounded UDP/TCP forwarder.
package relay

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"errors"
	"fmt"
	"github.com/buzzmean/veliq/core/protocol"
	"github.com/buzzmean/veliq/core/security"
	"github.com/buzzmean/veliq/core/telemetry"
	"github.com/buzzmean/veliq/core/traffic"
	"github.com/buzzmean/veliq/core/transport"
	"github.com/quic-go/quic-go"
	"io"
	"net"
	"net/http"
	"net/netip"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

type Config struct {
	TLS                   *tls.Config
	MaxSessions, MaxFlows int
	IdleTimeout           time.Duration
	// TCPIdleTimeout applies to relayed TCP flows (ssh, websockets, game lobbies sit
	// idle far longer than UDP mappings). Defaults to 10 minutes. A flow holds one of
	// MaxFlows slots, so this stays bounded.
	TCPIdleTimeout   time.Duration
	Allow            []netip.Prefix
	PacketsPerSecond int
	TicketVerifier   *security.TicketVerifier
	Fleet            *FleetAdmission
	FleetObserve     bool
	Acceptance       *AcceptanceConfig
}

// AcceptanceConfig is only set by explicit in-process acceptance fixtures. No production CLI/env enables it.
type AcceptanceConfig struct {
	// Source interface for isolated route-discrimination fixtures; no CLI/env.
	OutboundSource  netip.Addr
	LeaseDuration   time.Duration
	DropRenewalACKs int
}

// UpstreamDialFailure retains only the latest bounded setup error, never payload.
// It separates actual target/socket failures from admission/session capacity.
type UpstreamDialFailure struct {
	At          time.Time `json:"at"`
	Protocol    string    `json:"protocol"`
	Destination string    `json:"destination"`
	Detail      string    `json:"detail"`
}

type Metrics struct {
	LastUpstreamDialFailure                                                          atomic.Pointer[UpstreamDialFailure]
	OpenRejected                                                                     [8]atomic.Uint64
	Renewals, RenewalRejected, LeaseExpiries, Revocations                            atomic.Uint64
	Sessions, Flows                                                                  atomic.Int64
	UDPPackets, TCPConnections, RXBytes, TXBytes, Drops, RejectedFlows, AuthFailures atomic.Uint64
	FleetPackets, FleetOpenAttempts, FleetHandshakeRejected, FleetOpenRejected       atomic.Uint64
	LocalDrops                                                                       telemetry.Counters
}
type Server struct {
	Traffic     func() []traffic.MonthRow
	listener    *quic.Listener
	config      Config
	Metrics     Metrics
	sem         chan struct{}
	mu          sync.Mutex
	connections map[*quic.Conn]struct{}
	wg          sync.WaitGroup
	done        chan struct{}
	once        sync.Once
	fleetSample fleetSampler
}

func Listen(addr string, c Config) (*Server, error) {
	if c.TLS == nil || c.TLS.ClientAuth != tls.RequireAndVerifyClientCert || c.TLS.ClientCAs == nil {
		return nil, errors.New("relay requires verified mutual TLS")
	}
	if c.MaxSessions <= 0 {
		c.MaxSessions = 128
	}
	if c.MaxFlows <= 0 {
		c.MaxFlows = 64
	}
	if c.MaxFlows > 64 {
		return nil, errors.New("max flows exceeds stream limit 64")
	}
	if c.IdleTimeout <= 0 {
		c.IdleTimeout = 60 * time.Second
		if c.TCPIdleTimeout <= 0 {
			c.TCPIdleTimeout = 10 * time.Minute
		}
	}
	if c.TCPIdleTimeout <= 0 {
		c.TCPIdleTimeout = c.IdleTimeout // explicit IdleTimeout keeps one value for both
	}
	if c.PacketsPerSecond <= 0 {
		c.PacketsPerSecond = 2000
	}
	if c.Acceptance != nil && (c.Acceptance.LeaseDuration <= 0 || c.Acceptance.LeaseDuration > 30*time.Minute) {
		return nil, errors.New("invalid explicit acceptance lease")
	}
	q := transport.QUICConfig()
	q.MaxIncomingStreams = int64(c.MaxFlows)
	if c.TicketVerifier != nil {
		q.MaxIncomingStreams++
	} // authentication handshake headroom; renewal uses bounded QUIC DATAGRAM control
	if c.TicketVerifier != nil {
		c.TLS = c.TLS.Clone()
		c.TLS.NextProtos = []string{protocol.LeaseALPN, protocol.TicketALPN}
	}
	if c.Fleet != nil && c.FleetObserve {
		return nil, errors.New("choose one fleet relay mode")
	}
	if c.FleetObserve && c.TicketVerifier == nil {
		return nil, errors.New("fleet observation requires an authenticated relay")
	}
	if c.Fleet != nil {
		if c.TicketVerifier == nil || c.TicketVerifier.Audience != c.Fleet.node {
			return nil, errors.New("fleet relay requires a matching ticket audience")
		}
		c.Fleet.bind(c.MaxSessions, c.MaxFlows)
		transportConfig := *q
		q.GetConfigForClient = func(*quic.ClientInfo) (*quic.Config, error) {
			if !c.Fleet.permitHandshake(time.Now()) {
				c.Fleet.earlyRejected.Add(1)
				return nil, errFleetAdmission
			}
			return &transportConfig, nil
		}
	}
	l, e := quic.ListenAddr(addr, c.TLS, q)
	if e != nil {
		return nil, e
	}
	s := &Server{listener: l, config: c, sem: make(chan struct{}, c.MaxSessions), connections: make(map[*quic.Conn]struct{}), done: make(chan struct{})}
	s.wg.Add(1)
	go s.accept()
	return s, nil
}
func (s *Server) Addr() net.Addr { return s.listener.Addr() }
func (s *Server) Close() error {
	s.once.Do(func() {
		close(s.done)
		s.listener.Close()
		s.mu.Lock()
		for c := range s.connections {
			c.CloseWithError(0, "shutdown")
		}
		s.mu.Unlock()
	})
	s.wg.Wait()
	return nil
}
func (s *Server) accept() {
	defer s.wg.Done()
	for {
		c, e := s.listener.Accept(context.Background())
		if e != nil {
			return
		}
		if s.config.Fleet != nil && !s.config.Fleet.admitting(time.Now()) {
			s.Metrics.FleetHandshakeRejected.Add(1)
			c.CloseWithError(2, "fleet admission")
			continue
		}
		select {
		case s.sem <- struct{}{}:
		default:
			c.CloseWithError(2, "capacity")
			continue
		}
		s.mu.Lock()
		select {
		case <-s.done:
			s.mu.Unlock()
			<-s.sem
			c.CloseWithError(0, "shutdown")
			return
		default:
		}
		s.connections[c] = struct{}{}
		s.wg.Add(1)
		s.mu.Unlock()
		s.Metrics.Sessions.Add(1)
		go func() {
			defer s.wg.Done()
			defer func() { s.mu.Lock(); delete(s.connections, c); s.mu.Unlock(); <-s.sem; s.Metrics.Sessions.Add(-1) }()
			x := &session{server: s, conn: c, flows: make(map[uint32]*flow), tokens: float64(s.config.PacketsPerSecond), refill: time.Now()}
			x.run()
		}()
	}
}

// Explicit CIDRs restrict deployment egress. Without them only globally routable unicast is allowed.
func (s *Server) allowed(a netip.Addr) bool {
	a = a.Unmap()
	if a.IsUnspecified() || a.IsMulticast() {
		return false
	}
	if len(s.config.Allow) > 0 {
		for _, p := range s.config.Allow {
			if p.Contains(a) {
				return true
			}
		}
		return false
	}
	if a.Is6() && !netip.MustParsePrefix("2000::/3").Contains(a) {
		return false
	}
	if !a.IsGlobalUnicast() || a.IsPrivate() || a.IsLoopback() || a.IsLinkLocalUnicast() {
		return false
	}
	for _, p := range reserved {
		if p.Contains(a) {
			return false
		}
	}
	return true
}

var reserved = []netip.Prefix{netip.MustParsePrefix("0.0.0.0/8"), netip.MustParsePrefix("100.64.0.0/10"), netip.MustParsePrefix("192.0.0.0/24"), netip.MustParsePrefix("192.0.2.0/24"), netip.MustParsePrefix("198.18.0.0/15"), netip.MustParsePrefix("198.51.100.0/24"), netip.MustParsePrefix("203.0.113.0/24"), netip.MustParsePrefix("240.0.0.0/4"), netip.MustParsePrefix("2001:db8::/32"), netip.MustParsePrefix("2001::/23"), netip.MustParsePrefix("3fff::/20"), netip.MustParsePrefix("192.88.99.0/24"), netip.MustParsePrefix("64:ff9b::/96"), netip.MustParsePrefix("2002::/16")}

type flow struct {
	udp    *net.UDPConn
	tcp    net.Conn
	stream *quic.Stream
	last   atomic.Int64
	once   sync.Once
}

func (f *flow) close() {
	f.once.Do(func() {
		if f.udp != nil {
			f.udp.Close()
		}
		if f.tcp != nil {
			f.tcp.Close()
		}
		f.stream.CancelRead(0)
		f.stream.Close()
	})
}

type session struct {
	control         chan []byte
	packetSequence  atomic.Uint32
	reassembly      protocol.Reassembly
	server          *Server
	conn            *quic.Conn
	mu              sync.Mutex
	flows           map[uint32]*flow
	wg              sync.WaitGroup
	tokens          float64
	refill          time.Time
	deviceID        string
	leaseExpires    time.Time
	peerKey         ed25519.PublicKey
	renewalSequence uint64
	renewalHash     [32]byte
	renewalReceipt  protocol.LeaseAck
	fleetRelease    func()
}

func (x *session) run() {
	defer func() {
		if x.fleetRelease != nil {
			x.fleetRelease()
		}
	}()
	if x.server.config.TicketVerifier != nil {
		if e := x.authenticate(); e != nil {
			x.server.Metrics.AuthFailures.Add(1)
			x.conn.CloseWithError(1, "ticket rejected")
			return
		}
	}
	x.wg.Add(2)
	go func() { defer x.wg.Done(); x.datagrams() }()
	go func() { defer x.wg.Done(); x.expire() }()
	for {
		s, e := x.conn.AcceptStream(context.Background())
		if e != nil {
			break
		}
		x.wg.Add(1)
		go func() { defer x.wg.Done(); x.open(s) }()
	}
	x.conn.CloseWithError(0, "session ended")
	x.mu.Lock()
	for _, f := range x.flows {
		f.close()
	}
	x.mu.Unlock()
	x.wg.Wait()
}
func (x *session) remove(id uint32, f *flow) {
	f.close()
	x.mu.Lock()
	if x.flows[id] == f {
		delete(x.flows, id)
		x.server.Metrics.Flows.Add(-1)
	}
	x.mu.Unlock()
}
func (x *session) open(s *quic.Stream) {
	s.SetDeadline(time.Now().Add(5 * time.Second))
	o, e := protocol.ReadOpen(s)
	if e != nil {
		s.CancelRead(1)
		s.CancelWrite(1)
		return
	}
	reject := func(code byte) {
		if int(code) < len(x.server.Metrics.OpenRejected) {
			x.server.Metrics.OpenRejected[code].Add(1)
		}
		x.server.Metrics.RejectedFlows.Add(1)
		s.Write([]byte{code})
		s.Close()
		s.CancelRead(1)
	}
	if !x.server.allowed(o.Destination.Addr()) {
		reject(2)
		return
	}
	f := &flow{stream: s}
	f.last.Store(time.Now().UnixNano())
	x.mu.Lock()
	if x.server.config.TicketVerifier != nil && (!time.Now().Before(x.leaseExpires) || x.server.config.TicketVerifier.Revoked(x.deviceID)) {
		x.mu.Unlock()
		reject(7)
		return
	}
	if len(x.flows) >= x.server.config.MaxFlows || x.flows[o.ID] != nil {
		x.mu.Unlock()
		reject(3)
		return
	}
	if x.server.config.Fleet != nil || x.server.config.FleetObserve {
		x.server.Metrics.FleetOpenAttempts.Add(1)
	}
	if gate := x.server.config.Fleet; gate != nil {
		release, code := gate.reserveFlow(x.deviceID, o.Destination, o.Kind, time.Now())
		if code != 0 {
			x.mu.Unlock()
			x.server.Metrics.FleetOpenRejected.Add(1)
			reject(code)
			return
		}
		defer release()
	}
	x.flows[o.ID] = f
	x.server.Metrics.Flows.Add(1)
	x.mu.Unlock()
	defer x.remove(o.ID, f)
	ctx, cancel := context.WithTimeout(x.conn.Context(), 3*time.Second)
	defer cancel()
	d := net.Dialer{}
	if a := x.server.config.Acceptance; a != nil && a.OutboundSource.IsLoopback() {
		if o.Kind == protocol.TCP {
			d.LocalAddr = &net.TCPAddr{IP: net.IP(a.OutboundSource.AsSlice())}
		} else {
			d.LocalAddr = &net.UDPAddr{IP: net.IP(a.OutboundSource.AsSlice())}
		}
	}
	c, e := d.DialContext(ctx, map[byte]string{protocol.UDP: "udp", protocol.TCP: "tcp"}[o.Kind], o.Destination.String())
	if e != nil {
		detail := e.Error()
		if len(detail) > 512 {
			detail = detail[:512]
		}
		x.server.Metrics.LastUpstreamDialFailure.Store(&UpstreamDialFailure{At: time.Now(), Protocol: map[byte]string{protocol.UDP: "udp", protocol.TCP: "tcp"}[o.Kind], Destination: o.Destination.String(), Detail: detail})
		code := byte(6)
		var ne net.Error
		if errors.As(e, &ne) && ne.Timeout() {
			code = 4
		} else if errors.Is(e, syscall.ECONNREFUSED) {
			code = 5
		}
		reject(code)
		return
	}
	x.mu.Lock()
	if x.conn.Context().Err() != nil {
		x.mu.Unlock()
		c.Close()
		return
	}
	if gate := x.server.config.Fleet; gate != nil && gate.flowPermission(x.deviceID, o.Destination, o.Kind, time.Now()) != 0 {
		x.mu.Unlock()
		c.Close()
		x.server.Metrics.FleetOpenRejected.Add(1)
		reject(3)
		return
	}
	if o.Kind == protocol.UDP {
		f.udp = c.(*net.UDPConn)
	} else {
		f.tcp = c
	}
	x.mu.Unlock()
	if _, e = s.Write([]byte{0}); e != nil {
		return
	}
	s.SetDeadline(time.Time{})
	if o.Kind == protocol.UDP {
		done := make(chan struct{})
		go func() { defer close(done); x.readUDP(o.ID, f) }()
		var b [1]byte
		_, _ = s.Read(b[:])
		f.close()
		<-done
	} else {
		x.server.Metrics.TCPConnections.Add(1)
		done := make(chan struct{})
		go func() {
			defer close(done)
			_, _ = io.Copy(activityWriter{s, &f.last, &x.server.Metrics.TXBytes}, c)
			s.Close()
		}()
		_, _ = io.Copy(activityWriter{c, &f.last, &x.server.Metrics.RXBytes}, s)
		if t, ok := c.(*net.TCPConn); ok {
			t.CloseWrite()
		}
		<-done
	}
}

type activityWriter struct {
	io.Writer
	last    *atomic.Int64
	counter *atomic.Uint64
}

func (w activityWriter) Write(b []byte) (int, error) {
	n, e := w.Writer.Write(b)
	if n > 0 {
		w.last.Store(time.Now().UnixNano())
		if w.counter != nil {
			w.counter.Add(uint64(n))
		}
	}
	return n, e
}
func (x *session) readUDP(id uint32, f *flow) {
	defer f.close()
	b := make([]byte, protocol.MaxPayload+1)
	for {
		n, e := f.udp.Read(b)
		x.server.Metrics.LocalDrops.Attempt(telemetry.CaptureProcessing)
		if e != nil {
			return
		}
		if n > protocol.MaxPayload {
			x.server.Metrics.Drops.Add(1)
			x.server.Metrics.LocalDrops.Drop(telemetry.CaptureProcessing)
			continue
		}
		f.last.Store(time.Now().UnixNano())
		parts, _ := protocol.EncodeDatagrams(id, x.packetSequence.Add(1), b[:n])
		x.server.Metrics.LocalDrops.Attempt(telemetry.SocketSend)
		for _, p := range parts {
			if x.server.config.Fleet != nil || x.server.config.FleetObserve {
				x.server.Metrics.FleetPackets.Add(1)
			}
			if gate := x.server.config.Fleet; gate != nil && !gate.permitPacket(time.Now()) {
				e = errFleetAdmission
				break
			}
			if e = x.conn.SendDatagram(p); e != nil {
				break
			}
		}
		if e != nil {
			x.server.Metrics.Drops.Add(1)
			x.server.Metrics.LocalDrops.Drop(telemetry.SocketSend)
		} else {
			x.server.Metrics.TXBytes.Add(uint64(n))
		}
	}
}
func (x *session) datagrams() {
	for {
		b, e := x.conn.ReceiveDatagram(context.Background())
		if e != nil {
			return
		}
		if x.control != nil && len(b) >= 12 && len(b) <= 1035 && b[0] == protocol.LeaseRequestDatagram {
			// Independent bounded control inbox; application flow saturation cannot
			// consume its stream credit, reassembly state, or worker capacity.
			select {
			case x.control <- append([]byte(nil), b...):
			default:
			}
			continue
		}
		if x.server.config.Fleet != nil || x.server.config.FleetObserve {
			x.server.Metrics.FleetPackets.Add(1)
		}
		if gate := x.server.config.Fleet; gate != nil && !gate.permitPacket(time.Now()) {
			x.server.Metrics.Drops.Add(1)
			x.server.Metrics.LocalDrops.Attempt(telemetry.Policy)
			x.server.Metrics.LocalDrops.Drop(telemetry.Policy)
			continue
		}
		x.server.Metrics.LocalDrops.Attempt(telemetry.Decode)
		x.server.Metrics.LocalDrops.Attempt(telemetry.UnknownFlow)
		id, p, e := x.reassembly.Decode(b, time.Now())
		if e != nil {
			x.server.Metrics.Drops.Add(1)
			x.server.Metrics.LocalDrops.Drop(telemetry.Decode)
			continue
		}
		if p == nil {
			continue
		}
		now := time.Now()
		dt := now.Sub(x.refill).Seconds()
		x.refill = now
		x.tokens += dt * float64(x.server.config.PacketsPerSecond)
		if x.tokens > float64(x.server.config.PacketsPerSecond) {
			x.tokens = float64(x.server.config.PacketsPerSecond)
		}
		x.server.Metrics.LocalDrops.Attempt(telemetry.Policy)
		if x.tokens < 1 {
			x.server.Metrics.Drops.Add(1)
			x.server.Metrics.LocalDrops.Drop(telemetry.Policy)
			continue
		}
		x.tokens--
		x.mu.Lock()
		f := x.flows[id]
		var c *net.UDPConn
		if f != nil {
			c = f.udp
		}
		x.mu.Unlock()
		if c == nil {
			x.server.Metrics.Drops.Add(1)
			x.server.Metrics.LocalDrops.Drop(telemetry.UnknownFlow)
			continue
		}
		c.SetWriteDeadline(time.Now().Add(20 * time.Millisecond))
		x.server.Metrics.LocalDrops.Attempt(telemetry.SocketSend)
		if _, e = c.Write(p); e != nil {
			x.server.Metrics.Drops.Add(1)
			x.server.Metrics.LocalDrops.Drop(telemetry.SocketSend)
			continue
		}
		f.last.Store(now.UnixNano())
		x.server.Metrics.UDPPackets.Add(1)
		x.server.Metrics.RXBytes.Add(uint64(len(p)))
	}
}
func (x *session) expire() {
	interval := x.server.config.IdleTimeout / 4
	if interval < time.Millisecond {
		interval = time.Millisecond
	}
	if x.server.config.Acceptance != nil && interval > x.server.config.Acceptance.LeaseDuration/20 {
		interval = x.server.config.Acceptance.LeaseDuration / 20
	}
	if interval > time.Second {
		interval = time.Second
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-x.conn.Context().Done():
			return
		case now := <-t.C:
			x.mu.Lock()
			if x.server.config.TicketVerifier != nil {
				revoked := x.server.config.TicketVerifier.Revoked(x.deviceID)
				expired := !now.Before(x.leaseExpires)
				if revoked || expired {
					code := quic.ApplicationErrorCode(protocol.LeaseExpiredCode)
					reason := "authorization_lease_expired"
					if revoked {
						code = protocol.RevokedCode
						reason = "device_revoked"
						x.server.Metrics.Revocations.Add(1)
					} else {
						x.server.Metrics.LeaseExpiries.Add(1)
					}
					x.conn.CloseWithError(code, reason)
					x.mu.Unlock()
					return
				}
			}
			x.mu.Unlock()
			x.mu.Lock()
			for _, f := range x.flows {
				idle := now.Sub(time.Unix(0, f.last.Load()))
				if (f.udp != nil && idle > x.server.config.IdleTimeout) || (f.tcp != nil && idle > x.server.config.TCPIdleTimeout) {
					f.close()
				}
			}
			x.mu.Unlock()
		}
	}
}
func (s *Server) Handler() http.Handler {
	m := http.NewServeMux()
	m.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-s.done:
			http.Error(w, "stopped", 503)
		default:
			w.Write([]byte("ok\n"))
		}
	})
	m.HandleFunc("/metrics", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4")
		if s.Traffic != nil {
			for _, v := range s.Traffic() {
				fmt.Fprintf(w, "neexitlag_interface_month_egress_bytes{relay=%q,month=%q} %d\nneexitlag_interface_month_forecast_bytes{relay=%q,month=%q} %d\n", v.Relay, v.Month, v.Bytes, v.Relay, v.Month, v.Forecast)
			}
		}
		for code := byte(1); code < 8; code++ {
			fmt.Fprintf(w, "neexitlag_open_rejected_total{reason=%q} %d\n", protocol.OpenRejection(code), s.Metrics.OpenRejected[code].Load())
		}
		fmt.Fprintf(w, "neexitlag_lease_renewals_total %d\nneexitlag_lease_renewal_rejected_total %d\nneexitlag_lease_expiries_total %d\nneexitlag_revocations_total %d\n", s.Metrics.Renewals.Load(), s.Metrics.RenewalRejected.Load(), s.Metrics.LeaseExpiries.Load(), s.Metrics.Revocations.Load())
		fmt.Fprintf(w, "neexitlag_relay_health 1\nneexitlag_active_sessions %d\nneexitlag_active_flows %d\nneexitlag_udp_packets_total %d\nneexitlag_tcp_connections_total %d\nneexitlag_rx_bytes_total %d\nneexitlag_tx_bytes_total %d\nneexitlag_packet_drops_total %d\nneexitlag_rejected_flows_total %d\nneexitlag_auth_failures_total %d\n", s.Metrics.Sessions.Load(), s.Metrics.Flows.Load(), s.Metrics.UDPPackets.Load(), s.Metrics.TCPConnections.Load(), s.Metrics.RXBytes.Load(), s.Metrics.TXBytes.Load(), s.Metrics.Drops.Load(), s.Metrics.RejectedFlows.Load(), s.Metrics.AuthFailures.Load())
		if gate := s.config.Fleet; gate != nil || s.config.FleetObserve {
			rejected := s.Metrics.FleetHandshakeRejected.Load()
			if gate != nil {
				rejected += gate.earlyRejected.Load()
				fmt.Fprintf(w, "neexitlag_fleet_applied_registry_version %d\n", gate.Version())
			}
			fmt.Fprintf(w, "neexitlag_fleet_new_open_attempts_total %d\nneexitlag_fleet_new_open_rejected_total %d\nneexitlag_fleet_handshake_rejected_total %d\nneexitlag_fleet_udp_packet_events_total %d\n",
				s.Metrics.FleetOpenAttempts.Load(), s.Metrics.FleetOpenRejected.Load(), rejected, s.Metrics.FleetPackets.Load())
		}
		for name, metric := range s.Metrics.LocalDrops.Snapshot() {
			fmt.Fprintf(w, "neexitlag_relay_%s_total %d\n", name, metric.Count)
		}
	})
	return m
}
