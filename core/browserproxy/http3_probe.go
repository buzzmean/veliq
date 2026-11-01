package browserproxy

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/buzzmean/neexitlag/core/originpolicy"
	quic "github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

const HTTP3ProbeTimeout = 6 * time.Second
const HTTP3ProbeSampleBytes = 32*1024 + 1
const HTTP3ProbeReceiveLimit = 256 * 1024
const HTTP3ProbeSendLimit = 64 * 1024
const HTTP3ProbeReceivePackets = 256
const HTTP3ProbeSendPackets = 128

// The caller supplies the reviewed origin and its pinned IP. This does not bind
// the same hostname to any encrypted browser QUIC flow or authorize its route.
type HTTP3ProbeKey struct {
	Host, Network, Profile, Revision, Executable string
	Endpoint                                     netip.AddrPort
	PID                                          uint32
	Birth                                        uint64
}
type HTTP3ProbeSocket interface {
	net.PacketConn
	ScopeMatches(HTTP3ProbeKey) bool
	Committed() bool
}
type HTTP3ProbeResult struct {
	Outcome                                   string
	Status                                    int
	ALPN                                      string
	TLSVersion                                uint16
	VerifiedTLS, TransformCommitted, Observed bool
	BodyBytes, ReceivedBytes, SentBytes       uint64
	ReceivedPackets, SentPackets              uint64
}

// One running probe, no queue, automatic retries or positive route cache.
// A service should own one manager and also acquire its shared probe budget.
type HTTP3ProbeManager struct {
	mu             sync.Mutex
	ctx            context.Context
	cancel         context.CancelFunc
	active, closed bool
	workers        sync.WaitGroup
}

func NewHTTP3ProbeManager() *HTTP3ProbeManager {
	ctx, cancel := context.WithCancel(context.Background())
	return &HTTP3ProbeManager{ctx: ctx, cancel: cancel}
}
func (m *HTTP3ProbeManager) Close() {
	m.mu.Lock()
	m.closed = true
	m.cancel()
	m.mu.Unlock()
	m.workers.Wait()
}

func validHTTP3ProbeKey(k HTTP3ProbeKey) bool {
	return ValidPublicDNSName(k.Host) && originpolicy.Floor(k.Host).Kind == "DPI" && k.Endpoint.Port() == 443 && k.Endpoint.Addr().Is4() && PublicDNSAddress(k.Endpoint.Addr()) && k.PID != 0 && k.Birth != 0 && k.Executable != "" && len(k.Executable) <= 2048 && k.Network != "" && len(k.Network) <= 256 && k.Profile != "" && len(k.Profile) <= 128 && k.Revision != "" && len(k.Revision) <= 128
}

// Probe performs one credential-free GET / over one authenticated QUIC v1
// connection. current must be a fast, concurrency-safe scope check. open owns
// one new connected socket, respects ctx, and commits its exact decoy plan.
// RootCAs nil uses system trust; callers cannot disable certificate validation.
func (m *HTTP3ProbeManager) Probe(parent context.Context, key HTTP3ProbeKey, roots *x509.CertPool, current func(HTTP3ProbeKey) bool, open func(context.Context) (HTTP3ProbeSocket, error)) (r HTTP3ProbeResult) {
	r.Outcome = "HTTP3_SCOPE_INVALID"
	if !validHTTP3ProbeKey(key) || current == nil || open == nil {
		return
	}
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		r.Outcome = "HTTP3_MANAGER_CLOSED"
		return
	}
	if m.active {
		m.mu.Unlock()
		r.Outcome = "HTTP3_BUSY"
		return
	}
	m.active = true
	m.workers.Add(1)
	m.mu.Unlock()
	defer func() { m.mu.Lock(); m.active = false; m.mu.Unlock(); m.workers.Done() }()
	ctx, cancel := context.WithTimeout(parent, HTTP3ProbeTimeout)
	stop := context.AfterFunc(m.ctx, cancel)
	var stale atomic.Bool
	watchDone := make(chan struct{})
	go func() {
		defer close(watchDone)
		ticker := time.NewTicker(50 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if !current(key) {
					stale.Store(true)
					cancel()
					return
				}
			}
		}
	}()
	defer func() { stop(); cancel(); <-watchDone }()
	defer func() {
		if stale.Load() || !current(key) {
			r.Outcome = "HTTP3_SCOPE_CHANGED"
			r.Observed = false
			r.TransformCommitted = false
		} else if ctx.Err() != nil {
			r.Outcome = "HTTP3_CANCELED_OR_TIMEOUT"
			r.Observed = false
		}
	}()
	if ctx.Err() != nil || !current(key) {
		r.Outcome = "HTTP3_SCOPE_CHANGED"
		return
	}
	socket, err := open(ctx)
	if err != nil || socket == nil {
		r.Outcome = "HTTP3_SOCKET_OPEN_FAILED"
		return
	}
	defer socket.Close()
	if !socket.ScopeMatches(key) {
		r.Outcome = "HTTP3_SOCKET_SCOPE_MISMATCH"
		return
	}
	stopSocket := context.AfterFunc(ctx, func() { socket.Close() })
	defer stopSocket()
	if ctx.Err() != nil || !current(key) {
		r.Outcome = "HTTP3_SCOPE_CHANGED"
		return
	}
	meter := &http3ProbeMeter{PacketConn: socket, peer: key.Endpoint}
	defer func() {
		r.ReceivedBytes = meter.received.Load()
		r.SentBytes = meter.sent.Load()
		r.ReceivedPackets = meter.receivedPackets.Load()
		r.SentPackets = meter.sentPackets.Load()
		if meter.limited.Load() {
			r.Outcome = "HTTP3_DATAGRAM_BUDGET"
			r.Observed = false
		}
	}()
	transport := &quic.Transport{Conn: meter}
	defer transport.Close()
	defer func() {
		// Capture send evidence before closing the owned socket, also on TLS or
		// HTTP failures. A committed send alone never makes Observed true.
		r.TransformCommitted = socket.Committed()
		if r.Observed && !r.TransformCommitted {
			r.Observed = false
			r.Outcome = "HTTP3_TRANSFORM_UNCOMMITTED"
		}
	}()
	config := &quic.Config{Versions: []quic.Version{quic.Version1}, InitialPacketSize: 1200, DisablePathMTUDiscovery: true,
		HandshakeIdleTimeout: 2 * time.Second, MaxIdleTimeout: 2 * time.Second, MaxIncomingStreams: -1, MaxIncomingUniStreams: 3,
		InitialStreamReceiveWindow: 64 * 1024, MaxStreamReceiveWindow: 64 * 1024, InitialConnectionReceiveWindow: 128 * 1024, MaxConnectionReceiveWindow: 128 * 1024}
	conn, err := transport.Dial(ctx, net.UDPAddrFromAddrPort(key.Endpoint), &tls.Config{ServerName: key.Host, RootCAs: roots, MinVersion: tls.VersionTLS13, NextProtos: []string{"h3"}}, config)
	if err != nil {
		r.Outcome = "HTTP3_HANDSHAKE_FAILED"
		var certificate *tls.CertificateVerificationError
		if errors.As(err, &certificate) {
			r.Outcome = "HTTP3_CERTIFICATE_ERROR"
		}
		return
	}
	defer conn.CloseWithError(0, "probe complete")
	state := conn.ConnectionState()
	r.ALPN, r.TLSVersion = state.TLS.NegotiatedProtocol, state.TLS.Version
	r.VerifiedTLS = len(state.TLS.VerifiedChains) > 0 && state.TLS.HandshakeComplete && r.ALPN == "h3" && r.TLSVersion == tls.VersionTLS13 && state.Version == quic.Version1
	if !r.VerifiedTLS {
		r.Outcome = "HTTP3_TLS_UNVERIFIED"
		return
	}
	if ctx.Err() != nil || !current(key) {
		r.Outcome = "HTTP3_SCOPE_CHANGED"
		return
	}
	req, err := http.NewRequestWithContext(ctx, "GET", "https://"+key.Host+"/", nil)
	if err != nil {
		r.Outcome = "HTTP3_SCOPE_INVALID"
		return
	}
	req.Header.Set("User-Agent", "VELIQ-HTTP3-Probe/1")
	req.Header.Set("Accept-Encoding", "identity")
	req.Header.Set("Cache-Control", "no-cache")
	// ClientConn binds this single request to the already verified connection.
	// Transport.RoundTrip can retry a reused connection; we deliberately never
	// call it, DialEarly, http.Client, a redirect handler or another dial function.
	h3 := &http3.Transport{MaxResponseHeaderBytes: 8192, DisableCompression: true}
	response, err := h3.NewClientConn(conn).RoundTrip(req)
	if err != nil {
		r.Outcome = "HTTP3_RESPONSE_FAILED"
		return
	}
	defer response.Body.Close()
	r.Status = response.StatusCode
	if response.ProtoMajor != 3 || response.StatusCode != http.StatusOK {
		r.Outcome = "HTTP3_STATUS_REJECTED"
		return
	}
	if coding := response.Header.Get("Content-Encoding"); coding != "" && coding != "identity" {
		r.Outcome = "HTTP3_ENCODING_REJECTED"
		return
	}
	n, err := io.CopyN(io.Discard, response.Body, HTTP3ProbeSampleBytes)
	r.BodyBytes = uint64(n)
	if err != nil {
		r.Outcome = "HTTP3_BODY_INCOMPLETE"
		return
	}
	if ctx.Err() != nil || !current(key) {
		r.Outcome = "HTTP3_SCOPE_CHANGED"
		return
	}
	r.TransformCommitted = socket.Committed()
	if !r.TransformCommitted {
		r.Outcome = "HTTP3_TRANSFORM_UNCOMMITTED"
		return
	}
	r.Outcome = "HTTP3_AUTHENTICATED_SAMPLE"
	r.Observed = true // A bounded public sample, never full page/playback/admission proof.
	return
}

var errHTTP3ProbeBudget = errors.New("HTTP3_DATAGRAM_BUDGET")

type http3ProbeMeter struct {
	net.PacketConn
	peer                         netip.AddrPort
	received, sent               atomic.Uint64
	receivedPackets, sentPackets atomic.Uint64
	readMu, writeMu              sync.Mutex
	limited                      atomic.Bool
}

func (c *http3ProbeMeter) ReadFrom(p []byte) (int, net.Addr, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()
	if c.received.Load()+1500 > HTTP3ProbeReceiveLimit || c.receivedPackets.Load() >= HTTP3ProbeReceivePackets {
		c.limited.Store(true)
		return 0, nil, errHTTP3ProbeBudget
	}
	n, addr, err := c.PacketConn.ReadFrom(p[:min(len(p), 1500)])
	if err == nil || n > 0 {
		c.receivedPackets.Add(1)
	}
	if n > 0 {
		c.received.Add(uint64(n))
	}
	if addr != nil && addr.String() != c.peer.String() {
		return 0, nil, errors.New("HTTP3_UNEXPECTED_PEER")
	}
	return n, addr, err
}
func (c *http3ProbeMeter) WriteTo(p []byte, addr net.Addr) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if addr == nil || addr.String() != c.peer.String() {
		return 0, errors.New("HTTP3_UNEXPECTED_PEER")
	}
	if len(p) > 1472 || c.sent.Load()+uint64(len(p)) > HTTP3ProbeSendLimit || c.sentPackets.Load() >= HTTP3ProbeSendPackets {
		c.limited.Store(true)
		return 0, errHTTP3ProbeBudget
	}
	n, err := c.PacketConn.WriteTo(p, addr)
	if err == nil || n > 0 {
		c.sentPackets.Add(1)
	}
	if n > 0 {
		c.sent.Add(uint64(n))
	}
	return n, err
}
