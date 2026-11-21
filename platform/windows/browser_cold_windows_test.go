//go:build windows

package windowsplatform

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/buzzmean/neexitlag/core/browserproxy"
	"github.com/buzzmean/neexitlag/core/flowpolicy"
	"github.com/buzzmean/neexitlag/core/routing"
	"github.com/buzzmean/neexitlag/core/security"
	"github.com/buzzmean/neexitlag/core/transport"
	"github.com/buzzmean/neexitlag/internal/browserfixture"
	"github.com/buzzmean/neexitlag/services/relay"
	"github.com/buzzmean/neexitlag/tools/labcert"
)

// An actual DIRECT origin accepts TCP, consumes ClientHello and deliberately
// keeps its reply half open even after FIN. The authenticated relay reaches the
// SAME TLS/HTTP target from 127.0.0.2. No public server/credential is used.
type coldDirectListener struct {
	net.Listener
	mu     sync.Mutex
	held   []net.Conn
	closed bool
}

func (l *coldDirectListener) Accept() (net.Conn, error) {
	for {
		c, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		if c.RemoteAddr().(*net.TCPAddr).IP.Equal(net.IPv4(127, 0, 0, 2)) {
			return c, nil
		}
		l.mu.Lock()
		if l.closed {
			l.mu.Unlock()
			c.Close()
			return nil, net.ErrClosed
		}
		l.held = append(l.held, c)
		l.mu.Unlock()
		go func() { _, _ = io.Copy(io.Discard, c) }() // No Close after FIN: remote reply stays silent.
	}
}
func (l *coldDirectListener) Close() error {
	l.mu.Lock()
	l.closed = true
	held := append([]net.Conn(nil), l.held...)
	l.mu.Unlock()
	err := l.Listener.Close()
	for _, c := range held {
		_ = c.Close()
	}
	return err
}
func testNativeColdStallRetry(t *testing.T, b *WinDivertBackend, id ProcessIdentity) {
	t.Helper()
	ctx, stop := context.WithTimeout(b.ctx, 20*time.Second)
	defer stop()
	f, err := browserfixture.New()
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var replies atomic.Uint64
	target := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.RemoteAddr, "127.0.0.2:") {
			t.Error("HTTP response reached without authenticated relay source", r.RemoteAddr)
			http.Error(w, "wrong source", 403)
			return
		}
		replies.Add(1)
		w.Write([]byte(f.Nonce))
	}))
	target.EnableHTTP2 = true
	target.TLS = f.Server.TLS.Clone()
	target.Listener = &coldDirectListener{Listener: target.Listener}
	target.StartTLS()
	defer target.Close()
	destination := target.Listener.Addr().(*net.TCPAddr).AddrPort()
	serverTLS, clientTLS, err := labcert.Pair()
	if err != nil {
		t.Fatal(err)
	}
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	server, err := relay.Listen("127.0.0.1:0", relay.Config{TLS: serverTLS, TicketVerifier: security.NewTicketVerifier(map[string]ed25519.PublicKey{"test": pub}, "VPS-01"), Allow: []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")}, Acceptance: &relay.AcceptanceConfig{LeaseDuration: 2 * time.Minute, OutboundSource: netip.MustParseAddr("127.0.0.2")}})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	peer := clientTLS.Certificates[0].PrivateKey.(ed25519.PrivateKey).Public().(ed25519.PublicKey)
	pool, err := transport.NewPool(ctx, transport.DefaultPoolConfig(), func(ctx context.Context) (*transport.Client, error) {
		ticketID, _ := security.NewID()
		now := time.Now()
		ticket, err := security.Sign("ticket", "test", key, security.Ticket{ID: ticketID, DeviceID: "cold-fixture", DeviceKey: security.Fingerprint(peer), RelayID: "VPS-01", IssuedAt: now, ExpiresAt: now.Add(time.Minute)})
		if err != nil {
			return nil, err
		}
		return transport.DialWithTicket(ctx, server.Addr().String(), clientTLS, ticket)
	})
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	b.Engine.SetRelay("VPS-01", pool)
	// Reproduce the previous Close semantics with the actual driver: close
	// only the frontend kernel socket, without its new synchronous release hook.
	original := routing.Flow{Protocol: "tcp", PID: id.PID, ProcessPath: id.Path, ApplicationID: "cold-browser", Source: netip.MustParseAddrPort("127.0.0.1:12349"), Destination: destination, PinnedPolicy: &routing.Policy{}}
	d := Decision{NewConnectionsOnly: true, BlockOnFailure: true, OriginDomain: "www.youtube.com"}
	d.OpenDeferred = func(ctx context.Context, d Decision, _ string) (net.Conn, Decision, error) {
		up, e := b.Engine.OpenTCP(ctx, original)
		return up, d, e
	}
	held, e := b.OpenBrowserNativeTCP(ctx, id, original.Source, destination, d)
	if e != nil {
		t.Fatal("baseline native admission", e)
	}
	_, _ = held.Write([]byte("lifecycle-only"))
	_ = held.(*delegatedConn).Conn.Close()
	retry := original
	retry.PinnedPolicy = &routing.Policy{Route: routing.Route{RelayID: "VPS-01"}, BlockOnFailure: true}
	unexpected, e := b.Engine.OpenTCP(ctx, retry)
	if e == nil {
		unexpected.Close()
		held.Close()
		t.Fatal("old kernel-only Close did not reproduce the reported reservation collision")
	}
	if !errors.Is(e, routing.ErrFlowExists) {
		held.Close()
		t.Fatal("different failure class than local reservation", e)
	}
	_ = held.Close()
	for _, active := range b.Engine.Snapshot() {
		if active.Source == original.Source {
			t.Fatal("full planned close retained tuple", active)
		}
	}
	t.Log("CONFIRMED old kernel-only Close -> ErrFlowExists while app-scoped firewall is applied; synchronous planned close releases it")
	cache := flowpolicy.NewDirectTimeoutCache()
	cacheKey := func(q browserproxy.Request) flowpolicy.DirectTimeoutKey {
		return flowpolicy.DirectTimeoutKey{Network: "cold-network", Application: "cold-browser", Host: flowpolicy.DirectTimeoutHost(q.Host), Port: q.Port, Address: destination.Addr().String()}
	}
	var direct, collisions atomic.Uint64
	open := func(ctx context.Context, q browserproxy.Request, p browserproxy.Plan) (net.Conn, error) {
		d := Decision{NewConnectionsOnly: true, BlockOnFailure: true, OriginDomain: q.Host, Policy: p.Policy}
		if p.Policy.Action == flowpolicy.RelayRequired {
			d.Route = routing.Route{RelayID: "VPS-01"}
		}
		d.OpenDeferred = func(ctx context.Context, d Decision, _ string) (net.Conn, Decision, error) {
			if d.Route.Direct() {
				direct.Add(1)
			}
			up, err := b.Engine.OpenTCP(ctx, routing.Flow{Protocol: "tcp", Source: q.Source, Destination: destination, PID: id.PID, ProcessPath: id.Path, ApplicationID: "cold-browser", PinnedPolicy: &routing.Policy{Route: d.Route, BlockOnFailure: true}})
			if errors.Is(err, routing.ErrFlowExists) {
				collisions.Add(1)
			}
			return up, d, err
		}
		return b.OpenBrowserNativeTCP(ctx, id, q.Source, destination, d)
	}
	proxy, err := browserproxy.Listen(ctx, browserproxy.Config{
		Authorize: func(context.Context, netip.AddrPort, netip.AddrPort) (browserproxy.Owner, error) {
			return browserproxy.Owner{PID: id.PID, Birth: id.CreationTime, Exe: id.Path, Profile: "cold-browser"}, nil
		},
		Plan: func(_ context.Context, q browserproxy.Request) (browserproxy.Plan, error) {
			action, source := flowpolicy.Direct, "cold-direct"
			key := cacheKey(q)
			if flowpolicy.BrowserRelayGroup(q.Host) != "" {
				key.Address = ""
			}
			if active, _ := cache.Lookup(key, time.Now()); active {
				action, source = flowpolicy.RelayRequired, "direct_timeout_cache"
			}
			if q.Host == "chatgpt.com" {
				action, source = flowpolicy.RelayRequired, "protected"
			}
			return browserproxy.Plan{Enabled: true, Network: "cold-network", Destination: destination, Policy: flowpolicy.Result{Action: action, RelayID: "VPS-01", Fallback: flowpolicy.Required, Source: source}}, nil
		}, Open: open,
		OnStall: func(ctx context.Context, q browserproxy.Request, p browserproxy.Plan) (net.Conn, browserproxy.Plan, error) {
			if flowpolicy.BrowserRelayGroup(q.Host) != "" {
				cache.RecordOriginStall(cacheKey(q), time.Now())
			} else {
				cache.RecordStall(cacheKey(q), time.Now())
			}
			p.Policy = flowpolicy.Result{Action: flowpolicy.RelayRequired, RelayID: "VPS-01", Fallback: flowpolicy.Required, Source: "direct_stall_retry"}
			conn, err := open(ctx, q, p)
			cache.NoteRetry(err == nil)
			return conn, p, err
		}, StallTimeout: 150 * time.Millisecond, RequireClientHelloReplay: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer proxy.Close()
	proxyURL, _ := url.Parse("http://" + proxy.Address())
	tr := &http.Transport{Proxy: http.ProxyURL(proxyURL), TLSClientConfig: &tls.Config{RootCAs: f.Roots, MinVersion: tls.VersionTLS12}, DisableKeepAlives: true, ForceAttemptHTTP2: true}
	defer tr.CloseIdleConnections()
	client := &http.Client{Transport: tr, Timeout: 4 * time.Second}
	for _, host := range []string{"youtube.com", "www.youtube.com", "rr1---sn-test.googlevideo.com", "i.ytimg.com", "yt3.ggpht.com", "play.google.com", "vk.ru"} {
		for attempt := 0; attempt < 2; attempt++ {
			before := direct.Load()
			started := time.Now()
			response, err := client.Get("https://" + host + "/cold-nonce")
			if err != nil {
				t.Fatal("first cold request must finish, not rely on browser reconnect/cache", host, attempt, err, "local tuple collisions", collisions.Load())
			}
			t.Logf("cold verified TLS/HTTP headers: host=%s attempt=%d time=%v DIRECT opens=%d", host, attempt, time.Since(started), direct.Load()-before)
			body, readErr := io.ReadAll(response.Body)
			response.Body.Close()
			if readErr != nil || response.StatusCode != 200 || string(body) != f.Nonce {
				t.Fatal("TLS/HTTP nonce failed", host, response.StatusCode, readErr)
			}
			if (attempt == 1 || flowpolicy.BrowserRelayGroup(host) != "" && host != "youtube.com") && direct.Load() != before {
				t.Fatal("cached request retried DIRECT", host)
			}
		}
	}
	before := direct.Load()
	response, err := client.Get("https://chatgpt.com/cold-nonce")
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(response.Body)
	response.Body.Close()
	if err != nil || string(body) != f.Nonce || direct.Load() != before {
		t.Fatal("protected origin failed or leaked DIRECT", err)
	}
	snapshot := proxy.Snapshot()
	if collisions.Load() != 0 || replies.Load() != 15 || snapshot.Failures["DIRECT_STALL"] != 3 || snapshot.Failures["DIRECT_STALL_RETRIED_VIA_RELAY"] != 3 || snapshot.Failures["DIRECT_STALL_RETRY_FAILED"] != 0 {
		t.Fatal("cold retry counters", collisions.Load(), replies.Load(), snapshot.Failures)
	}
	var groupDirect, groupRelay uint64
	for _, timing := range snapshot.FirstByteMetrics {
		if timing.Group != "youtube-media" {
			continue
		}
		t.Logf("connection-to-first-byte: group=%s mode=%s n=%d avg=%.2fms min=%.2fms max=%.2fms no_reply=%d", timing.Group, timing.Mode, timing.Replies, timing.TotalMS/float64(timing.Replies), timing.MinMS, timing.MaxMS, timing.NoReply)
		if timing.NoReply != 0 {
			t.Fatal("group lost first connection", timing)
		}
		if timing.Mode == "DIRECT_FIRST" {
			groupDirect += timing.Replies
		}
		if timing.Mode == "RELAY_FIRST" {
			groupRelay += timing.Replies
		}
	}
	if groupDirect != 1 || groupRelay != 9 {
		t.Fatal("cold group paid repeated DIRECT timeouts", groupDirect, groupRelay)
	}
	t.Log("PASS cold-cache native DIRECT stall -> same CONNECT authenticated RELAY: verified TLS+HTTP nonce, seven first requests survive; YouTube group only one initial stall, no Engine collision, cached request relay-first, protected no DIRECT")
}
