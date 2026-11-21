package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"github.com/buzzmean/neexitlag/core/protocol"
	"github.com/buzzmean/neexitlag/core/routing"
	"github.com/buzzmean/neexitlag/internal/webprobe"
	"github.com/quic-go/quic-go/http3"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/buzzmean/neexitlag/core/optimizer"
	"github.com/buzzmean/neexitlag/core/security"
	"github.com/buzzmean/neexitlag/core/transport"
	"github.com/buzzmean/neexitlag/internal/e2eprobe"
	"github.com/buzzmean/neexitlag/services/relay"
	"github.com/buzzmean/neexitlag/tools/labcert"
)

func testRelay(t *testing.T) (options, authenticated, *transport.Client, []byte, ed25519.PrivateKey) {
	t.Helper()
	serverTLS, clientTLS, err := labcert.Pair()
	if err != nil {
		t.Fatal(err)
	}
	pub, issuer, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	verifier := security.NewTicketVerifier(map[string]ed25519.PublicKey{"issuer": pub}, "VPS-01")
	server, err := relay.Listen("127.0.0.1:0", relay.Config{TLS: serverTLS, TicketVerifier: verifier, Allow: []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { server.Close() })
	o := options{relay: server.Addr().String(), relayID: "VPS-01", count: 30, interval: 20 * time.Millisecond, timeout: time.Second}
	a := authenticated{tls: clientTLS, keys: map[string]ed25519.PublicKey{"issuer": pub}}
	ticket := testTicket(t, issuer, clientTLS, "valid", time.Now().Add(time.Minute))
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	client, err := transport.DialWithTicket(ctx, o.relay, clientTLS, ticket)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { client.Close() })
	return o, a, client, []byte("controlled-echo-key-32-characters"), issuer
}
func testTicket(t *testing.T, key ed25519.PrivateKey, tlsConfig *tls.Config, id string, expiry time.Time) []byte {
	t.Helper()
	peer := tlsConfig.Certificates[0].PrivateKey.(ed25519.PrivateKey).Public().(ed25519.PublicKey)
	now := time.Now()
	issued := now.Add(-2 * time.Minute)
	if expiry.After(now) {
		issued = now
	}
	raw, err := security.Sign("ticket", "issuer", key, security.Ticket{ID: id, DeviceID: "device", DeviceKey: security.Fingerprint(peer), RelayID: "VPS-01", IssuedAt: issued, ExpiresAt: expiry})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
func TestRealAuthenticatedUDPAndTCPBothPaths(t *testing.T) {
	o, _, client, key, _ := testRelay(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	udp, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- e2eprobe.Serve(ctx, udp, key, &e2eprobe.EchoStats{}) }()
	defer func() { cancel(); <-done }()
	o.target = udp.LocalAddr().String()
	direct, relayed, recommended := benchmark(ctx, o, client.OpenDatagram, key, 0)
	if direct.Successful != 30 || relayed.Successful != 30 || direct.Failed != 0 || relayed.Failed != 0 || direct.Loss == nil || *direct.Loss != 0 || relayed.Score == nil || recommended == "INSUFFICIENT_EVIDENCE" {
		t.Fatal(direct, relayed, recommended)
	}
	if direct.MedianMS == nil || direct.P95MS == nil || direct.JitterMS == nil || len(relayed.ObservedSources) != 1 {
		t.Fatal("missing actual metrics")
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	tcpDone := make(chan error, 1)
	go func() { tcpDone <- e2eprobe.ServeTCP(ctx, listener, key, &e2eprobe.EchoStats{}) }()
	defer func() { cancel(); <-tcpDone }()
	o.tcpTarget = listener.Addr().String()
	for _, route := range []string{"DIRECT", "RELAY"} {
		peer, err := tcpProof(ctx, o, client, key, route)
		if err != nil || peer != "127.0.0.1" {
			t.Fatal(route, peer, err)
		}
	}
	t.Log("real authenticated local UDP/TCP DIRECT+RELAY integration; not Internet performance validation")
}
func TestWrongExpiredAndMismatchedTicketCredentialsAreRejected(t *testing.T) {
	o, a, _, _, issuer := testRelay(t)
	expired := testTicket(t, issuer, a.tls, "expired", time.Now().Add(-time.Second))
	if err := rejected(context.Background(), o, a, expired); err != nil {
		t.Fatal(err)
	}
	wrong := testTicket(t, issuer, a.tls, "wrong", time.Now().Add(time.Minute))
	wrong[len(wrong)-4] ^= 1
	if err := rejected(context.Background(), o, a, wrong); err != nil {
		t.Fatal(err)
	}
	mismatch, err := security.Sign("ticket", "issuer", issuer, security.Ticket{ID: "other-device", DeviceID: "device", DeviceKey: "incorrect-fingerprint", RelayID: "VPS-01", IssuedAt: time.Now(), ExpiresAt: time.Now().Add(time.Minute)})
	if err != nil {
		t.Fatal(err)
	}
	if err := rejected(context.Background(), o, a, mismatch); err != nil {
		t.Fatal(err)
	}
}
func TestUnavailableIsNeverAnAuthenticationPass(t *testing.T) {
	o, a, _, _, issuer := testRelay(t)
	reserved, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer reserved.Close()
	o.relay = reserved.LocalAddr().String()
	o.timeout = 150 * time.Millisecond
	raw := testTicket(t, issuer, a.tls, "unavailable", time.Now().Add(time.Minute))
	if err := rejected(context.Background(), o, a, raw); err == nil {
		t.Fatal("timeout falsely counted as authenticated rejection")
	}
}
func TestActualEchoTimeoutRemainsVisible(t *testing.T) {
	o, _, client, _, _ := testRelay(t)
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	done := make(chan struct{})
	release := make(chan struct{})
	go func() {
		defer close(done)
		conn, err := listener.Accept()
		if err == nil {
			defer conn.Close()
			<-release
		}
	}()
	o.tcpTarget = listener.Addr().String()
	o.timeout = time.Second
	_, err = tcpProof(context.Background(), o, client, []byte("controlled-echo-key-32-characters"), "DIRECT")
	close(release)
	listener.Close()
	<-done
	var timeout net.Error
	if !errors.As(err, &timeout) || !timeout.Timeout() {
		t.Fatal("expected real receive timeout", err)
	}
}
func TestMetricsAndRecommendationUseLossFirstOptimizer(t *testing.T) {
	r := &observation{attempts: 4, sources: map[string]bool{"2.56.177.4": true}, packets: []optimizer.ProbeSample{{Outcome: optimizer.Reply, RTT: 10 * time.Millisecond}, {Outcome: optimizer.Timeout}, {Outcome: optimizer.Reply, RTT: 30 * time.Millisecond}, {Outcome: optimizer.Reply, RTT: 20 * time.Millisecond}}}
	m := summarize(r, optimizer.Quality{}, 0)
	if m.Successful != 3 || m.Failed != 1 || *m.Loss != .25 || *m.MedianMS != 20 || *m.P95MS != 30 || *m.JitterMS != 15 {
		t.Fatal(m)
	}
	quality := func(rtt float64, loss float64) optimizer.Quality {
		return optimizer.Quality{Health: "healthy", Samples: 100, NetworkSamples: 100, MedianRTT: time.Duration(rtt * 1e6), P95RTT: time.Duration(rtt * 1e6), EWMARTT: time.Duration(rtt * 1e6), Loss: loss, Stability: 1}
	}
	if optimizer.QualityScore(quality(55, 0), 0) >= optimizer.QualityScore(quality(48, .02), 0) {
		t.Fatal("small RTT advantage overrode loss")
	}
	if publicEndpoint("127.0.0.1:40000") || publicEndpoint("203.0.113.1:40000") || !publicEndpoint("2.56.177.4:40000") {
		t.Fatal("local/docs address labeled Internet")
	}
}

func TestRealAuthenticatedLargeUDPDatagrams(t *testing.T) {
	_, _, client, _, _ := testRelay(t)
	socket, e := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if e != nil {
		t.Fatal(e)
	}
	defer socket.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		b := make([]byte, 2048)
		for {
			n, peer, e := socket.ReadFromUDP(b)
			if e != nil {
				return
			}
			_, _ = socket.WriteToUDP(b[:n], peer)
		}
	}()
	defer func() { socket.Close(); <-done }()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	flow, e := client.OpenUDP(ctx, socket.LocalAddr().(*net.UDPAddr).AddrPort())
	if e != nil {
		t.Fatal(e)
	}
	defer flow.Close()
	for _, size := range []int{64, 1100, 1200, 1350, protocol.MaxPayload} {
		payload := bytes.Repeat([]byte{byte(size)}, size)
		if e = flow.Send(payload); e != nil {
			t.Fatal(size, e)
		}
		got, e := flow.Receive(ctx)
		if e != nil || !bytes.Equal(got, payload) {
			t.Fatalf("size %d: %v, got %d", size, e, len(got))
		}
	}
	t.Log("actual authenticated QUIC DATAGRAM fragmentation in both directions, local integration only")
}

// Real nested HTTP/3, including >=1200-byte QUIC Initial datagrams, through the
// actual authenticated relay. The loopback bridge is a test socket adapter;
// it is not external Windows/browser acceptance and generates no telemetry.
func TestRealHTTP3ThroughAuthenticatedRelay(t *testing.T) {
	_, _, client, _, _ := testRelay(t)
	token := "controlled-h3-token-1234567890"
	certServer := httptest.NewTLSServer(webprobe.Handler(token))
	tlsConfig := certServer.TLS.Clone()
	certificate := certServer.Certificate()
	certServer.Close()
	target, e := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if e != nil {
		t.Fatal(e)
	}
	server := &http3.Server{Handler: webprobe.Handler(token), TLSConfig: tlsConfig}
	serverDone := make(chan error, 1)
	go func() { serverDone <- server.Serve(target) }()
	defer func() { server.Close(); <-serverDone }()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	flow, e := client.OpenUDP(ctx, target.LocalAddr().(*net.UDPAddr).AddrPort())
	if e != nil {
		t.Fatal(e)
	}
	defer flow.Close()
	bridge, e := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if e != nil {
		t.Fatal(e)
	}
	var mu sync.Mutex
	var peer *net.UDPAddr
	var wg sync.WaitGroup
	wg.Add(2)
	defer func() { cancel(); bridge.Close(); flow.Close(); wg.Wait() }()
	go func() {
		defer wg.Done()
		b := make([]byte, 2048)
		for {
			n, p, e := bridge.ReadFromUDP(b)
			if e != nil {
				return
			}
			mu.Lock()
			if peer == nil {
				peer = p
			}
			same := peer.String() == p.String()
			mu.Unlock()
			if same {
				if flow.Send(b[:n]) != nil {
					return
				}
			}
		}
	}()
	go func() {
		defer wg.Done()
		for {
			b, e := flow.Receive(ctx)
			if e != nil {
				return
			}
			mu.Lock()
			p := peer
			mu.Unlock()
			if p != nil {
				if _, e = bridge.WriteToUDP(b, p); e != nil {
					return
				}
			}
		}
	}()
	roots := x509.NewCertPool()
	roots.AddCert(certificate)
	transport := &http3.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS13}}
	defer transport.Close()
	request, e := http.NewRequestWithContext(ctx, "GET", "https://"+bridge.LocalAddr().String()+"/observe?nonce=1234567890abcdef", nil)
	if e != nil {
		t.Fatal(e)
	}
	request.Header.Set("X-Neexitlag-Proof", webprobe.SignRequest(token, "GET", "/observe", request.URL.Query().Get("nonce")))
	response, e := (&http.Client{Transport: transport}).Do(request)
	if e != nil {
		t.Fatal(e)
	}
	defer response.Body.Close()
	observation, e := webprobe.ReadObservation(response.Body)
	if e != nil || response.ProtoMajor != 3 || observation.Protocol != "HTTP/3.0" || !observation.TLS || observation.Nonce != "1234567890abcdef" || !webprobe.VerifyObservation(token, observation) {
		t.Fatalf("%+v %v", observation, e)
	}
}

func TestHTTPSHTTP2OverAuthenticatedTCPRelay(t *testing.T) {
	_, _, client, _, _ := testRelay(t)
	token := "controlled-tls-endpoint-token-123456"
	target := httptest.NewUnstartedServer(webprobe.Handler(token))
	target.EnableHTTP2 = true
	target.StartTLS()
	defer target.Close()
	roots := x509.NewCertPool()
	roots.AddCert(target.Certificate())
	tr := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}, ForceAttemptHTTP2: true, DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
		destination, e := netip.ParseAddrPort(addr)
		if e != nil {
			return nil, e
		}
		return client.OpenTCP(ctx, destination)
	}}
	defer tr.CloseIdleConnections()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	request, e := http.NewRequestWithContext(ctx, "GET", target.URL+"/observe?nonce=0123456789abcdef", nil)
	if e != nil {
		t.Fatal(e)
	}
	request.Header.Set("X-Neexitlag-Proof", webprobe.SignRequest(token, "GET", "/observe", request.URL.Query().Get("nonce")))
	response, e := (&http.Client{Transport: tr}).Do(request)
	if e != nil {
		t.Fatal(e)
	}
	defer response.Body.Close()
	o, e := webprobe.ReadObservation(response.Body)
	if e != nil || !o.TLS || o.Protocol != "HTTP/2.0" || o.Nonce != "0123456789abcdef" || !webprobe.VerifyObservation(token, o) || response.ProtoMajor != 2 {
		t.Fatalf("%+v %v", o, e)
	}
}

func TestRealTCPRoutePinningAndNativeOpenFailureFallback(t *testing.T) {
	_, _, client, _, _ := testRelay(t)
	target, e := net.Listen("tcp4", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer target.Close()
	var workers sync.WaitGroup
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			c, e := target.Accept()
			if e != nil {
				return
			}
			workers.Add(1)
			go func() { defer workers.Done(); defer c.Close(); _, _ = io.Copy(c, c) }()
		}
	}()
	defer func() { target.Close(); <-done; workers.Wait() }()
	engine := routing.New(10)
	engine.SetRelay("VPS-01", client)
	engine.SetPolicy("selected", routing.Policy{Route: routing.Route{RelayID: "VPS-01"}})
	f := routing.Flow{Protocol: "tcp", PID: 42, ProcessPath: "selected.exe", ApplicationID: "selected", Source: netip.MustParseAddrPort("127.0.0.1:50001"), Destination: target.Addr().(*net.TCPAddr).AddrPort()}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	first, e := engine.OpenTCP(ctx, f)
	if e != nil {
		t.Fatal(e)
	}
	defer first.Close()
	engine.SetPolicy("selected", routing.Policy{})
	if _, e = first.Write([]byte("pin")); e != nil {
		t.Fatal(e)
	}
	b := make([]byte, 3)
	if _, e = io.ReadFull(first, b); e != nil || string(b) != "pin" {
		t.Fatal(e, string(b))
	}
	if snapshot := engine.Snapshot(); len(snapshot) != 1 || snapshot[0].Route.RelayID != "VPS-01" {
		t.Fatal("existing TCP migrated", snapshot)
	}
	f.Source = netip.MustParseAddrPort("127.0.0.1:50002")
	second, e := engine.OpenTCP(ctx, f)
	if e != nil {
		t.Fatal(e)
	}
	defer second.Close()
	found := false
	for _, flow := range engine.Snapshot() {
		if flow.Source == f.Source {
			found = flow.Route.Direct()
		}
	}
	if !found {
		t.Fatal("new TCP ignored changed policy")
	}
	engine.SetPolicy("selected", routing.Policy{Route: routing.Route{RelayID: "unavailable"}})
	f.Source = netip.MustParseAddrPort("127.0.0.1:50003")
	fallback, e := engine.OpenTCP(ctx, f)
	if e != nil {
		t.Fatal(e)
	}
	defer fallback.Close()
	found = false
	for _, flow := range engine.Snapshot() {
		if flow.Source == f.Source {
			found = flow.Route.Direct()
		}
	}
	if !found {
		t.Fatal("opening failure did not use native DIRECT")
	}
	client.Close()
	_ = first.SetReadDeadline(time.Now().Add(time.Second))
	if _, e = first.Read(b); e == nil {
		t.Fatal("dead relay TCP silently migrated")
	}
}
