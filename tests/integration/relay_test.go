package integration

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"github.com/buzzmean/neexitlag/core/protocol"
	"github.com/buzzmean/neexitlag/core/transport"
	"github.com/buzzmean/neexitlag/services/relay"
	"github.com/buzzmean/neexitlag/tools/echo"
	"github.com/buzzmean/neexitlag/tools/labcert"
	"io"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"
)

func setup(t *testing.T, timeout time.Duration) (*relay.Server, *transport.Client, *tls.Config) {
	t.Helper()
	s, c, e := labcert.Pair()
	if e != nil {
		t.Fatal(e)
	}
	r, e := relay.Listen("127.0.0.1:0", relay.Config{TLS: s, IdleTimeout: timeout, Allow: []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")}})
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { r.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	client, e := transport.Dial(ctx, r.Addr().String(), c)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { client.Close() })
	return r, client, c
}
func TestUDPE2E(t *testing.T) {
	r, c, _ := setup(t, time.Second*5)
	a, close, e := echo.UDP()
	if e != nil {
		t.Fatal(e)
	}
	defer close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	f, e := c.OpenUDP(ctx, netip.MustParseAddrPort(a.String()))
	if e != nil {
		t.Fatal(e)
	}
	defer f.Close()
	start := time.Now()
	for i := 0; i < 50; i++ {
		p := []byte(fmt.Sprintf("packet-%03d", i))
		if e = f.Send(p); e != nil {
			t.Fatal(e)
		}
		got, e := f.Receive(ctx)
		if e != nil || !bytes.Equal(got, p) {
			t.Fatalf("packet %d: %q %v", i, got, e)
		}
	}
	t.Logf("50 delivered, observed loss 0%%, request/reply ordering verified, mean RTT %s", time.Since(start)/50)
	if e = f.Send(make([]byte, protocol.MaxPayload+1)); e == nil {
		t.Fatal("oversize accepted")
	}
	// A received echo is not a synchronization barrier for the sender's
	// accounting: UDP Write can wake the echo/reply goroutines before Add runs.
	// Wait only for that bookkeeping; delivery, ordering and exact count remain
	// strict. This never retries a lost probe or hides packet loss.
	accountingDeadline := time.Now().Add(time.Second)
	for r.Metrics.UDPPackets.Load() < 50 && time.Now().Before(accountingDeadline) {
		time.Sleep(time.Millisecond)
	}
	if got := r.Metrics.UDPPackets.Load(); got != 50 {
		t.Fatalf("packet accounting: got %d, want exactly 50", got)
	}
	w := httptest.NewRecorder()
	r.Handler().ServeHTTP(w, httptest.NewRequest("GET", "/metrics", nil))
	if !strings.Contains(w.Body.String(), "neexitlag_udp_packets_total 50") {
		t.Fatal(w.Body.String())
	}
}
func TestTCPE2E(t *testing.T) {
	_, c, _ := setup(t, time.Second*5)
	a, close, e := echo.TCP()
	if e != nil {
		t.Fatal(e)
	}
	defer close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	f, e := c.OpenTCP(ctx, netip.MustParseAddrPort(a.String()))
	if e != nil {
		t.Fatal(e)
	}
	defer f.Close()
	f.SetDeadline(time.Now().Add(5 * time.Second))
	p := bytes.Repeat([]byte("tcp-echo"), 10000)
	done := make(chan error, 1)
	go func() {
		_, e := f.Write(p)
		if h, ok := f.(interface{ CloseWrite() error }); ok {
			h.CloseWrite()
		}
		done <- e
	}()
	got, e := io.ReadAll(f)
	if e != nil || !bytes.Equal(got, p) {
		t.Fatalf("TCP echo: %d bytes %v", len(got), e)
	}
	if e := <-done; e != nil {
		t.Fatal(e)
	}
}
func TestUnauthenticated(t *testing.T) {
	r, _, c := setup(t, time.Second)
	bad := c.Clone()
	bad.Certificates = nil
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	x, e := transport.Dial(ctx, r.Addr().String(), bad)
	if e == nil {
		defer x.Close()
		_, e = x.OpenUDP(ctx, netip.MustParseAddrPort("127.0.0.1:9999"))
	}
	if e == nil {
		t.Fatal("missing device certificate accepted")
	}
}
func TestDestinationPolicy(t *testing.T) {
	_, c, _ := setup(t, time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if _, e := c.OpenUDP(ctx, netip.MustParseAddrPort("169.254.169.254:80")); e == nil {
		t.Fatal("metadata address accepted")
	}
}
func TestIdleCleanup(t *testing.T) {
	r, c, _ := setup(t, 100*time.Millisecond)
	a, close, e := echo.UDP()
	if e != nil {
		t.Fatal(e)
	}
	defer close()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	f, e := c.OpenUDP(ctx, netip.MustParseAddrPort(a.String()))
	if e != nil {
		t.Fatal(e)
	}
	defer f.Close()
	if _, e = f.Receive(ctx); e == nil || ctx.Err() != nil {
		t.Fatalf("idle flow not closed: %v", e)
	}
	deadline := time.Now().Add(time.Second)
	for r.Metrics.Flows.Load() != 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if r.Metrics.Flows.Load() != 0 {
		t.Fatal("flow leak")
	}
}
func TestRelayShutdown(t *testing.T) {
	r, c, _ := setup(t, time.Second)
	r.Close()
	select {
	case <-c.Done():
	case <-time.After(3 * time.Second):
		t.Fatal("client did not detect shutdown")
	}
}
