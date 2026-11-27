package browserproxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/buzzmean/veliq/core/flowpolicy"
)

const ordinaryPassthroughStall = 50 * time.Millisecond

func ordinaryPassthroughProxy(t *testing.T, address string, shouldWatch func(Request, Plan) bool) (*Server, *atomic.Int32, *atomic.Int32) {
	t.Helper()
	var opens, stalls atomic.Int32
	server, err := Listen(context.Background(), Config{
		RequireClientHelloReplay: true,
		StallTimeout:             ordinaryPassthroughStall,
		Authorize: func(context.Context, netip.AddrPort, netip.AddrPort) (Owner, error) {
			return Owner{PID: 73, Birth: 19, Profile: "ordinary-owner-application"}, nil
		},
		Plan: func(context.Context, Request) (Plan, error) {
			return Plan{Enabled: true, Policy: flowpolicy.Result{Action: flowpolicy.Direct, Source: "owner_system_passthrough"}}, nil
		},
		Open: func(ctx context.Context, _ Request, plan Plan) (net.Conn, error) {
			opens.Add(1)
			if !plan.Enabled || plan.FirstFlightManaged || plan.Policy.Action != flowpolicy.Direct {
				t.Error("fixture must exercise an enabled, unmanaged DIRECT plan")
			}
			return (&net.Dialer{}).DialContext(ctx, "tcp", address)
		},
		ShouldWatchDirect: shouldWatch,
		OnStall: func(context.Context, Request, Plan) (net.Conn, Plan, error) {
			stalls.Add(1)
			return nil, Plan{}, errors.New("ordinary application must not enter browser recovery")
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { server.Close() })
	return server, &opens, &stalls
}

func ordinaryPassthroughDecision(t *testing.T, calls *atomic.Int32) func(Request, Plan) bool {
	t.Helper()
	return func(q Request, p Plan) bool {
		calls.Add(1)
		if q.Owner.Profile != "ordinary-owner-application" || !q.Secure || q.Host != "example.com" || q.Port != 443 || !p.Enabled || p.Policy.Action != flowpolicy.Direct {
			t.Error("passthrough selector lost authenticated owner or actual CONNECT scope")
		}
		return false
	}
}

func TestOrdinaryPassthroughKeepsDelayedVerifiedTLSOnOriginalConnection(t *testing.T) {
	var originRequests atomic.Int32
	origin := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		originRequests.Add(1)
		io.WriteString(w, "ordinary TLS response")
	}))
	// A healthy origin may need longer than the browser first-flight budget.
	// Delay the real ServerHello, not a synthetic HTTP response after TLS.
	origin.TLS = &tls.Config{GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
		timer := time.NewTimer(4 * ordinaryPassthroughStall)
		defer timer.Stop()
		select {
		case <-timer.C:
			return nil, nil
		case <-hello.Context().Done():
			return nil, hello.Context().Err()
		}
	}}
	origin.StartTLS()
	defer origin.Close()
	var decisions atomic.Int32
	proxy, opens, stalls := ordinaryPassthroughProxy(t, origin.Listener.Addr().String(), ordinaryPassthroughDecision(t, &decisions))
	raw, _ := connectVia(t, proxy.Address(), "example.com:443")
	roots := x509.NewCertPool()
	roots.AddCert(origin.Certificate())
	secure := tls.Client(raw, &tls.Config{RootCAs: roots, ServerName: "example.com", MinVersion: tls.VersionTLS12})
	defer secure.Close()
	secure.SetDeadline(time.Now().Add(5 * time.Second))
	if err := secure.Handshake(); err != nil {
		t.Fatal("ordinary delayed TLS was interrupted by browser recovery", err)
	}
	request, err := http.NewRequest(http.MethodGet, "https://example.com/ordinary", nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Close = true
	if err := request.Write(secure); err != nil {
		t.Fatal(err)
	}
	response, err := http.ReadResponse(bufio.NewReader(secure), request)
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(response.Body)
	response.Body.Close()
	if err != nil || response.StatusCode != http.StatusOK || string(body) != "ordinary TLS response" {
		t.Fatal("ordinary verified TLS exchange changed", response.StatusCode, string(body), err)
	}
	if decisions.Load() != 1 || opens.Load() != 1 || stalls.Load() != 0 || originRequests.Load() != 1 {
		t.Fatal("ordinary TLS was retried or skipped its scope decision", decisions.Load(), opens.Load(), stalls.Load(), originRequests.Load())
	}
}

func TestOrdinaryPassthroughKeepsBinaryCONNECT443BytesWithoutReplay(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	payload := []byte{0x01, 0x00, 0xfe, 0x10, 0x80, 0x00, 0x07}
	reply := []byte{0x02, 0x00, 0x81, 0x99}
	originDone := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			originDone <- err
			return
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(5 * time.Second))
		got := make([]byte, len(payload))
		if _, err := io.ReadFull(conn, got); err != nil {
			originDone <- err
			return
		}
		if string(got) != string(payload) {
			originDone <- errors.New("binary first flight changed")
			return
		}
		time.Sleep(4 * ordinaryPassthroughStall)
		if _, err := conn.Write(reply); err != nil {
			originDone <- err
			return
		}
		// After the delayed reply, later application bytes remain on this exact
		// stream. Any replay adds the binary prefix before this marker.
		later := make([]byte, len("same stream"))
		_, err = io.ReadFull(conn, later)
		if err == nil && string(later) != "same stream" {
			err = errors.New("binary payload replayed or later bytes changed")
		}
		originDone <- err
	}()
	var decisions atomic.Int32
	proxy, opens, stalls := ordinaryPassthroughProxy(t, listener.Addr().String(), ordinaryPassthroughDecision(t, &decisions))
	conn, reader := connectVia(t, proxy.Address(), "example.com:443")
	if _, err := conn.Write(payload); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(reply))
	if _, err := io.ReadFull(reader, got); err != nil || string(got) != string(reply) {
		t.Fatal("healthy binary CONNECT was treated as browser TLS", got, err)
	}
	if _, err := io.WriteString(conn, "same stream"); err != nil {
		t.Fatal(err)
	}
	if err := <-originDone; err != nil {
		t.Fatal(err)
	}
	if decisions.Load() != 1 || opens.Load() != 1 || stalls.Load() != 0 {
		t.Fatal("ordinary binary stream entered browser recovery", decisions.Load(), opens.Load(), stalls.Load())
	}
}

func TestOrdinaryPassthroughSelectorDoesNotDisableDefaultBrowserStallRecovery(t *testing.T) {
	for _, name := range []string{"nil", "allow"} {
		t.Run(name, func(t *testing.T) {
			address, _ := silentOrigin(t, false)
			var decisions atomic.Int32
			var choose func(Request, Plan) bool
			if name == "allow" {
				choose = func(Request, Plan) bool { decisions.Add(1); return true }
			}
			proxy, opens, stalls := ordinaryPassthroughProxy(t, address, choose)
			raw, _ := connectVia(t, proxy.Address(), "example.com:443")
			// Real TLS generates a replay-eligible ClientHello. No certificate can
			// be accepted because the original origin never sends any bytes.
			secure := tls.Client(raw, &tls.Config{ServerName: "example.com", MinVersion: tls.VersionTLS12})
			defer secure.Close()
			secure.SetDeadline(time.Now().Add(3 * time.Second))
			if err := secure.Handshake(); err == nil {
				t.Fatal("silent origin unexpectedly completed TLS")
			}
			if opens.Load() != 1 || stalls.Load() != 1 || name == "allow" && decisions.Load() != 1 {
				t.Fatal("browser stall recovery was disabled globally", name, opens.Load(), stalls.Load(), decisions.Load())
			}
			if failures := proxy.Snapshot().Failures; failures["DIRECT_STALL"] != 1 {
				t.Fatal("default browser stall lost its diagnostic", failures)
			}
		})
	}
}
