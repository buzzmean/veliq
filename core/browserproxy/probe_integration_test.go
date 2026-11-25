package browserproxy

import (
	"bufio"
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
	"slices"
	"testing"
	"time"

	"crypto/x509"
	"github.com/buzzmean/veliq/core/flowpolicy"
	"github.com/buzzmean/veliq/core/security"
	"github.com/buzzmean/veliq/core/transport"
	"github.com/buzzmean/veliq/services/relay"
	"github.com/buzzmean/veliq/tools/labcert"
)

// A real authenticated QUIC relay and an h2-only TLS origin. A TCP connection or
// HEAD response is deliberately not sufficient. No Internet/VPS credentials.
func TestOriginUnavailableDirectWorkingAuthenticatedRelayHTTP2(t *testing.T) {
	target := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" || r.URL.Path != "/" || r.Host != "example.com:"+targetPort(r) || r.ProtoMajor != 2 {
			t.Error("wrong origin request", r.Method, r.Host, r.Proto)
		}
		io.WriteString(w, "complete controlled origin document")
	}))
	target.EnableHTTP2 = true
	target.TLS = &tls.Config{GetConfigForClient: func(h *tls.ClientHelloInfo) (*tls.Config, error) {
		if h.ServerName != "example.com" || !slices.Contains(h.SupportedProtos, "h2") {
			return nil, errors.New("requires correct SNI and HTTP/2 ALPN")
		}
		return nil, nil
	}}
	target.StartTLS()
	defer target.Close()
	roots := x509.NewCertPool()
	roots.AddCert(target.Certificate())
	st, ct, err := labcert.Pair()
	if err != nil {
		t.Fatal(err)
	}
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	srv, err := relay.Listen("127.0.0.1:0", relay.Config{TLS: st, TicketVerifier: security.NewTicketVerifier(map[string]ed25519.PublicKey{"test": pub}, "VPS-01"), Allow: []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	now := time.Now()
	id, _ := security.NewID()
	device := ct.Certificates[0].PrivateKey.(ed25519.PrivateKey).Public().(ed25519.PublicKey)
	ticket, err := security.Sign("ticket", "test", key, security.Ticket{ID: id, DeviceID: "probe", DeviceKey: security.Fingerprint(device), RelayID: "VPS-01", IssuedAt: now, ExpiresAt: now.Add(time.Minute)})
	if err != nil {
		t.Fatal(err)
	}
	peer, err := transport.DialWithTicket(context.Background(), srv.Addr().String(), ct, ticket)
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	dest := target.Listener.Addr().(*net.TCPAddr).AddrPort()
	learning := flowpolicy.NewBrowserLearning()
	k := flowpolicy.LearnKey{Network: "test", Application: "chrome", Protocol: "tcp", Target: "example.com", Port: dest.Port()}
	a, err := learning.Begin(k, "", "VPS-01", now)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		p := ProbeOriginDetailed(context.Background(), "example.com", dest.Port(), true, roots, func(ctx context.Context) (net.Conn, error) {
			if a.Route.Action == flowpolicy.Direct {
				return nil, context.DeadlineExceeded
			}
			return peer.OpenTCP(ctx, dest)
		})
		if i == 1 && (p.Failure != "" || p.ALPN != "h2" || p.Bytes == 0 || p.Phase != "ORIGIN_RESPONSE") {
			t.Fatal(p)
		}
		a, err = learning.Observe(k, flowpolicy.BrowserObservation{Token: a.Token, Correlated: true, HTTPStatus: p.Status, ResponseBytes: p.Bytes, NetworkError: p.Failure, Destination: dest.String()}, "", "VPS-01", time.Now())
		if err != nil {
			t.Fatal(err)
		}
	}
	if !a.Confirmed || a.Route.Action != flowpolicy.RelayRequired || a.Route.Fallback != flowpolicy.Required || a.Destination != dest.String() {
		t.Fatal(a)
	}
}
func targetPort(r *http.Request) string { _, p, _ := net.SplitHostPort(r.Host); return p }

func TestProbeRejectsHeadersOnlyAndClassifiesTLSClosure(t *testing.T) {
	for _, tc := range []struct{ name, reply, phase, detail string }{
		{"truncated", "HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\n", "ORIGIN_BODY", "PEER_CLOSED"},
		{"empty", "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n", "ORIGIN_BODY", "EMPTY_BODY"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a, b := net.Pipe()
			go func() {
				defer b.Close()
				req, e := http.ReadRequest(bufio.NewReader(b))
				if e == nil {
					req.Body.Close()
					io.WriteString(b, tc.reply)
				}
			}()
			r := ProbeOriginDetailed(context.Background(), "example.com", 80, false, nil, func(context.Context) (net.Conn, error) { return a, nil })
			if r.Failure == "" || r.Phase != tc.phase || r.Detail != tc.detail {
				t.Fatal(r)
			}
		})
	}
	a, b := net.Pipe()
	go func() { var data [4096]byte; b.Read(data[:]); b.Close() }()
	r := ProbeOriginDetailed(context.Background(), "example.com", 443, true, nil, func(context.Context) (net.Conn, error) { return a, nil })
	if r.Phase != "ORIGIN_TLS" || r.Failure != "TLS_FAILED" || r.Detail != "PEER_CLOSED" {
		t.Fatal(r)
	}
}
