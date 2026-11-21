package integration

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/buzzmean/neexitlag/core/browserproxy"
)

// Real ticket-authenticated QUIC+mTLS -> silent TCP -> alternate verified TLS
// origin. Browser TLS transcript is unchanged; no certificate bypass or MITM.
func TestRelayOriginFailoverPreservesVerifiedTLSAndEstablishedHTTP(t *testing.T) {
	for _, kind := range []string{"silent", "eof"} {
		t.Run(kind, func(t *testing.T) {
			fixture := newLeaseFixture(t, 30*time.Second, 0)
			target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.TLS.ServerName != "example.com" || r.Host != "example.com" {
					t.Error("SNI/Host changed")
				}
				io.WriteString(w, "verified origin response")
			}))
			defer target.Close()
			bad, err := net.Listen("tcp4", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer bad.Close()
			go func() {
				c, e := bad.Accept()
				if e != nil {
					return
				}
				defer c.Close()
				var p [4096]byte
				c.Read(p[:])
				if kind == "silent" {
					io.Copy(io.Discard, c)
				}
			}()
			one := bad.Addr().(*net.TCPAddr).AddrPort()
			two := target.Listener.Addr().(*net.TCPAddr).AddrPort()
			raw, err := fixture.client.OpenTCP(context.Background(), one)
			if err != nil {
				t.Fatal(err)
			}
			var opens atomic.Int32
			h := browserproxy.NewOriginHealth()
			conn := browserproxy.WatchRelayOrigin(raw, browserproxy.OriginConfig{Context: context.Background(), Health: h, Scope: "network/profile/example.com/443/VPS-01", Initial: one, Candidates: []netip.AddrPort{one, two}, Open: func(ctx context.Context, dst netip.AddrPort) (net.Conn, error) {
				opens.Add(1)
				return fixture.client.OpenTCP(ctx, dst)
			}})
			defer conn.Close()
			roots := x509.NewCertPool()
			roots.AddCert(target.Certificate())
			tc := tls.Client(conn, &tls.Config{ServerName: "example.com", RootCAs: roots, MinVersion: tls.VersionTLS13, CurvePreferences: []tls.CurveID{tls.X25519MLKEM768}, NextProtos: []string{"http/1.1"}})
			ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
			defer cancel()
			if err := tc.HandshakeContext(ctx); err != nil {
				t.Fatal(err)
			}
			reader := bufio.NewReader(tc)
			for i := 0; i < 2; i++ {
				fmt.Fprint(tc, "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
				response, err := http.ReadResponse(reader, nil)
				if err != nil {
					t.Fatal(err)
				}
				body, err := io.ReadAll(response.Body)
				response.Body.Close()
				if err != nil || response.StatusCode != 200 || string(body) != "verified origin response" {
					t.Fatal(response, err, string(body))
				}
			}
			report := conn.(browserproxy.OriginReporter).OriginAttempts()
			if opens.Load() != 1 || report.AddressAttempts != 2 || report.Selected != two.String() || report.ReplayedBytes < 1000 {
				t.Fatal(opens.Load(), report)
			}
			// Two full HTTP results on the same established stream, not app reconnect.
			if ip, _ := h.Pick("network/profile/example.com/443/VPS-01", []netip.AddrPort{one, two}, nil, time.Now()); ip != two {
				t.Fatal("negative address not skipped", ip)
			}
		})
	}
}
