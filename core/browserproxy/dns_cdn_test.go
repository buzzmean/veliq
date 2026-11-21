package browserproxy

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
	"time"
)

func TestGooglevideoDNSAuthenticatedRootErrorIsNotDNSFailure(t *testing.T) {
	for _, tc := range []struct {
		host   string
		status int
		usable bool
	}{
		{"rr1---sn-q4fl6ns6.googlevideo.com", 200, true}, {"rr1---sn-q4fl6ns6.googlevideo.com", 403, true}, {"rr1---sn-q4fl6ns6.googlevideo.com", 404, true}, {"rr1---sn-q4fl6ns6.googlevideo.com", 500, false}, {"googlevideo.com.attacker.net", 403, false}, {"example.com", 403, false},
	} {
		t.Run(fmt.Sprint(tc.host, tc.status), func(t *testing.T) {
			host, status := tc.host, tc.status
			pub, key, _ := ed25519.GenerateKey(rand.Reader)
			cert := &x509.Certificate{SerialNumber: big.NewInt(1), DNSNames: []string{host}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, BasicConstraintsValid: true}
			der, err := x509.CreateCertificate(rand.Reader, cert, cert, pub, key)
			if err != nil {
				t.Fatal(err)
			}
			parsed, _ := x509.ParseCertificate(der)
			roots := x509.NewCertPool()
			roots.AddCert(parsed)
			target := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.TLS.ServerName != host || r.Method != "GET" || r.URL.Path != "/" {
					t.Error("wrong origin probe")
				}
				w.WriteHeader(status)
				fmt.Fprint(w, "CDN root requires a signed media URL")
			}))
			target.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}
			target.StartTLS()
			defer target.Close()
			dst := netip.MustParseAddrPort("8.8.4.4:443")
			calls := 0
			lookup := func(context.Context, string, DNSOpen) (DNSAnswer, error) {
				calls++
				return DNSAnswer{Addresses: []netip.Addr{dst.Addr()}, TTL: time.Second, ObtainedAt: time.Now()}, nil
			}
			open := func(ctx context.Context, _ netip.AddrPort) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, "tcp", target.Listener.Addr().String())
			}
			cache := NewDNSRecovery()
			got := cache.Recover(context.Background(), "network-profile-domain-port", host, 443, roots, lookup, open)
			if !tc.usable {
				if got.Failure == "" || got.Verified {
					t.Fatal("upstream failure learned healthy", got)
				}
				return
			}
			if got.Failure != "" || got.Destination != dst || got.Probe.Status != status {
				t.Fatalf("authenticated CDN HTTP response mislabeled DNS failure: %+v", got)
			}
			if got.Verified != (status == 200) {
				t.Fatal("root rejection called page success", got)
			}
			again := cache.Recover(context.Background(), "network-profile-domain-port", host, 443, roots, lookup, open)
			if calls != 1 || again.Destination != dst {
				t.Fatal("positive DNS TTL not reused")
			}
			if _, ok := cache.Lookup("different-network-profile", time.Now()); ok {
				t.Fatal("cross-scope cache")
			}
			if _, ok := cache.Lookup("network-profile-domain-port", time.Now().Add(2*time.Second)); ok {
				t.Fatal("DNS TTL extended")
			}
			untrusted := NewDNSRecovery().Recover(context.Background(), "untrusted", host, 443, nil, lookup, open)
			if untrusted.Failure == "" || untrusted.Verified {
				t.Fatal("untrusted origin accepted")
			}
		})
	}
}
