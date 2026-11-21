package clientservice

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/buzzmean/neexitlag/core/browserproxy"
	"github.com/buzzmean/neexitlag/core/flowpolicy"
	"github.com/buzzmean/neexitlag/core/profiles"
)

// A real, cert-verified TLS + GET exchange after an ECH/DNS routing hint. Logical
// public IPs are mapped ONLY in this isolated open fixture; no production access.
func TestOpaqueTelegramSelectsVerifiedIPBeforeBrowserTLSAndPreservesStream(t *testing.T) {
	const host = "web.telegram.org"
	c, cur := timeoutFixture(t)
	cur.profile = profiles.Profile{ID: "chrome", Mode: profiles.Auto, Executables: []string{`C:\Apps\chrome.exe`}, BrowserTransport: "native"}
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	cert := &x509.Certificate{SerialNumber: big.NewInt(3), DNSNames: []string{host}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, pub, key)
	if err != nil {
		t.Fatal(err)
	}
	parsed, _ := x509.ParseCertificate(der)
	roots := x509.NewCertPool()
	roots.AddCert(parsed)
	c.BrowserProbeRoots = roots
	var requests, bad, lookups atomic.Int32
	target := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS.ServerName != host || r.Method != "GET" {
			t.Error("SNI/HTTP corrupted")
		}
		requests.Add(1)
		w.Write([]byte("verified Telegram fixture"))
	}))
	target.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}
	target.StartTLS()
	defer target.Close()
	one := netip.MustParseAddrPort("149.154.167.40:443")
	two := netip.MustParseAddrPort("149.154.167.99:443")
	c.BrowserAlternativeDNS = func(context.Context, string, browserproxy.DNSOpen) (browserproxy.DNSAnswer, error) {
		lookups.Add(1)
		return browserproxy.DNSAnswer{Addresses: []netip.Addr{one.Addr(), two.Addr()}, TTL: time.Minute, ObtainedAt: time.Now(), Source: "ISOLATED_RELAY_DNS"}, nil
	}
	open := func(ctx context.Context, dst netip.AddrPort) (net.Conn, error) {
		if dst == two {
			return (&net.Dialer{}).DialContext(ctx, "tcp", target.Listener.Addr().String())
		}
		if dst != one {
			t.Errorf("unexpected address %s", dst)
		}
		bad.Add(1)
		a, b := net.Pipe()
		go func() {
			defer b.Close()
			var record [5]byte
			if _, e := io.ReadFull(b, record[:]); e != nil {
				return
			}
			length := int(record[3])<<8 | int(record[4])
			io.CopyN(io.Discard, b, int64(length))
			b.Write([]byte{21, 3, 3, 0, 0})
		}()
		return a, nil
	}
	q := browserproxy.Request{Host: host, Port: 443, Secure: true}
	evidence := c.browser.domains.evidence(cur.network, one.Addr(), host, time.Now())
	if evidence.Domain != host || !evidence.Restricted {
		t.Fatal(evidence)
	}
	p := c.nativeOpaquePlan(cur.profile, policyTuple("tcp", 443), cur.network, evidence)
	p.Destination = one
	for attempt := 0; attempt < 2; attempt++ {
		plan := c.prepareHintedRelayOrigin(context.Background(), cur, q, p, open)
		if plan.Destination != two || plan.Policy.Action != flowpolicy.RelayRequired || plan.Policy.Fallback != flowpolicy.Required || plan.DNSRecovery == nil || !plan.DNSRecovery.Verified {
			t.Fatal(plan)
		}
		// Browser application socket starts only after candidate selection; TLS bytes
		// (including SNI/ALPN) pass untouched through existing originConn machinery.
		raw, err := open(context.Background(), plan.Destination)
		if err != nil {
			t.Fatal(err)
		}
		watched := c.watchKnownOrigin(raw, cur, q, plan, func(ctx context.Context, _ browserproxy.Request, p browserproxy.Plan) (net.Conn, error) {
			return open(ctx, p.Destination)
		})
		browser := tls.Client(watched, &tls.Config{RootCAs: roots, ServerName: host, MinVersion: tls.VersionTLS12, NextProtos: []string{"http/1.1"}})
		browser.SetDeadline(time.Now().Add(3 * time.Second))
		if err := browser.Handshake(); err != nil {
			t.Fatal(err)
		}
		io.WriteString(browser, "GET / HTTP/1.1\r\nHost: "+host+"\r\nConnection: close\r\n\r\n")
		response, err := http.ReadResponse(bufio.NewReader(browser), nil)
		if err != nil {
			t.Fatal(err)
		}
		body, err := io.ReadAll(response.Body)
		response.Body.Close()
		browser.Close()
		if err != nil || response.StatusCode != 200 || string(body) != "verified Telegram fixture" {
			t.Fatal(response.Status, err, string(body))
		}
	}
	if bad.Load() != 1 || lookups.Load() != 1 || requests.Load() != 3 {
		t.Fatal("missing bad-IP probe/TTL cache/browser GET", bad.Load(), lookups.Load(), requests.Load())
	}
}
func TestHintedOriginPreflightNeverProbesOrdinaryOrAmbiguousNames(t *testing.T) {
	c, cur := timeoutFixture(t)
	p := boundedDirectPlan()
	p.Enabled = true
	p.Policy = browserDNSPolicy(cur)
	c.BrowserAlternativeDNS = func(context.Context, string, browserproxy.DNSOpen) (browserproxy.DNSAnswer, error) {
		t.Fatal("unexpected query")
		return browserproxy.DNSAnswer{}, nil
	}
	for _, host := range []string{"", "ordinarysite.com", "rr1.googlevideo.com"} {
		q := browserproxy.Request{Host: host, Port: 443, Secure: true}
		got := c.prepareHintedRelayOrigin(context.Background(), cur, q, p, nil)
		if got.Destination != p.Destination || got.DNSRecovery != nil {
			t.Fatal(got)
		}
	}
}
