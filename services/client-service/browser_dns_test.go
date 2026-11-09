package clientservice

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/buzzmean/neexitlag/core/browserproxy"
	"github.com/buzzmean/neexitlag/core/flowpolicy"
	"github.com/buzzmean/neexitlag/core/profiles"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
	"time"
)

func TestOriginComparisonStrictlyRelayOnlyAndReadOnly(t *testing.T) {
	c := New(context.Background())
	defer c.Close()
	c.Profiles.Upsert(profiles.Profile{ID: "keep", Name: "existing", Executables: []string{`C:\Apps\chrome.exe`}, Mode: profiles.Auto})
	before, _ := json.Marshal(c.Profiles.List())
	for _, raw := range []string{`{"host":"a.local","candidates":["8.8.8.8"]}`, `{"host":"example.com","candidates":["127.0.0.1"]}`, `{"host":"example.com","candidates":["169.254.169.254"]}`, `{"host":"example.com","candidates":["8.8.8.8","8.8.8.8"]}`, `{"host":"example.com","candidates":["8.8.8.8","::ffff:8.8.8.8"]}`, `{"host":"example.com","candidates":[]}`, `{"host":"example.com","candidates":["8.8.8.8"],"insecure":true}`} {
		if _, err := c.Handle(context.Background(), "browser.origin.check", []byte(raw)); err == nil {
			t.Fatal("invalid diagnostic accepted", raw)
		}
	}
	// No relay configured: a public destination must fail BEFORE any DIRECT dial.
	response, err := c.Handle(context.Background(), "browser.origin.check", []byte(`{"host":"example.com","candidates":["8.8.8.8"]}`))
	if err != nil {
		t.Fatal(err)
	}
	wire, _ := json.Marshal(response)
	var report struct {
		Candidates []struct {
			Route    string                          `json:"route"`
			Verified bool                            `json:"origin_verified"`
			Origin   struct{ Failure, Phase string } `json:"origin"`
		} `json:"candidates"`
	}
	if json.Unmarshal(wire, &report) != nil || len(report.Candidates) != 1 {
		t.Fatal(string(wire))
	}
	result := report.Candidates[0]
	if result.Route != string(flowpolicy.RelayRequired) || result.Verified || result.Origin.Phase != "RELAY_OR_TCP_OPEN" || result.Origin.Failure == "" {
		t.Fatal(string(wire))
	}
	after, _ := json.Marshal(c.Profiles.List())
	if string(before) != string(after) || c.Snapshot().Optimizing {
		t.Fatal("read-only check changed profiles/optimization")
	}
}

func TestDNSRecoveredPinAvailableToQueuedChromeRequests(t *testing.T) {
	c := New(context.Background())
	defer c.Close()
	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("independent origin proof")) }))
	defer target.Close()
	roots := x509.NewCertPool()
	roots.AddCert(target.Certificate())
	destination := target.Listener.Addr().(*net.TCPAddr).AddrPort()
	current := profilesResult{profile: profiles.Profile{ID: "chrome", Name: "Chrome", Executables: []string{`C:\Apps\chrome.exe`}, Mode: profiles.Auto}, network: "network-A", enabled: true}
	q := browserproxy.Request{Host: "example.com", Port: destination.Port(), Secure: true}
	// This test supplies a local TLS origin to the cache; the separate core
	// integration proves actual authenticated relay DNS + origin I/O.
	result := c.browser.dns.Recover(context.Background(), c.browserDNSKey(q, current), q.Host, q.Port, roots, func(context.Context, string, browserproxy.DNSOpen) (browserproxy.DNSAnswer, error) {
		return browserproxy.DNSAnswer{Addresses: []netip.Addr{destination.Addr()}, TTL: time.Minute, Source: "ISOLATED_TLS", ObtainedAt: time.Now()}, nil
	}, func(ctx context.Context, _ netip.AddrPort) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "tcp", destination.String())
	})
	if !result.Verified {
		t.Fatal(result)
	}
	// Exactly as after the primary planner completed recovery: ordinary learning
	// is empty. Both initial requests and pending-channel waiters use this reader.
	for i := 0; i < 2; i++ {
		plan, ok := c.browserDNSCachedPlan(q, current)
		if !ok || plan.Destination != destination || plan.Policy.Action != flowpolicy.RelayRequired || plan.Policy.Fallback != flowpolicy.Required {
			t.Fatal("queued request reverted to bad system DNS", plan, ok)
		}
	}
	changed := current
	changed.network = "network-B"
	if _, ok := c.browserDNSCachedPlan(q, changed); ok {
		t.Fatal("cross-network pin")
	}
	changed = current
	changed.profile.RelayID = "VPS-02"
	if _, ok := c.browserDNSCachedPlan(q, changed); ok {
		t.Fatal("cross-relay pin")
	}
	changed = current
	changed.enabled = false
	if _, ok := c.browserDNSCachedPlan(q, changed); ok {
		t.Fatal("disabled optimization used recovered pin")
	}
	changed = current
	changed.profile.Rules = []flowpolicy.Rule{{ID: "block", Domains: []string{q.Host}, Action: flowpolicy.Block}}
	if _, ok := c.browserDNSCachedPlan(q, changed); ok {
		t.Fatal("new BLOCK policy ignored")
	}
}

func TestGooglevideoDNSRecoveryIsAttemptedAndExplicitDirectPlusIsPreserved(t *testing.T) {
	c := New(context.Background())
	defer c.Close()
	cur := profilesResult{profile: profiles.Profile{ID: "chrome", Mode: profiles.Auto, Executables: []string{`C:\Chrome\chrome.exe`}}, network: "net", enabled: true}
	calls := 0
	c.BrowserAlternativeDNS = func(context.Context, string, browserproxy.DNSOpen) (browserproxy.DNSAnswer, error) {
		calls++
		return browserproxy.DNSAnswer{}, errors.New("controlled NXDOMAIN")
	}
	q := browserproxy.Request{Host: "rr1---sn-q4fl6ns6.googlevideo.com", Port: 443, Secure: true}
	result, ok := c.recoverBrowserDNS(context.Background(), q, cur, browserproxy.Plan{})
	if ok || calls != 1 || result.DNSRecovery == nil || result.DNSRecovery.Failure != "DNS_ALTERNATIVE_FAILED" {
		t.Fatal("CDN DNS failure hidden or recovery excluded", calls, result)
	}
	c.recoverBrowserDNS(context.Background(), q, cur, browserproxy.Plan{})
	if calls != 1 {
		t.Fatal("negative cooldown ignored")
	}
	cur.profile.Rules = []flowpolicy.Rule{{ID: "local", Domains: []string{"googlevideo.com"}, Action: flowpolicy.DirectPlus, Strategy: "baseline"}}
	c.recoverBrowserDNS(context.Background(), browserproxy.Request{Host: "another.googlevideo.com", Port: 443, Secure: true}, cur, browserproxy.Plan{})
	if calls != 1 {
		t.Fatal("DNS recovery overrode configured DIRECT+")
	}
}
func TestGooglevideoRecoveredDNSPinRequiresOriginalSNICertificateAndHTTP(t *testing.T) {
	for _, status := range []int{200, 403, 404} {
		t.Run(fmt.Sprint(status), func(t *testing.T) { checkGooglevideoDNSOrigin(t, status) })
	}
}
func checkGooglevideoDNSOrigin(t *testing.T, status int) {
	c := New(context.Background())
	defer c.Close()
	host := "rr1---sn-q4fl6ns6.googlevideo.com"
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	template := &x509.Certificate{SerialNumber: big.NewInt(1), DNSNames: []string{host}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, BasicConstraintsValid: true}
	der, err := x509.CreateCertificate(rand.Reader, template, template, pub, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	roots := x509.NewCertPool()
	roots.AddCert(cert)
	target := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS.ServerName != host || r.Method != "GET" {
			t.Error("origin identity/probe mismatch")
		}
		w.WriteHeader(status)
		w.Write([]byte("controlled CDN origin"))
	}))
	target.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}
	target.StartTLS()
	defer target.Close()
	dst := target.Listener.Addr().(*net.TCPAddr).AddrPort()
	cur := profilesResult{profile: profiles.Profile{ID: "chrome", Mode: profiles.Auto}, network: "net", enabled: true}
	q := browserproxy.Request{Host: host, Port: dst.Port(), Secure: true}
	lookup := func(context.Context, string, browserproxy.DNSOpen) (browserproxy.DNSAnswer, error) {
		return browserproxy.DNSAnswer{Addresses: []netip.Addr{dst.Addr()}, TTL: time.Second, ObtainedAt: time.Now()}, nil
	}
	open := func(ctx context.Context, _ netip.AddrPort) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "tcp", dst.String())
	}
	bad := c.browser.dns.Recover(context.Background(), "wrong-certificate", host, dst.Port(), nil, lookup, open)
	if bad.Verified {
		t.Fatal("untrusted certificate accepted")
	}
	result := c.browser.dns.Recover(context.Background(), c.browserDNSKey(q, cur), host, dst.Port(), roots, lookup, open)
	if !result.Usable() || result.Verified != (status == 200) {
		t.Fatal(result)
	}
	plan, ok := c.browserDNSCachedPlan(q, cur)
	if !ok || plan.Destination != dst || plan.Policy.Action != flowpolicy.RelayRequired || plan.Policy.Fallback != flowpolicy.Required {
		t.Fatal("CDN pin ignored or leaked DIRECT", plan)
	}
	cur.profile.Rules = []flowpolicy.Rule{{ID: "local", Domains: []string{"googlevideo.com"}, Action: flowpolicy.DirectPlus, Strategy: "baseline"}}
	if _, ok := c.browserDNSCachedPlan(q, cur); ok {
		t.Fatal("cached DNS recovery overrode DIRECT+")
	}
	if _, ok := c.browser.dns.Lookup(c.browserDNSKey(q, cur), time.Now().Add(2*time.Second)); ok {
		t.Fatal("DNS TTL extended")
	}
}
