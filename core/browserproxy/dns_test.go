package browserproxy

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/buzzmean/veliq/core/security"
	"github.com/buzzmean/veliq/core/transport"
	"github.com/buzzmean/veliq/services/relay"
	"github.com/buzzmean/veliq/tools/labcert"
	"golang.org/x/net/dns/dnsmessage"
)

func dnsWire(t *testing.T, host string, ttl uint32, ip [4]byte) []byte {
	t.Helper()
	name, _, err := dnsQuestion(host)
	if err != nil {
		t.Fatal(err)
	}
	msg := dnsmessage.Message{Header: dnsmessage.Header{Response: true}, Questions: []dnsmessage.Question{{Name: name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}}, Answers: []dnsmessage.Resource{{Header: dnsmessage.ResourceHeader{Name: name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: ttl}, Body: &dnsmessage.AResource{A: ip}}}}
	data, err := msg.Pack()
	if err != nil {
		t.Fatal(err)
	}
	return data
}
func TestAlternativeDNSRejectsPoisonedAndMalformedAnswers(t *testing.T) {
	name, _, _ := dnsQuestion("example.com")
	for _, ip := range [][4]byte{{127, 0, 0, 1}, {10, 0, 0, 1}, {169, 254, 169, 254}, {100, 64, 0, 1}, {0, 1, 2, 3}, {224, 1, 1, 1}, {192, 0, 2, 1}, {240, 1, 2, 3}, {192, 88, 99, 1}} {
		if _, e := decodeDNS(dnsWire(t, "example.com", 30, ip), name); e == nil {
			t.Fatal("nonpublic accepted", ip)
		}
	}
	good := dnsWire(t, "example.com", 2, [4]byte{8, 8, 4, 4})
	a, e := decodeDNS(good, name)
	if e != nil || a.TTL != 2*time.Second || len(a.Addresses) != 1 {
		t.Fatal(a, e)
	}
	wrong, _, _ := dnsQuestion("other.example")
	if _, e = decodeDNS(good, wrong); e == nil {
		t.Fatal("wrong question accepted")
	}
	good[0] = 1
	if _, e = decodeDNS(good, name); e == nil {
		t.Fatal("wrong transaction accepted")
	}
	for _, host := range []string{"localhost", "a.local", "a.lan", "a.internal", "a.onion", "home.arpa", "a.home.arpa", "a.test", "1.1.1.1", "a..com", "-bad.com", "example.com\r\nHost:bad"} {
		if ValidPublicDNSName(host) {
			t.Fatal(host)
		}
	}
	// CNAME TTL is part of the result's lifetime; unrelated answer injection is not.
	canonical, _ := dnsmessage.NewName("alias.example.")
	var msg dnsmessage.Message
	msg.Unpack(dnsWire(t, "example.com", 60, [4]byte{8, 8, 4, 4}))
	msg.Answers[0].Header.Name = canonical
	msg.Answers = append(msg.Answers, dnsmessage.Resource{Header: dnsmessage.ResourceHeader{Name: name, Type: dnsmessage.TypeCNAME, Class: dnsmessage.ClassINET, TTL: 1}, Body: &dnsmessage.CNAMEResource{CNAME: canonical}})
	wire, _ := msg.Pack()
	a, e = decodeDNS(wire, name)
	if e != nil || a.TTL != time.Second {
		t.Fatal(a, e)
	}
}

func TestPoisonedDNSRecoveryThroughAuthenticatedRelayTLSHTTP(t *testing.T) {
	var queries atomic.Uint64
	target := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		source, _, _ := net.SplitHostPort(r.RemoteAddr)
		if source != "127.0.0.2" {
			t.Error("non-relay request", source)
		}
		if r.TLS.ServerName != "example.com" {
			t.Error("wrong SNI", r.TLS.ServerName)
		}
		if r.URL.Path == "/dns-query" {
			queries.Add(1)
			if r.Method != "POST" || r.Header.Get("Content-Type") != "application/dns-message" {
				t.Error("not RFC8484")
			}
			wire, e := io.ReadAll(r.Body)
			if e != nil {
				t.Error(e)
			}
			var question dnsmessage.Message
			if question.Unpack(wire) != nil || len(question.Questions) != 1 || question.Questions[0].Name.String() != "example.com." {
				t.Error("query mismatch")
			}
			w.Header().Set("Content-Type", "application/dns-message")
			w.Write(dnsWire(t, "example.com", 2, [4]byte{8, 8, 4, 4}))
			return
		}
		if r.Method != "GET" || r.URL.Path != "/" || r.Header.Get("Cookie") != "" {
			t.Error("wrong origin proof")
		}
		io.WriteString(w, "controlled full response over relay")
	}))
	target.EnableHTTP2 = true
	target.StartTLS()
	defer target.Close()
	roots := x509.NewCertPool()
	roots.AddCert(target.Certificate())
	bad, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer bad.Close()
	go func() {
		for {
			conn, e := bad.Accept()
			if e != nil {
				return
			}
			go func() {
				defer conn.Close()
				var b [4096]byte
				conn.Read(b[:])
				io.WriteString(conn, "HTTP/1.1 200 Wrong-DNS\r\n\r\n")
			}()
		}
	}()
	st, ct, err := labcert.Pair()
	if err != nil {
		t.Fatal(err)
	}
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	srv, err := relay.Listen("127.0.0.1:0", relay.Config{TLS: st, TicketVerifier: security.NewTicketVerifier(map[string]ed25519.PublicKey{"test": pub}, "VPS-01"), Allow: []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}, Acceptance: &relay.AcceptanceConfig{LeaseDuration: 90 * time.Second, OutboundSource: netip.MustParseAddr("127.0.0.2")}})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	now := time.Now()
	id, _ := security.NewID()
	device := ct.Certificates[0].PrivateKey.(ed25519.PrivateKey).Public().(ed25519.PublicKey)
	ticket, err := security.Sign("ticket", "test", key, security.Ticket{ID: id, DeviceID: "dns", DeviceKey: security.Fingerprint(device), RelayID: "VPS-01", IssuedAt: now, ExpiresAt: now.Add(time.Minute)})
	if err != nil {
		t.Fatal(err)
	}
	peer, err := transport.DialWithTicket(context.Background(), srv.Addr().String(), ct, ticket)
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	// Isolated virtual Internet mapping, never public DNS/VPS access. The relay
	// still performs real OPEN/dial/TCP and both TLS sessions are fully verified.
	open := func(ctx context.Context, dst netip.AddrPort) (net.Conn, error) {
		actual := target.Listener.Addr().(*net.TCPAddr).AddrPort()
		if dst.Addr() == netip.MustParseAddr("149.154.167.40") {
			actual = bad.Addr().(*net.TCPAddr).AddrPort()
		}
		return peer.OpenTCP(ctx, actual)
	}
	poisoned := ProbeOriginDetailed(context.Background(), "example.com", 443, true, roots, func(ctx context.Context) (net.Conn, error) {
		return open(ctx, netip.MustParseAddrPort("149.154.167.40:443"))
	})
	if poisoned.Detail != "INVALID_TLS_RECORD" || poisoned.Failure != "TLS_FAILED" {
		t.Fatal(poisoned)
	}
	resolver := &DoHResolver{providers: []dohProvider{{"example.com", netip.MustParseAddrPort("8.8.8.8:443")}}, roots: roots}
	recovery := NewDNSRecovery()
	recovered := recovery.Recover(context.Background(), "app/network-A/domain/policy", "example.com", 443, roots, resolver.Lookup, open)
	if !recovered.Verified || recovered.Destination != netip.MustParseAddrPort("8.8.4.4:443") || recovered.Probe.Status != 200 || recovered.Probe.ALPN != "h2" || recovered.Probe.Bytes == 0 {
		t.Fatal(recovered)
	}
	if recovered.Expires.After(time.Now().Add(2 * time.Second)) {
		t.Fatal("TTL extended", recovered)
	}
	count := queries.Load()
	again := recovery.Recover(context.Background(), "app/network-A/domain/policy", "example.com", 443, roots, resolver.Lookup, open)
	if !again.Verified || queries.Load() != count {
		t.Fatal("verified TTL cache missed")
	}
	if _, ok := recovery.Lookup("app/network-B/domain/policy", time.Now()); ok {
		t.Fatal("network crossed")
	}
	if _, ok := recovery.Lookup("app/network-A/domain/policy", recovered.Expires); ok {
		t.Fatal("TTL boundary accepted")
	}
	// Resolver certificate failure cannot create a candidate or a healthy cache.
	untrusted := &DoHResolver{providers: resolver.providers}
	result := NewDNSRecovery().Recover(context.Background(), "bad-cert", "example.com", 443, roots, untrusted.Lookup, open)
	if result.Verified || result.Failure == "" {
		t.Fatal("DoH certificate bypass", result)
	}
	// Even a valid DNS response is insufficient if the ORIGIN certificate fails.
	result = NewDNSRecovery().Recover(context.Background(), "bad-origin", "other.example", 443, roots, func(context.Context, string, DNSOpen) (DNSAnswer, error) {
		return DNSAnswer{Addresses: []netip.Addr{netip.MustParseAddr("8.8.4.4")}, TTL: time.Minute}, nil
	}, open)
	if result.Verified || result.Probe.Failure != "TLS_CERTIFICATE_ERROR" {
		t.Fatal("origin certificate bypass", result)
	}
}

func TestDNSRecoveryNegativeSingleflightAndBound(t *testing.T) {
	recovery := NewDNSRecovery()
	var calls atomic.Int32
	start := make(chan struct{})
	release := make(chan struct{})
	lookup := func(context.Context, string, DNSOpen) (DNSAnswer, error) {
		if calls.Add(1) == 1 {
			close(start)
			<-release
		}
		return DNSAnswer{}, errors.New("unavailable")
	}
	var wg sync.WaitGroup
	results := make(chan DNSRecoveryResult, 12)
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			results <- recovery.Recover(context.Background(), "same-domain-network", "example.com", 443, nil, lookup, nil)
		}()
	}
	<-start
	close(release)
	wg.Wait()
	close(results)
	for result := range results {
		if result.Verified {
			t.Fatal(result)
		}
	}
	if calls.Load() != 1 {
		t.Fatal("duplicate negative DNS queries", calls.Load())
	}
	for i := 0; i < 512; i++ {
		recovery.entries[fmt.Sprint(i)] = &dnsRecoveryEntry{until: time.Now().Add(time.Minute)}
	}
	result := recovery.Recover(context.Background(), "overflow", "example.com", 443, nil, lookup, nil)
	if result.Failure != "DNS_RECOVERY_CAPACITY" || calls.Load() != 1 {
		t.Fatal("unbounded admission", result, calls.Load())
	}
}

func TestDoHHTTPAgeAndCacheControlNeverExtendDNSLifetime(t *testing.T) {
	cases := []struct {
		age, cache string
		want       time.Duration
	}{{"1", "", time.Second}, {"99", "", 0}, {"invalid", "", 0}, {"", "no-store", 0}, {"", "max-age=0", 0}, {"", "max-age=300", 2 * time.Second}}
	for _, tc := range cases {
		t.Run(tc.age+tc.cache, func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/dns-message")
				w.Header().Set("Age", tc.age)
				w.Header().Set("Cache-Control", tc.cache)
				w.Write(dnsWire(t, "example.com", 2, [4]byte{8, 8, 4, 4}))
			}))
			defer server.Close()
			roots := x509.NewCertPool()
			roots.AddCert(server.Certificate())
			resolver := &DoHResolver{providers: []dohProvider{{"example.com", netip.MustParseAddrPort("8.8.8.8:443")}}, roots: roots}
			answer, err := resolver.Lookup(context.Background(), "example.com", func(ctx context.Context, _ netip.AddrPort) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, "tcp", server.Listener.Addr().String())
			})
			if err != nil || answer.TTL != tc.want {
				t.Fatal(answer, err)
			}
		})
	}
}

func TestAlternativeDNSRetainsAllBoundedAddressesForIPHealthSelection(t *testing.T) {
	name, _, _ := dnsQuestion("example.com")
	msg := dnsmessage.Message{Header: dnsmessage.Header{Response: true}, Questions: []dnsmessage.Question{{Name: name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}}}
	for i := 1; i <= 8; i++ {
		msg.Answers = append(msg.Answers, dnsmessage.Resource{Header: dnsmessage.ResourceHeader{Name: name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 60}, Body: &dnsmessage.AResource{A: [4]byte{8, 8, 8, byte(i)}}})
	}
	raw, err := msg.Pack()
	if err != nil {
		t.Fatal(err)
	}
	a, err := decodeDNS(raw, name)
	if err != nil || len(a.Addresses) != 8 {
		t.Fatal(a, err)
	}
	h := NewOriginHealth()
	candidates := []netip.AddrPort{}
	now := time.Now()
	for i, ip := range a.Addresses {
		dst := netip.AddrPortFrom(ip, 443)
		candidates = append(candidates, dst)
		if i < 5 {
			h.Failed("network/profile/domain", dst, now)
		}
	}
	selected, skipped := h.Pick("network/profile/domain", candidates, nil, now)
	if selected != candidates[5] || skipped != 5 {
		t.Fatal("candidate after third address was lost", selected, skipped)
	}
}

func TestAlternativeDNSAllProvidersCanRepairValidButBadFirstAnswer(t *testing.T) {
	var calls atomic.Int32
	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := calls.Add(1)
		w.Header().Set("Content-Type", "application/dns-message")
		w.Write(dnsWire(t, "web.telegram.org", 60, [4]byte{8, 8, 8, byte(n)}))
	}))
	defer target.Close()
	roots := x509.NewCertPool()
	roots.AddCert(target.Certificate())
	resolver := &DoHResolver{roots: roots, providers: []dohProvider{{"example.com", netip.MustParseAddrPort("8.8.8.8:443")}, {"example.com", netip.MustParseAddrPort("1.1.1.1:443")}}}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	a, err := resolver.LookupAll(ctx, "web.telegram.org", func(ctx context.Context, _ netip.AddrPort) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "tcp", target.Listener.Addr().String())
	})
	if err != nil || calls.Load() != 2 || len(a.Addresses) != 2 || a.Addresses[1] != netip.MustParseAddr("8.8.8.2") {
		t.Fatal(a, err, calls.Load())
	}
}
