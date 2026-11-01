package browserproxy

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
	"time"

	"github.com/buzzmean/neexitlag/core/security"
	"github.com/buzzmean/neexitlag/core/transport"
	"github.com/buzzmean/neexitlag/services/relay"
	"github.com/buzzmean/neexitlag/tools/labcert"
	"golang.org/x/net/dns/dnsmessage"
)

func TestDNSWireRecoveryAuthenticatedRelayToHTTPData(t *testing.T) {
	roots := x509.NewCertPool()
	serve := func(h http.HandlerFunc) *httptest.Server {
		s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			source, _, _ := net.SplitHostPort(r.RemoteAddr)
			if source != "127.0.0.2" {
				t.Error("DNS/origin bypassed authenticated relay", source)
			}
			h(w, r)
		}))
		t.Cleanup(s.Close)
		roots.AddCert(s.Certificate())
		return s
	}
	negative := serve(wireResponseHandler(t, dnsmessage.RCodeNameError))
	positive := serve(wireResponseHandler(t, dnsmessage.RCodeSuccess))
	origin := serve(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS.ServerName != "example.com" || r.URL.Path != "/" {
			t.Error("wrong origin proof")
		}
		w.Write([]byte("independent verified HTTP response after DNS recovery"))
	})
	st, ct, e := labcert.Pair()
	if e != nil {
		t.Fatal(e)
	}
	pub, key, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	server, e := relay.Listen("127.0.0.1:0", relay.Config{TLS: st, TicketVerifier: security.NewTicketVerifier(map[string]ed25519.PublicKey{"dns-test": pub}, "isolated"), Allow: []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}, Acceptance: &relay.AcceptanceConfig{LeaseDuration: 90 * time.Second, OutboundSource: netip.MustParseAddr("127.0.0.2")}})
	if e != nil {
		t.Fatal(e)
	}
	defer server.Close()
	id, e := security.NewID()
	if e != nil {
		t.Fatal(e)
	}
	now := time.Now()
	device := ct.Certificates[0].PrivateKey.(ed25519.PrivateKey).Public().(ed25519.PublicKey)
	ticket, e := security.Sign("ticket", "dns-test", key, security.Ticket{ID: id, DeviceID: "dns-wire", DeviceKey: security.Fingerprint(device), RelayID: "isolated", IssuedAt: now, ExpiresAt: now.Add(time.Minute)})
	if e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	peer, e := transport.DialWithTicket(ctx, server.Addr().String(), ct, ticket)
	if e != nil {
		t.Fatal(e)
	}
	defer peer.Close()
	r := &DoHResolver{roots: roots, providers: []dohProvider{{"example.com", netip.MustParseAddrPort("8.8.8.8:443")}, {"example.com", netip.MustParseAddrPort("1.1.1.1:443")}}}
	mapping := map[netip.AddrPort]*httptest.Server{r.providers[0].address: negative, r.providers[1].address: positive, netip.MustParseAddrPort("142.251.1.94:443"): origin}
	var opened []netip.AddrPort
	open := func(ctx context.Context, dst netip.AddrPort) (net.Conn, error) {
		s, ok := mapping[dst]
		if !ok || dst.Port() != 443 {
			t.Error("unapproved destination or raw DNS/53", dst)
			return nil, context.Canceled
		}
		opened = append(opened, dst)
		return peer.OpenTCP(ctx, s.Listener.Addr().(*net.TCPAddr).AddrPort())
	}
	query, _ := wireDNS(t, dnsmessage.TypeA)
	var m dnsmessage.Message
	m.Unpack(query)
	m.Questions[0].Name = dnsmessage.MustNewName("example.com.")
	query, _ = m.Pack()
	answer, e := r.ExchangeWire(ctx, query, open)
	if e != nil {
		t.Fatal(e)
	}
	hints, e := ValidateDNSResponse(query, answer)
	if e != nil || len(hints) != 1 || hints[0].Address != "142.251.1.94" || len(opened) != 2 {
		t.Fatal("negative DNS did not reach second authenticated provider", e, hints, opened)
	}
	dst := netip.AddrPortFrom(netip.MustParseAddr(hints[0].Address), 443)
	result := ProbeOriginDetailed(ctx, "example.com", 443, true, roots, func(ctx context.Context) (net.Conn, error) { return open(ctx, dst) })
	if result.Failure != "" || result.Status != 200 || result.Bytes == 0 || result.TLSVersion == 0 || len(opened) != 3 {
		t.Fatal("DNS answer did not lead to real authenticated HTTP data", result, opened)
	}
}
