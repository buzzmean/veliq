package clientservice

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/buzzmean/veliq/core/browserproxy"
	"github.com/buzzmean/veliq/core/profiles"
	wp "github.com/buzzmean/veliq/platform/windows"
	"golang.org/x/net/dns/dnsmessage"
)

func brokerWire(t *testing.T, host string) ([]byte, []byte) {
	t.Helper()
	name, _ := dnsmessage.NewName(host + ".")
	q := dnsmessage.Question{Name: name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}
	m := dnsmessage.Message{Header: dnsmessage.Header{ID: 19}, Questions: []dnsmessage.Question{q}}
	query, _ := m.Pack()
	m.Response = true
	m.Answers = []dnsmessage.Resource{{Header: dnsmessage.ResourceHeader{Name: name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 10}, Body: &dnsmessage.AResource{A: [4]byte{87, 240, 137, 208}}}}
	reply, _ := m.Pack()
	return query, reply
}
func TestBrowserDNSProtectedNeverUsesSystemResolverAndOwnsHints(t *testing.T) {
	c, cur := timeoutFixture(t)
	tuple := policyTuple("udp", 53)
	tuple.Destination = netip.MustParseAddrPort("127.0.0.1:53")
	for _, host := range []string{"www.youtube.com", "r1.googlevideo.com", "ytimg.com", "ggpht.com", "web.telegram.org", "claude.ai", "chatgpt.com"} {
		query, reply := brokerWire(t, host)
		calls := 0
		out, err := c.exchangeBrowserDNS(context.Background(), cur, tuple, query, func(context.Context, profilesResult, wp.Tuple, []byte) ([]byte, error) { calls++; return reply, nil })
		if err != nil || len(out) == 0 || calls != 1 {
			t.Fatal(host, err, calls)
		}
	}
	query, _ := brokerWire(t, "chatgpt.com")
	if _, err := c.exchangeBrowserDNS(context.Background(), cur, tuple, query, func(context.Context, profilesResult, wp.Tuple, []byte) ([]byte, error) {
		return nil, errors.New("relay unavailable")
	}); err == nil {
		t.Fatal("protected DNS failed open")
	}
	ip := netip.MustParseAddr("87.240.137.208")
	e := c.browser.domains.profileEvidence(cur.network, cur.profile.ID, ip, "", time.Now())
	if !e.Restricted || !e.Ambiguous || e.Source != "BROWSER_DNS_REPLY_AMBIGUOUS" {
		t.Fatal(e)
	}
	for _, scope := range []struct{ network, profile string }{{"other", cur.profile.ID}, {cur.network, "edge"}} {
		if e := c.browser.domains.profileEvidence(scope.network, scope.profile, ip, "", time.Now()); e.Restricted || len(e.Candidates) > 0 {
			t.Fatal("cross browser/network DNS hint", e)
		}
	}
	if e := c.browser.domains.profileEvidence(cur.network, cur.profile.ID, ip, "", time.Now().Add(11*time.Second)); e.Restricted {
		t.Fatal("TTL extended", e)
	}
}
func TestBrowserDNSOrdinaryUsesOriginalResolverAndSurvivesOSRefresh(t *testing.T) {
	c, cur := timeoutFixture(t)
	query, reply := brokerWire(t, "vk.ru")
	server, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		var b [8192]byte
		_, peer, e := server.ReadFrom(b[:])
		if e == nil {
			server.WriteTo(reply, peer)
		}
	}()
	tuple := policyTuple("udp", 53)
	tuple.Destination = server.LocalAddr().(*net.UDPAddr).AddrPort()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_, err = c.exchangeBrowserDNS(ctx, cur, tuple, query, func(context.Context, profilesResult, wp.Tuple, []byte) ([]byte, error) {
		t.Error("ordinary DNS relayed")
		return nil, errors.New("forbidden")
	})
	if err != nil {
		t.Fatal(err)
	}
	<-done
	c.browser.domains.replace(cur.network, nil, errors.New("OS cache unavailable"), time.Now())
	e := c.browser.domains.profileEvidence(cur.network, cur.profile.ID, netip.MustParseAddr("87.240.137.208"), "", time.Now())
	if e.Domain != "vk.ru" || e.Restricted || e.Source != "BROWSER_DNS_REPLY_PROFILE_TTL_HINT" {
		t.Fatal(e)
	}
}
func TestBrowserDNSHooksOnlyNativeEnabledSelectedBrowsers(t *testing.T) {
	c, p, _ := nativeEdgeFixture(t)
	c.enabled = true
	c.settings.Automatic = true
	p.Mode = profiles.Auto
	p.BrowserTransport = "native"
	c.Profiles.Upsert(p)
	id := wp.ProcessIdentity{PID: 77, CreationTime: 1, Path: p.Executables[0]}
	for _, proto := range []string{"udp", "tcp"} {
		d := c.Classify(id, policyTuple(proto, 53))
		if d.DNSExchange == nil || !d.Route.Direct() || d.Deferred {
			t.Fatal(proto, d)
		}
		if proto == "tcp" && d.OpenDeferred == nil {
			t.Fatal("TCP DNS still pass-through")
		}
	}
	for _, off := range []bool{false, true} {
		c.enabled = !off
		other := id
		if !off {
			other.Path = `C:\Games\TslGame.exe`
		}
		if d := c.Classify(other, policyTuple("udp", 53)); d.DNSExchange != nil {
			t.Fatal("unrelated/disabled DNS intercepted", d)
		}
	}
}
func TestBrowserDNSHintCapacityAndZeroTTL(t *testing.T) {
	var x browserDomainIndex
	now := time.Now()
	x.observeBrowserDNS("net", "chrome", []browserproxy.DNSHint{{Name: "www.youtube.com", Address: "8.8.8.8", TTL: 0}}, now)
	if e := x.profileEvidence("net", "chrome", netip.MustParseAddr("8.8.8.8"), "", now); e.Restricted {
		t.Fatal(e)
	}
	for i := 0; i < 1200; i++ {
		ip := netip.AddrFrom4([4]byte{8, 8, byte(i >> 8), byte(i)})
		x.observeBrowserDNS("net", "chrome", []browserproxy.DNSHint{{Name: "www.youtube.com", Address: ip.String(), TTL: 10}}, now)
	}
	if len(x.owned) > 1024 {
		t.Fatal("unbounded DNS hints", len(x.owned))
	}
}
