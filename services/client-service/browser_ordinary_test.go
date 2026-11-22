package clientservice

import (
	"bufio"
	"context"
	"crypto/tls"
	"github.com/buzzmean/neexitlag/core/browserproxy"
	"github.com/buzzmean/neexitlag/core/flowpolicy"
	"github.com/buzzmean/neexitlag/core/profiles"
	"io"
	"net"
	"net/http"
	"net/netip"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

func TestOrdinaryFailedIPTriesHealthySecondBeforeLadder(t *testing.T) {
	c, cur, q, p := youtubeFixture(t)
	q.Host = "akashi.vk-portal.net"
	second := netip.MustParseAddrPort("87.240.137.208:443")
	p.DirectCandidates = []netip.AddrPort{p.Destination, second}
	c.browser.directTimeouts.RecordTimeout(c.directTimeoutKey(cur, q, p), time.Now())
	calls := 0
	a, b := net.Pipe()
	defer b.Close()
	raw, actual, err := c.openBrowserPlan(context.Background(), cur, q, p, func(_ context.Context, _ browserproxy.Request, plan browserproxy.Plan) (net.Conn, error) {
		calls++
		if plan.Policy.Action != flowpolicy.Direct || plan.Destination != second {
			t.Errorf("one failed IP bypassed healthy DIRECT peer: %+v", plan)
		}
		return a, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	if calls != 1 || actual.Policy.Action != flowpolicy.Direct || actual.Destination != second {
		t.Fatal(calls, actual)
	}
}

func TestOrdinarySilentTLSUsesOtherDNSBeforeRelayAndReportsActualRoute(t *testing.T) {
	c, cur, q, p := youtubeFixture(t)
	q.Host = "akashi.vk-portal.net"
	p.Policy = flowpolicy.Result{Action: flowpolicy.RelayRequired, Source: "direct_timeout_cache", Fallback: flowpolicy.Required}
	second := netip.MustParseAddrPort("87.240.137.208:443")
	neighborIP := p.Destination.Addr().As4()
	neighborIP[3] ^= 1
	samePrefix := netip.AddrPortFrom(netip.AddrFrom4(neighborIP), q.Port)
	p.DirectCandidates = []netip.AddrPort{p.Destination, samePrefix, second, netip.MustParseAddrPort("93.186.225.194:443")}
	server, roots := youtubeTLSHTTPFixture(t, q.Host, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { io.WriteString(w, "ordinary direct works") }))
	var opens atomic.Int32
	raw, _, err := c.openBrowserPlan(context.Background(), cur, q, p, func(ctx context.Context, _ browserproxy.Request, actual browserproxy.Plan) (net.Conn, error) {
		opens.Add(1)
		if actual.Policy.Action != flowpolicy.Direct {
			t.Error("relay before DNS peer")
		}
		if actual.Destination == p.Destination {
			a, b := net.Pipe()
			go func() { defer b.Close(); io.Copy(io.Discard, b) }()
			return a, nil
		}
		if actual.Destination != second {
			t.Error("did not choose the distinct DNS prefix for the second attempt")
		}
		return (&net.Dialer{}).DialContext(ctx, "tcp", server.Listener.Addr().String())
	})
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	secure := tls.Client(raw, &tls.Config{ServerName: q.Host, RootCAs: roots, MinVersion: tls.VersionTLS12, CurvePreferences: []tls.CurveID{tls.CurveP256}})
	secure.SetDeadline(time.Now().Add(5 * time.Second))
	if err = secure.Handshake(); err != nil {
		t.Fatal(err)
	}
	req, _ := http.NewRequest("GET", "https://"+q.Host+"/", nil)
	if err = req.Write(secure); err != nil {
		t.Fatal(err)
	}
	response, err := http.ReadResponse(bufio.NewReader(secure), req)
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(response.Body)
	response.Body.Close()
	if err != nil || string(body) != "ordinary direct works" || opens.Load() != 2 {
		t.Fatal(err, string(body), opens.Load())
	}
	actual := raw.(browserproxy.PlanReporter).CurrentPlan()
	if actual.Destination != second || actual.Policy.Action != flowpolicy.Direct {
		t.Fatal(actual)
	}
	if !c.directAddressFailed(cur, q, p) || c.directAddressFailed(cur, q, browserproxy.RetargetOrigin(p, second)) {
		t.Fatal("per-IP health mixed")
	}
	if c.browser.directTimeouts.AddressFailed(c.directTimeoutKey(cur, q, p), time.Now().Add(11*time.Minute)) {
		t.Fatal("permanent pin")
	}
	for _, other := range []profilesResult{{network: "other", profile: cur.profile}, {network: cur.network, profile: profiles.Profile{ID: "other"}}} {
		if c.directAddressFailed(other, q, p) {
			t.Fatal("negative crossed network/profile")
		}
	}
	rows := c.localProbeSnapshot()["ordinary"].([]ordinaryFlowEvidence)
	if len(rows) != 1 || rows[0].Stage != "DIRECT" || len(rows[0].Addresses) != 2 || rows[0].Addresses[0].Result != "TLS_FIRST_FLIGHT_FAILED_NEGATIVE_TTL" || rows[0].Addresses[1].Result != "TLS_SERVER_HELLO; NOT_HTTP_PROOF" {
		t.Fatalf("missing ordinary TLS attempts: %+v", rows)
	}
}

func TestOrdinaryAllCheckedDNSFailThenRelayOnly(t *testing.T) {
	c, cur, q, p := youtubeFixture(t)
	q.Host = "blocked.example.net"
	p.Policy = flowpolicy.Result{Action: flowpolicy.RelayRequired, Source: "direct_timeout_cache", Fallback: flowpolicy.Required}
	p.DirectCandidates = []netip.AddrPort{p.Destination, netip.MustParseAddrPort("93.186.225.194:443"), netip.MustParseAddrPort("87.240.137.208:443")}
	var actions []flowpolicy.Action
	a, b := net.Pipe()
	defer b.Close()
	raw, actual, e := c.openBrowserPlan(context.Background(), cur, q, p, func(_ context.Context, _ browserproxy.Request, plan browserproxy.Plan) (net.Conn, error) {
		actions = append(actions, plan.Policy.Action)
		if plan.Policy.Action == flowpolicy.Direct {
			return nil, &net.OpError{Op: "dial", Net: "tcp", Err: syscall.ECONNREFUSED}
		}
		return a, nil
	})
	if e != nil {
		t.Fatal(e)
	}
	defer raw.Close()
	if len(actions) != 3 || actions[0] != flowpolicy.Direct || actions[1] != flowpolicy.Direct || actions[2] != flowpolicy.RelayRequired || actual.Policy.Fallback != flowpolicy.Required {
		t.Fatal(actions, actual)
	}
	rows := c.localProbeSnapshot()["ordinary"].([]ordinaryFlowEvidence)
	if len(rows) != 1 || rows[0].Stage != "RELAY" || len(rows[0].Addresses) != 3 || rows[0].Addresses[0].Result != "TCP_OPEN_FAILED" || rows[0].Addresses[1].Result != "TCP_OPEN_FAILED" {
		t.Fatal(rows)
	}
}

func TestOrdinaryOriginByteForbidsReplayAndScopeStaysStrict(t *testing.T) {
	c, cur, q, p := youtubeFixture(t)
	q.Host = "ordinary.example.net"
	p.Policy = flowpolicy.Result{Action: flowpolicy.RelayRequired, Source: "direct_timeout_cache", Fallback: flowpolicy.Required}
	p.DirectCandidates = []netip.AddrPort{p.Destination, netip.MustParseAddrPort("87.240.137.208:443")}
	calls := 0
	raw, _, e := c.openBrowserPlan(context.Background(), cur, q, p, func(context.Context, browserproxy.Request, browserproxy.Plan) (net.Conn, error) {
		calls++
		a, b := net.Pipe()
		go func() { defer b.Close(); b.Read(make([]byte, 8192)); b.Write([]byte{21, 3, 3, 0, 2, 2, 40}) }()
		return a, nil
	})
	if e != nil {
		t.Fatal(e)
	}
	defer raw.Close()
	secure := tls.Client(raw, &tls.Config{ServerName: q.Host, MinVersion: tls.VersionTLS12, CurvePreferences: []tls.CurveID{tls.CurveP256}})
	secure.SetDeadline(time.Now().Add(3 * time.Second))
	if secure.Handshake() == nil || calls != 1 {
		t.Fatal("origin byte replayed", calls)
	}
	for _, host := range []string{"chatgpt.com", "web.telegram.org", "claude.ai", "www.youtube.com", "discord.com"} {
		q.Host = host
		if c.ordinaryAddressRetry(cur, q, p) {
			t.Fatal("protected/DPI entered ordinary", host)
		}
	}
	q.Host = "ordinary.example.net"
	q.OriginAmbiguous = true
	if c.ordinaryAddressRetry(cur, q, p) {
		t.Fatal("ambiguous scope")
	}
	q.OriginAmbiguous = false
	p.Policy.Source = "rule"
	if c.ordinaryAddressRetry(cur, q, p) {
		t.Fatal("explicit rule overridden")
	}
	p.Policy.Source = "direct_timeout_cache"
	cur.profile = profiles.Profile{ID: "cs2", Mode: profiles.Auto, Executables: []string{"cs2.exe"}}
	if c.ordinaryAddressRetry(cur, q, p) {
		t.Fatal("game entered browser retry")
	}
}

func TestOrdinaryScopeDenialIsVisibleAndNotCountedAsDNSAttempt(t *testing.T) {
	c, cur, q, p := youtubeFixture(t)
	q.Host = "akashi.vk-portal.net"
	q.OriginAmbiguous = true
	p.Policy = flowpolicy.Result{Action: flowpolicy.RelayRequired, Source: "direct_timeout_cache"}
	if c.ordinaryAddressRetry(cur, q, p) {
		t.Fatal("ambiguous DNS retarget authorized")
	}
	snap := c.localProbeSnapshot()
	rows := snap["ordinary"].([]ordinaryFlowEvidence)
	if len(rows) != 1 || rows[0].Reason != "AMBIGUOUS_DOMAIN_NO_DNS_RETARGET" || snap["ordinary_dns_direct_attempts"].(uint64) != 0 || snap["ordinary_scope_denials"].(uint64) != 1 {
		t.Fatal(snap)
	}
}
