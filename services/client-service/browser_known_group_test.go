package clientservice

import (
	"context"
	"errors"
	"github.com/buzzmean/veliq/core/transport"
	"io"
	"net"
	"net/netip"
	"testing"

	"github.com/buzzmean/veliq/core/browserproxy"
	"github.com/buzzmean/veliq/core/flowpolicy"
	wp "github.com/buzzmean/veliq/platform/windows"
)

func TestBrowserKnownGroupsRelayFirstWithoutColdDirectOrFallback(t *testing.T) {
	c, cur := timeoutFixture(t)
	for _, host := range []string{"web.telegram.org", "kws2.web.telegram.org", "venus.web.telegram.org", "pluto2.web.telegram.org", "zws1.web.telegram.org", "t.me", "telegram.org", "claude.ai", "api.anthropic.com", "assets-proxy.anthropic.com", "bridge.claudeusercontent.com", "claude.com"} {
		q := browserproxy.Request{Host: host, Port: 443, Secure: true}
		p := boundedDirectPlan() // Also rejects a stale DIRECT plan made before this rule.
		calls := 0
		_, got, err := c.openBrowserPlan(context.Background(), cur, q, p, func(_ context.Context, _ browserproxy.Request, p browserproxy.Plan) (net.Conn, error) {
			calls++
			if p.Policy.Action != flowpolicy.RelayRequired || p.Policy.Fallback != flowpolicy.Required || p.Policy.RelayID != "VPS-01" || p.DirectAttempts != 0 {
				t.Fatal(host, p)
			}
			return nil, errors.New("isolated relay unavailable")
		})
		if calls != 1 || err == nil || got.Probe != "KNOWN_RELAY_FIRST" {
			t.Fatal(host, calls, got, err)
		}
		if directTimeoutEligible(q, p) {
			t.Fatal("known group used ordinary DIRECT timeout learning", host)
		}
	}
	if s := c.browser.directTimeouts.Stats(); s.Stalls != 0 || s.Created != 0 {
		t.Fatal("cold groups paid DIRECT timeout", s)
	}
	// Do not spread YouTube cache keys or local strategy eligibility to other groups.
	if flowpolicy.DirectTimeoutHost("web.telegram.org") == "youtube.com" || youtubeRelayDomain("claude.ai") || youtubeDomain("claude.ai") {
		t.Fatal("family policy cross-contamination")
	}
}
func TestBrowserKnownGroupsExactScopeDNSAndOrdinaryRoutes(t *testing.T) {
	c, cur := timeoutFixture(t)
	for _, host := range []string{"claude.ai.attacker.example", "notclaude.ai", "anthropic.com.evil.example", "web.telegram.org.evil.example", "telegram.example", "ordinary.example", "www.google.com"} {
		result := c.browserFlow(cur.profile, wp.ProcessIdentity{}, wp.Tuple{Protocol: "tcp", Destination: netip.MustParseAddrPort("8.8.8.8:443")}, host, cur.network)
		if result.Action != flowpolicy.Direct || flowpolicy.KnownBrowserRelayGroup(host) != "" {
			t.Fatal("ordinary origin captured by known rule", host, result)
		}
	}
	for _, host := range []string{"web.telegram.org", "claude.ai", "chatgpt.com"} {
		result := c.browserFlow(cur.profile, wp.ProcessIdentity{}, wp.Tuple{Protocol: "udp", Destination: netip.MustParseAddrPort("192.168.1.1:53")}, host, cur.network)
		if result.Action != flowpolicy.Direct {
			t.Fatal("DNS to relay", host, result)
		}
	}
	blocked := cur.profile
	blocked.Rules = []flowpolicy.Rule{{ID: "block", Domains: []string{"claude.ai"}, Action: flowpolicy.Block}}
	if got := c.browserFlow(blocked, wp.ProcessIdentity{}, wp.Tuple{Protocol: "tcp", Destination: netip.MustParseAddrPort("8.8.8.8:443")}, "claude.ai", cur.network); got.Action != flowpolicy.Block {
		t.Fatal("explicit BLOCK weakened", got)
	}

	// Policy on explicitly disabled optimization stays outside automatic forcing.
	p := boundedDirectPlan()
	p.Enabled = false
	calls := 0
	_, got, _ := c.openBrowserPlan(context.Background(), cur, browserproxy.Request{Host: "claude.ai", Port: 443}, p, func(_ context.Context, _ browserproxy.Request, p browserproxy.Plan) (net.Conn, error) {
		calls++
		return nil, errors.New("test")
	})
	if calls != 1 || got.Policy.Action != flowpolicy.Direct {
		t.Fatal("disabled optimization changed", got)
	}
}

func TestBrowserKnownGroupsSuccessfulRelayAndDNSFailureScope(t *testing.T) {
	c, cur := timeoutFixture(t)
	for _, host := range []string{"venus.web.telegram.org", "api.anthropic.com"} {
		a, b := net.Pipe()
		done := make(chan struct{})
		go func() { defer close(done); defer b.Close(); _, _ = b.Write([]byte("origin reply")) }()
		conn, plan, err := c.openBrowserPlan(context.Background(), cur, browserproxy.Request{Host: host, Port: 443, Secure: true}, boundedDirectPlan(), func(_ context.Context, _ browserproxy.Request, p browserproxy.Plan) (net.Conn, error) {
			if p.Policy.Action != flowpolicy.RelayRequired || p.Policy.Fallback != flowpolicy.Required || p.DirectAttempts != 0 {
				t.Fatal(p)
			}
			return a, nil
		})
		if err != nil || plan.Probe != "KNOWN_RELAY_FIRST" {
			t.Fatal(plan, err)
		}
		data, err := io.ReadAll(conn)
		conn.Close()
		<-done
		if err != nil || string(data) != "origin reply" {
			t.Fatal(string(data), err)
		}
	}
	for _, code := range []string{"upstream_dial_timeout", "upstream_connection_refused", "upstream_dial_failed"} {
		if !recoverableKnownOriginOpen(&transport.OpenError{Reason: code}) {
			t.Fatal(code)
		}
	}
	for _, code := range []string{"ticket_rejected", "session_closed", "stream_capacity", "transport_open_failed"} {
		if recoverableKnownOriginOpen(&transport.OpenError{Reason: code}) {
			t.Fatal("auth/session failure triggered DNS recovery", code)
		}
	}
}

func TestBrowserKnownGroupsDNSRecoveryNotStarvedByOrdinaryProbes(t *testing.T) {
	c, cur := timeoutFixture(t)
	for i := 0; i < cap(c.browser.probes); i++ {
		c.browser.probes <- struct{}{}
	}
	calls := 0
	c.BrowserAlternativeDNS = func(context.Context, string, browserproxy.DNSOpen) (browserproxy.DNSAnswer, error) {
		calls++
		return browserproxy.DNSAnswer{}, errors.New("isolated negative DNS answer")
	}
	p := boundedDirectPlan()
	_, got, err := c.openBrowserPlan(context.Background(), cur, browserproxy.Request{Host: "web.telegram.org", Port: 443, Secure: true}, p, func(_ context.Context, _ browserproxy.Request, p browserproxy.Plan) (net.Conn, error) {
		if p.Policy.Action != flowpolicy.RelayRequired {
			t.Fatal("DIRECT leak", p)
		}
		return nil, &transport.OpenError{Reason: "upstream_dial_failed"}
	})
	if err == nil || calls != 1 || got.DNSRecovery == nil || got.DNSRecovery.Failure != "DNS_ALTERNATIVE_FAILED" {
		t.Fatal("ordinary probes starved bounded DNS recovery", calls, got, err)
	}
}

func TestBrowserKnownGroupsPreserveVerifiedDNSPlanForQueuedRequests(t *testing.T) {
	c, cur := timeoutFixture(t)
	dst := netip.MustParseAddrPort("8.8.8.8:443")
	p := browserproxy.Plan{Enabled: true, Network: cur.network, Destination: dst, Policy: browserDNSPolicy(cur), Probe: "DNS_RELAY_HTTP_VERIFIED", HTTPStatus: 200, DNSRecovery: &browserproxy.DNSRecoveryResult{Verified: true, Destination: dst}}
	_, got, _ := c.openBrowserPlan(context.Background(), cur, browserproxy.Request{Host: "web.telegram.org", Port: 443, Secure: true}, p, func(_ context.Context, _ browserproxy.Request, actual browserproxy.Plan) (net.Conn, error) {
		if actual.Probe != "DNS_RELAY_HTTP_VERIFIED" || actual.Policy.Action != flowpolicy.RelayRequired || actual.Policy.Fallback != flowpolicy.Required || actual.Destination != dst || actual.DNSRecovery == nil || !actual.DNSRecovery.Verified {
			t.Fatal("verified DNS evidence lost", actual)
		}
		return nil, errors.New("isolated session failure")
	})
	if got.Probe != p.Probe || got.HTTPStatus != 200 {
		t.Fatal(got)
	}
	cur.profile.Rules = []flowpolicy.Rule{{ID: "block", Domains: []string{"telegram.org"}, Action: flowpolicy.Block}}
	_, _, _ = c.openBrowserPlan(context.Background(), cur, browserproxy.Request{Host: "web.telegram.org", Port: 443, Secure: true}, p, func(_ context.Context, _ browserproxy.Request, actual browserproxy.Plan) (net.Conn, error) {
		if actual.Policy.Action != flowpolicy.Block {
			t.Fatal("cached Required plan ignored newer BLOCK", actual)
		}
		return nil, errors.New("blocked")
	})
}
