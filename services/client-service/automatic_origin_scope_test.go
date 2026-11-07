package clientservice

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/buzzmean/neexitlag/core/browserproxy"
)

func TestAutomaticRelayOriginStopsStaleFirstFlightRecovery(t *testing.T) {
	for _, change := range []string{"network", "automatic-off", "failover", "profile-direct"} {
		t.Run(change, func(t *testing.T) {
			c, cur, q, p := automaticFixture(t)
			p = stallRetryPlan(cur, p)
			a, peer := net.Pipe()
			defer peer.Close()
			var lookups, opens atomic.Int32
			c.BrowserAlternativeDNS = func(context.Context, string, browserproxy.DNSOpen) (browserproxy.DNSAnswer, error) {
				lookups.Add(1)
				return browserproxy.DNSAnswer{}, errors.New("unexpected stale DNS")
			}
			conn := c.watchKnownOrigin(a, cur, q, p, func(context.Context, browserproxy.Request, browserproxy.Plan) (net.Conn, error) {
				opens.Add(1)
				return nil, errors.New("unexpected stale OPEN")
			})
			defer conn.Close()
			conn.SetDeadline(time.Now().Add(2 * time.Second))
			hello := []byte{22, 3, 1, 0, 7, 1, 0, 0, 3, 1, 2, 3}
			drained := make(chan struct{})
			go func() { defer close(drained); _, _ = io.CopyN(io.Discard, peer, int64(len(hello))) }()
			if _, err := conn.Write(hello); err != nil {
				t.Fatal(err)
			}
			<-drained
			changeAutomaticRecoveryScope(t, c, cur, change)
			peer.Close()
			_, err := io.ReadAll(conn)
			key := c.browserDNSKey(q, cur) + ":" + p.Policy.RelayID
			selected, _ := c.browser.origins.Pick(key, []netip.AddrPort{p.Destination}, nil, time.Now())
			if err == nil || lookups.Load() != 0 || opens.Load() != 0 || selected != p.Destination {
				t.Fatalf("stale relay origin learned/recovered: err=%v lookups=%d opens=%d selected=%v", err, lookups.Load(), opens.Load(), selected)
			}
		})
	}
}

func TestAutomaticOriginResolverRejectsScopeChange(t *testing.T) {
	for _, when := range []string{"before-resolve", "during-resolve", "before-dns-open"} {
		t.Run(when, func(t *testing.T) {
			c, cur, q, p := automaticFixture(t)
			p = stallRetryPlan(cur, p)
			calls := 0
			c.BrowserAlternativeDNS = func(ctx context.Context, _ string, open browserproxy.DNSOpen) (browserproxy.DNSAnswer, error) {
				calls++
				changeAutomaticRecoveryScope(t, c, cur, "automatic-off")
				if when == "before-dns-open" {
					conn, err := open(ctx, netip.MustParseAddrPort("1.1.1.1:443"))
					if conn != nil || !errors.Is(err, errAutomaticScopeChanged) {
						t.Errorf("resolver dial lost captured scope: conn=%v err=%v", conn, err)
					}
					return browserproxy.DNSAnswer{}, err
				}
				return browserproxy.DNSAnswer{Addresses: []netip.Addr{netip.MustParseAddr("8.8.8.8")}, TTL: time.Minute}, nil
			}
			if when == "before-resolve" {
				changeAutomaticRecoveryScope(t, c, cur, "automatic-off")
			}
			answer, err := c.knownOriginResolve(context.Background(), cur, q, p)
			if err == nil || len(answer.Addresses) != 0 || when == "before-resolve" && calls != 0 {
				t.Fatal("stale resolver work accepted", when, calls, answer, err)
			}
		})
	}
}

func TestAutomaticOriginVerifiedDNSRecoveryDropsStaleEvidence(t *testing.T) {
	c, cur, q, p := automaticFixture(t)
	p = stallRetryPlan(cur, p)
	key := c.browserDNSKey(q, cur)
	c.BrowserAlternativeDNS = func(context.Context, string, browserproxy.DNSOpen) (browserproxy.DNSAnswer, error) {
		changeAutomaticRecoveryScope(t, c, cur, "automatic-off")
		return browserproxy.DNSAnswer{Addresses: []netip.Addr{netip.MustParseAddr("8.8.8.8")}, TTL: time.Minute}, nil
	}
	plan, ok := c.recoverBrowserDNS(context.Background(), q, cur, p)
	if ok || plan.DNSRecovery == nil || plan.DNSRecovery.Failure != "DNS_RECOVERY_SCOPE_CHANGED" {
		t.Fatal("obsolete verified DNS recovery accepted", ok, plan.DNSRecovery)
	}
	if _, found := c.browser.dns.Lookup(key, time.Now()); found {
		t.Fatal("obsolete verified DNS recovery cached")
	}
}
