package clientservice

import (
	"context"
	"errors"
	"github.com/buzzmean/veliq/core/browserproxy"
	"github.com/buzzmean/veliq/core/flowpolicy"
	"net"
	"net/netip"
	"syscall"
	"testing"
	"time"
)

func boundedDirectPlan() browserproxy.Plan {
	a := netip.MustParseAddrPort("142.251.150.4:443")
	b := netip.MustParseAddrPort("142.251.151.4:443")
	return browserproxy.Plan{Enabled: true, Network: "net-1", Destination: a, DirectCandidates: []netip.AddrPort{a, b, netip.MustParseAddrPort("142.251.152.4:443")}, Policy: flowpolicy.Result{Action: flowpolicy.Direct}, DirectDeadline: time.Now().Add(browserDirectBudget)}
}
func TestDirectOpenRefusedTriesOnlyTwoAddressesThenAuthenticatedRelay(t *testing.T) {
	c, cur := timeoutFixture(t)
	q := browserproxy.Request{Host: "www.youtube.com", Port: 443, Secure: true}
	p := boundedDirectPlan()
	var plans []browserproxy.Plan
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	conn, actual, err := c.openBrowserPlan(context.Background(), cur, q, p, func(_ context.Context, _ browserproxy.Request, p browserproxy.Plan) (net.Conn, error) {
		plans = append(plans, p)
		if p.Policy.Action == flowpolicy.Direct {
			return nil, &net.OpError{Op: "dial", Net: "tcp", Err: syscall.ECONNREFUSED}
		}
		return a, nil
	})
	if err != nil || conn != a || actual.Policy.Action != flowpolicy.RelayRequired || actual.Policy.Fallback != flowpolicy.Required || actual.DirectAttempts != 2 || len(plans) != 3 {
		t.Fatal(actual, len(plans), err)
	}
	if plans[0].Destination == plans[1].Destination || plans[1].Destination != p.DirectCandidates[1] {
		t.Fatal("not two distinct bounded DNS answers")
	}
}
func TestDirectOpenSharesBudgetRatherThanMultiplyingTimeoutByAddresses(t *testing.T) {
	c, cur := timeoutFixture(t)
	q := browserproxy.Request{Host: "www.youtube.com", Port: 443, Secure: true}
	p := boundedDirectPlan()
	p.DirectDeadline = time.Now().Add(120 * time.Millisecond)
	start := time.Now()
	direct, relay := 0, 0
	_, _, err := c.openBrowserPlan(context.Background(), cur, q, p, func(ctx context.Context, _ browserproxy.Request, p browserproxy.Plan) (net.Conn, error) {
		if p.Policy.Action == flowpolicy.Direct {
			direct++
			<-ctx.Done()
			return nil, ctx.Err()
		}
		relay++
		return nil, errors.New("relay unavailable")
	})
	if err == nil || direct > 2 || relay != 1 || time.Since(start) > 500*time.Millisecond {
		t.Fatal("budget multiplied", direct, relay, time.Since(start), err)
	}
}
func TestProtectedDirectPlusExplicitRulesDisabledAndCancellationNeverDowngrade(t *testing.T) {
	c, cur := timeoutFixture(t)
	for _, tc := range []struct {
		host string
		p    browserproxy.Plan
	}{{"chatgpt.com", browserproxy.Plan{Enabled: true, Policy: flowpolicy.Result{Action: flowpolicy.RelayRequired, Fallback: flowpolicy.Required}}}, {"www.youtube.com", browserproxy.Plan{Enabled: true, Policy: flowpolicy.Result{Action: flowpolicy.DirectPlus}}}, {"youtube.com", browserproxy.Plan{Enabled: true, Policy: flowpolicy.Result{Action: flowpolicy.Direct, Source: "rule"}}}, {"youtube.com", browserproxy.Plan{Policy: flowpolicy.Result{Action: flowpolicy.Direct}}}, {"intranet.example", browserproxy.Plan{Enabled: true, Probe: "PRIVATE_ORIGIN_NO_AUTOPROBE", Policy: flowpolicy.Result{Action: flowpolicy.Direct}}}, {"youtube.com", browserproxy.Plan{Enabled: true, Destination: netip.MustParseAddrPort("[2001:4860:4860::8888]:443"), Policy: flowpolicy.Result{Action: flowpolicy.Direct}}}} {
		calls := 0
		_, actual, _ := c.openBrowserPlan(context.Background(), cur, browserproxy.Request{Host: tc.host, Port: 443}, tc.p, func(_ context.Context, _ browserproxy.Request, p browserproxy.Plan) (net.Conn, error) {
			calls++
			return nil, context.DeadlineExceeded
		})
		if calls != 1 || actual.Policy.Action != tc.p.Policy.Action {
			t.Fatal("policy changed", tc.host, calls, actual)
		}
	}
	calls := 0
	_, _, _ = c.openBrowserPlan(context.Background(), cur, browserproxy.Request{Host: "youtube.com"}, boundedDirectPlan(), func(context.Context, browserproxy.Request, browserproxy.Plan) (net.Conn, error) {
		calls++
		return nil, context.Canceled
	})
	if calls != 1 {
		t.Fatal("canceled user retried")
	}
}

func TestKnownBadAddressSkipsToPeerWithoutPoisoningOtherDestination(t *testing.T) {
	c, cur := timeoutFixture(t)
	p := boundedDirectPlan()
	q := browserproxy.Request{Host: "youtube.com", Port: 443}
	c.browser.directTimeouts.RecordTimeout(c.directTimeoutKey(cur, q, p), time.Now())
	calls := 0
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	_, actual, e := c.openBrowserPlan(context.Background(), cur, q, p, func(_ context.Context, _ browserproxy.Request, p browserproxy.Plan) (net.Conn, error) {
		calls++
		return a, nil
	})
	if e != nil || calls != 1 || actual.Destination != p.DirectCandidates[1] || actual.Policy.Action != flowpolicy.Direct || actual.DirectAttempts != 1 {
		t.Fatal("failed IP retried or whole domain poisoned", actual, e)
	}
}
func TestGooglevideoRelayCapNeverDowngradesToKnownDeadDirect(t *testing.T) {
	c, cur := timeoutFixture(t)
	for _, host := range []string{"r.googlevideo.com", "chatgpt.com"} {
		p := boundedDirectPlan()
		p.Policy = flowpolicy.Result{Action: flowpolicy.RelayRequired, Fallback: flowpolicy.Required, Source: "direct_timeout_cache"}
		calls := 0
		_, actual, err := c.openBrowserPlan(context.Background(), cur, browserproxy.Request{Host: host, Port: 443}, p, func(_ context.Context, _ browserproxy.Request, p browserproxy.Plan) (net.Conn, error) {
			calls++
			if p.Policy.Action != flowpolicy.RelayRequired {
				t.Fatal("DIRECT leak")
			}
			return nil, errVideoRelayCapacity
		})
		if !errors.Is(err, errVideoRelayCapacity) || calls != 1 || actual.Policy.Action != flowpolicy.RelayRequired {
			t.Fatal(actual, err, calls)
		}
	}
}

func TestCachedAddressSelectionReportsZeroFreshDirectDials(t *testing.T) {
	c, cur := timeoutFixture(t)
	p := boundedDirectPlan()
	q := browserproxy.Request{Host: "youtube.com", Port: 443}
	c.browser.directTimeouts.RecordTimeout(c.directTimeoutKey(cur, q, p), time.Now())
	peer := p
	peer.Destination = p.DirectCandidates[1]
	c.browser.directTimeouts.RecordTimeout(c.directTimeoutKey(cur, q, peer), time.Now())
	calls := 0
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	_, actual, err := c.openBrowserPlan(context.Background(), cur, q, p, func(_ context.Context, _ browserproxy.Request, p browserproxy.Plan) (net.Conn, error) {
		calls++
		if p.Policy.Action != flowpolicy.RelayRequired {
			t.Fatal("cached dead address dialed DIRECT")
		}
		return a, nil
	})
	if err != nil || calls != 1 || actual.DirectAttempts != 0 || actual.Probe != "DIRECT_TIMEOUT_CACHED" {
		t.Fatal("evidence claimed nonexistent DIRECT dials", actual, calls, err)
	}
}
