package clientservice

import (
	"context"
	"net"
	"time"

	"github.com/buzzmean/veliq/core/browserproxy"
	"github.com/buzzmean/veliq/core/flowpolicy"
)

// An empty hostname MUST NOT enter the domain cache: two unrelated IP failures
// could otherwise steer every unknown browser connection to relay again.
func (c *Controller) openOpaqueBrowserPlan(ctx context.Context, cur profilesResult, q browserproxy.Request, p browserproxy.Plan, open func(context.Context, browserproxy.Request, browserproxy.Plan) (net.Conn, error)) (net.Conn, browserproxy.Plan, error) {
	if q.Host != "" || p.Policy.Action != flowpolicy.Direct || p.Policy.Source == "rule" {
		return c.openBrowserPlan(ctx, cur, q, p, open)
	}
	attempt, cancel := context.WithTimeout(ctx, browserDirectAttempt)
	conn, err := open(attempt, q, p)
	cancel()
	if err == nil || ctx.Err() != nil || !retryableDirectOpen(err) {
		return conn, p, err
	}
	c.browser.domains.failedDirect(cur.network, cur.profile.ID, p.Destination, time.Now())
	c.browser.domains.googleFailed(cur.network, cur.profile.ID, p.Destination, "DIRECT_TCP_OPEN_FAILED", time.Now())
	// No application bytes have left yet. A successful TCP stream is never moved.
	p = stallRetryPlan(cur, p)
	p.Policy.Source = "opaque_direct_open_retry"
	p.Probe = "OPAQUE_DIRECT_OPEN_FAILED_RELAY"
	return c.openBrowserPlan(ctx, cur, q, p, open)
}
func (c *Controller) recordNativeBrowserStall(cur profilesResult, q browserproxy.Request, p browserproxy.Plan, opaque bool) {
	if q.Host != "" {
		c.recordBrowserStall(cur, q, p)
	}
	if opaque {
		c.browser.domains.failedDirect(cur.network, cur.profile.ID, p.Destination, time.Now())
	}
}
func nativeFirstReplyEligible(q browserproxy.Request, p browserproxy.Plan) bool {
	return directTimeoutEligible(q, p) || q.Host == "" && q.Port != 53 && p.Policy.Action == flowpolicy.Direct && p.Policy.Source != "rule"
}
