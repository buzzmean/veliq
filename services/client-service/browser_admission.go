package clientservice

import (
	"context"
	"errors"
	"net"
	"runtime"
	"syscall"
	"time"

	"github.com/buzzmean/neexitlag/core/browserproxy"
	"github.com/buzzmean/neexitlag/core/flowpolicy"
	wp "github.com/buzzmean/neexitlag/platform/windows"
)

const browserDirectBudget = 3 * time.Second
const browserDirectAttempt = 1300 * time.Millisecond

// Only the planner's DNS answers are tried, at most twice. The deadline survives
// a successful TCP connect so a silent TLS handshake cannot restart the budget.
func directAttemptContext(ctx context.Context, p browserproxy.Plan) (context.Context, context.CancelFunc) {
	deadline := time.Now().Add(browserDirectAttempt)
	if !p.DirectDeadline.IsZero() && p.DirectDeadline.Before(deadline) {
		deadline = p.DirectDeadline
	}
	return context.WithDeadline(ctx, deadline)
}
func nextDirectPlan(p browserproxy.Plan) (browserproxy.Plan, bool) {
	if p.DirectIndex >= 2 || p.DirectAttempts >= 2 || (!p.DirectDeadline.IsZero() && !time.Now().Before(p.DirectDeadline)) {
		return p, false
	}
	for _, addr := range p.DirectCandidates {
		if addr != p.Destination && addr.IsValid() {
			p.Destination = addr
			p.DirectIndex = 2
			p.Probe = "DIRECT_SECOND_ADDRESS"
			return p, true
		}
	}
	return p, false
}
func retryableDirectOpen(err error) bool {
	if err == nil || errors.Is(err, context.Canceled) {
		return false
	}
	// net.OpError implements net.Error even for local permission/resource errors.
	// Those errors say nothing about the destination and must not poison its
	// negative cache or steer subsequent connections through the relay.
	var dns *net.DNSError
	if errors.As(err, &dns) {
		return false // DNS resolution failure is not a failed destination socket.
	}
	var errno syscall.Errno
	if errors.As(err, &errno) {
		switch errno {
		case syscall.ETIMEDOUT, syscall.ECONNREFUSED, syscall.ECONNRESET, syscall.EHOSTUNREACH, syscall.ENETUNREACH:
			return true
		}
		// Windows sockets return Winsock values, not syscall's portable POSIX
		// aliases. Keep these numbers Windows-only; unknown errno stays unknown.
		if runtime.GOOS == "windows" {
			switch errno {
			case 10060, 10061, 10054, 10065, 10051: // timed out, refused, reset, host/network unreachable
				return true
			}
		}
		return false
	}
	var ne net.Error
	return errors.Is(err, context.DeadlineExceeded) || errors.As(err, &ne) && ne.Timeout()
}
func (c *Controller) browserOpenPlan(ctx context.Context, q browserproxy.Request, p browserproxy.Plan) (net.Conn, browserproxy.Plan, error) {
	cur, err := c.browserProfile(q.Owner)
	if err != nil {
		return nil, p, err
	}
	return c.openBrowserPlan(ctx, cur, q, p, c.browserOpen)
}
func (c *Controller) openBrowserPlan(ctx context.Context, current profilesResult, q browserproxy.Request, p browserproxy.Plan, open func(context.Context, browserproxy.Request, browserproxy.Plan) (net.Conn, error)) (net.Conn, browserproxy.Plan, error) {
	if generation := c.youtubeLocalBetaOriginScope(q); generation != p.YouTubeLocalGeneration {
		return nil, p, errYouTubeLocalScopeChanged
	}
	if p.YouTubeLocalGeneration != 0 {
		return c.openYouTubeLocalBeta(ctx, current, q, p, open)
	}
	if current.enabled && riotAuto(current.profile) && riotHost(q.Host) && p.Policy.Source == "riot_direct_first" {
		return c.openRiotPlan(ctx, current, q, p, open)
	}
	if c.ordinaryAddressRetry(current, q, p) {
		return c.openOrdinaryAddresses(ctx, current, q, p, open)
	}
	if current.enabled && (browserAuto(current.profile) || automaticApplication(current.profile)) && !current.routingDisabled && c.localLadderEligible(current, q, p) {
		if _, explicit := flowpolicy.Evaluate(current.profile.Rules, flowpolicy.Input{Protocol: "tcp", Destination: p.Destination, Domain: q.Host, Network: current.network}); !explicit {
			return c.openYoutubeLadder(ctx, current, q, p, open)
		}
	}

	conn, actual, err := c.openBrowserPlanAttempt(ctx, current, q, p, open)
	return c.capacityDirectFallback(ctx, current, q, actual, conn, err, open)
}
func (c *Controller) openBrowserPlanAttempt(ctx context.Context, current profilesResult, q browserproxy.Request, p browserproxy.Plan, open func(context.Context, browserproxy.Request, browserproxy.Plan) (net.Conn, error)) (net.Conn, browserproxy.Plan, error) {
	if current.routingDisabled {
		p = disabledBrowserPlan(p)
		conn, err := open(ctx, q, p)
		return conn, p, err
	}
	if p.Enabled && current.enabled && q.Port != 53 && c.browserOriginPolicy(q.Host).Kind == "RELAY" {
		currentPolicy := c.browserFlow(current.profile, current.id, wp.Tuple{Protocol: "tcp", Destination: p.Destination}, q.Host, current.network)
		if currentPolicy.Action == flowpolicy.Block || p.Policy.Action != flowpolicy.RelayRequired || p.Policy.Fallback != flowpolicy.Required {
			p.Policy = currentPolicy
		}
		p.DirectAttempts, p.DirectIndex, p.DirectCandidates = 0, 0, nil
		// A queued request may already hold the verified DNS pin. Keep its
		// origin verification evidence rather than relabeling it as unprobed.
		if p.DNSRecovery == nil || !p.DNSRecovery.Usable() || p.Probe != p.DNSRecovery.ProbeName() {
			p.Probe = "KNOWN_RELAY_FIRST"
		}
		return c.openKnownBrowserGroup(ctx, current, q, p, open)
	}
	// Extend health selection to protected/YouTube origins already planned RELAY_REQUIRED.
	// Do not change policy: DIRECT/DIRECT+ and ordinary DIRECT-first stay outside.
	if p.Enabled && current.enabled && q.Secure && q.Port == 443 && p.Policy.Action == flowpolicy.RelayRequired && p.Policy.Fallback == flowpolicy.Required && browserproxy.ValidPublicDNSName(q.Host) {
		return c.openKnownBrowserGroup(ctx, current, q, p, open)
	}
	// A sibling may have confirmed the group while this request was planning.
	if p.Enabled {
		if steered, ok := c.steerTimedOutOrigin(p, current, q, time.Now()); ok {
			if q.Secure && steered.Policy.Action == flowpolicy.RelayRequired && browserproxy.ValidPublicDNSName(q.Host) {
				return c.openKnownBrowserGroup(ctx, current, q, steered, open)
			}
			conn, err := open(ctx, q, steered)
			return conn, steered, err
		}
	}
	if !p.Enabled || !directTimeoutEligible(q, p) {
		conn, err := open(ctx, q, p)
		return conn, p, err
	}
	if p.DirectDeadline.IsZero() {
		p.DirectDeadline = time.Now().Add(browserDirectBudget)
	}
	if p.DirectIndex == 0 {
		p.DirectIndex = 1
	}
	if c.directAddressFailed(current, q, p) {
		next, ok := nextDirectPlan(p)
		if !ok || c.directAddressFailed(current, q, next) {
			return c.relayAfterDirect(ctx, current, q, p, open)
		}
		p = next
	}

	attempt, stop := directAttemptContext(ctx, p)
	p.DirectAttempts++
	conn, err := open(attempt, q, p)
	stop()
	if err == nil || ctx.Err() != nil || !retryableDirectOpen(err) {
		return conn, p, err
	}
	if next, ok := nextDirectPlan(p); ok {
		p = next
		attempt, stop = directAttemptContext(ctx, p)
		p.DirectAttempts++
		conn, err = open(attempt, q, p)
		stop()
		if err == nil || ctx.Err() != nil || !retryableDirectOpen(err) {
			return conn, p, err
		}
	}
	return c.relayAfterDirect(ctx, current, q, p, open)
}
func (c *Controller) relayAfterDirect(ctx context.Context, current profilesResult, q browserproxy.Request, p browserproxy.Plan, open func(context.Context, browserproxy.Request, browserproxy.Plan) (net.Conn, error)) (net.Conn, browserproxy.Plan, error) {
	p = stallRetryPlan(current, p)
	p.Policy.Source = "direct_open_retry"
	p.Probe = "DIRECT_OPEN_FAILED_RELAY"
	p.Policy.Reason = "Bounded DIRECT connection attempts failed; open this new flow through authenticated relay"
	if p.DirectAttempts == 0 {
		p.Policy.Source = "direct_timeout_cache"
		p.Probe = "DIRECT_ADDRESS_CACHED_RELAY"
		p.Policy.Reason = "Cached failed destination addresses; no DIRECT dial for this new flow"
	}
	conn, err := open(ctx, q, p)
	return conn, p, err
}
func (c *Controller) directAddressFailed(cur profilesResult, q browserproxy.Request, p browserproxy.Plan) bool {
	return cur.network != "" && c.browser.directTimeouts.AddressFailed(c.directTimeoutKey(cur, q, p), time.Now())
}
