package clientservice

import (
	"context"
	"encoding/json"
	"errors"
	wp "github.com/buzzmean/neexitlag/platform/windows"
	"net"
	"net/netip"
	"time"

	"github.com/buzzmean/neexitlag/core/browserproxy"
	"github.com/buzzmean/neexitlag/core/flowpolicy"
)

// browserStatusView is browser.status plus the DIRECT-timeout cache counters, so the
// load this cache puts on the relay is visible in diagnostics.
type browserStatusView struct {
	PolicyRefresh wp.BrowserPolicyRefreshView `json:"policy_refresh"`
	browserproxy.Snapshot
	SilentActivation browserSilentView             `json:"silent_activation"`
	LastError        string                        `json:"last_error"`
	ReadinessState   string                        `json:"readiness_state"`
	DirectTimeouts   flowpolicy.DirectTimeoutStats `json:"direct_timeout_cache"`
	RelayUsage       relayUsageSnapshot            `json:"relay_usage"`
}

// directTimeoutEligible limits the cache to ordinary DIRECT-first origins. Protected
// origins are relay-required from the start and IP literals have no domain identity.
// YouTube is eligible only while its policy is plain DIRECT; once DIRECT+ is configured
// the plan's action is DirectPlus and this cache stays out of its way.
func directTimeoutEligible(q browserproxy.Request, plan browserproxy.Plan) bool {
	return directTimeoutRouteEligible(q, plan) && !(plan.Destination.IsValid() && plan.Destination.Addr().Is6())
}

// Steering to authenticated relay is safe for IPv6 too; observing unsupported
// native IPv6 DIRECT is deliberately still excluded from failure learning.
func directTimeoutRouteEligible(q browserproxy.Request, plan browserproxy.Plan) bool {
	if plan.Policy.Source == youtubeLadderSource || q.Host == "" || q.Port == 53 || plan.Policy.Action != flowpolicy.Direct || plan.Policy.Source == "rule" || plan.Probe == "PRIVATE_ORIGIN_NO_AUTOPROBE" || protectedBrowserDomain(q.Host) || flowpolicy.KnownBrowserRelayGroup(q.Host) != "" {
		return false
	}
	_, ipErr := netip.ParseAddr(q.Host)
	return ipErr != nil
}

// cacheHost folds CDN families that use a different hostname per video or edge node
// (rr3---sn-xyz.googlevideo.com) into one entry; blocking hits the whole family.
func cacheHost(host string) string { return flowpolicy.DirectTimeoutHost(host) }

func (c *Controller) directTimeoutKey(current profilesResult, q browserproxy.Request, plans ...browserproxy.Plan) flowpolicy.DirectTimeoutKey {
	key := flowpolicy.DirectTimeoutKey{Network: current.network, Application: current.profile.ID, Host: cacheHost(q.Host), Port: q.Port}
	if len(plans) > 0 && plans[0].Destination.IsValid() {
		key.Address = plans[0].Destination.Addr().String()
	}
	return key
}

// Только подтверждённые ошибки открытия меняют failure verdict. Успешный
// TCP connect и непроверенный TLS байт не подтверждают работоспособность сайта.
func (c *Controller) observeDirectOpen(current profilesResult, q browserproxy.Request, plan browserproxy.Plan, err error, now time.Time) {
	if current.network == "" || !directTimeoutEligible(q, plan) || !c.automaticScopeCurrent(current) {
		return
	}
	key := c.directTimeoutKey(current, q, plan)
	switch {
	case errors.Is(err, context.DeadlineExceeded) || err != nil && plan.Destination.IsValid() && retryableDirectOpen(err):
		c.browser.directTimeouts.RecordTimeout(key, now)
		c.browser.directTimeouts.SetProbeHost(key, q.Host)
	}
}

// relayAllowedFor now means explicit relay-first preference, never permission for fallback.
func (c *Controller) relayAllowedFor(host string) bool {
	if !youtubeRelayDomain(host) {
		return true
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.settings.YouTubeViaRelay
}

// steerTimedOutOrigin moves a cached origin straight to the authenticated relay,
// fail-closed. It never returns a DIRECT decision.
func (c *Controller) steerTimedOutOrigin(plan browserproxy.Plan, current profilesResult, q browserproxy.Request, now time.Time) (browserproxy.Plan, bool) {
	if !current.enabled || current.network == "" || !directTimeoutRouteEligible(q, plan) {
		return plan, false
	}
	key := c.directTimeoutKey(current, q)
	active, due := c.browser.directTimeouts.Lookup(key, now)
	if !active {
		return plan, false
	}
	if due {
		c.revalidateDirect(current, q, plan, key)
	}
	relay := current.profile.RelayID
	if relay == "" {
		relay = "VPS-01"
	}
	plan.Policy = flowpolicy.Result{Action: flowpolicy.RelayRequired, RelayID: relay, Fallback: flowpolicy.Required, Source: "direct_timeout_cache", Reason: "DIRECT failure confirmed on this network/profile; relay-first pending bounded TLS/HTTP recheck"}
	plan.Probe = "DIRECT_TIMEOUT_CACHED"
	return plan, true
}

// browserDirectAnswered observes transport progress only; it cannot certify HTTPS.
func (c *Controller) browserDirectAnswered(q browserproxy.Request, plan browserproxy.Plan) {
	current, err := c.browserProfile(q.Owner)
	if err != nil {
		return
	}
	c.recordAnswered(current, q, plan)
}
func (c *Controller) recordAnswered(current profilesResult, q browserproxy.Request, plan browserproxy.Plan) {
	if current.network == "" || !directTimeoutEligible(q, plan) {
		return
	}
	// An unparsed first TLS byte is not a verified HTTP result. Only the bounded
	// background TLS/certificate/GET probe clears a relay-first verdict.

}

// stallRetryPlan is the relay-first, fail-closed plan used to retry a stalled tunnel.
func stallRetryPlan(current profilesResult, plan browserproxy.Plan) browserproxy.Plan {
	relay := current.profile.RelayID
	if relay == "" {
		relay = "VPS-01"
	}
	plan.Policy = flowpolicy.Result{Action: flowpolicy.RelayRequired, RelayID: relay, Fallback: flowpolicy.Required, Source: "direct_stall_retry", Reason: "DIRECT origin silent after the ClientHello; retried through the authenticated relay"}
	plan.Probe = "DIRECT_STALL_RETRY"
	return plan
}

// browserStall is the proxy's OnStall hook. It counts the stall like a connect timeout
// (two within 60 s make the origin relay-first for the TTL) and opens a relay path for
// the current tunnel. It can only move traffic towards the relay: protected origins and
// anything that is not an ordinary DIRECT origin are refused, and the open itself enforces
// that a protected domain never downgrades.
func (c *Controller) browserStall(ctx context.Context, q browserproxy.Request, plan browserproxy.Plan) (net.Conn, browserproxy.Plan, error) {
	current, err := c.browserProfile(q.Owner)
	if err != nil {
		return nil, plan, err
	}
	return c.stallRetry(ctx, current, q, plan, c.browserOpen)
}

// stallRetry does the work of browserStall for an already resolved browser profile; open is
// the upstream opener (browserOpen in production).
func (c *Controller) stallRetry(ctx context.Context, current profilesResult, q browserproxy.Request, plan browserproxy.Plan, open func(context.Context, browserproxy.Request, browserproxy.Plan) (net.Conn, error)) (net.Conn, browserproxy.Plan, error) {
	if !directTimeoutEligible(q, plan) {
		return nil, plan, errors.New("stall retry not allowed for this origin")
	}
	if current.network != "" {
		c.recordBrowserStall(current, q, plan)
	}
	if next, ok := nextDirectPlan(plan); !youtubeRelayDomain(q.Host) && ok && !c.directAddressFailed(current, q, next) {
		attempt, stop := directAttemptContext(ctx, next)
		next.DirectAttempts++
		conn, err := open(attempt, q, next)
		stop()
		if err == nil {
			return conn, next, nil
		}
		if ctx.Err() != nil || !retryableDirectOpen(err) {
			return nil, next, err
		}
		plan = next
	}
	next := stallRetryPlan(current, plan)
	conn, err := open(ctx, q, next)
	c.browser.directTimeouts.NoteRetry(err == nil)
	return conn, next, err
}

// revalidateDirect runs the single background DIRECT probe of a TTL. The open itself
// reports success (origin returns to DIRECT) or a fresh timeout (entry renewed).
func (c *Controller) revalidateDirect(current profilesResult, q browserproxy.Request, plan browserproxy.Plan, key flowpolicy.DirectTimeoutKey) {
	// A TTL storm cannot allocate one socket/goroutine per cached origin.
	select {
	case c.browser.probes <- struct{}{}:
	default:
		c.browser.directTimeouts.ProbeDone(key, time.Now(), false)
		return
	}
	probePlan := plan
	probePlan.Policy = flowpolicy.Result{Action: flowpolicy.Direct, Fallback: flowpolicy.FailOpen, Source: "direct_timeout_recheck", Reason: "periodic background DIRECT recheck of a timed-out origin"}
	c.wg.Add(1)
	go func() {
		defer c.wg.Done()
		defer func() { <-c.browser.probes }()
		ctx, cancel := context.WithTimeout(c.ctx, 3*time.Second)
		defer cancel()
		conclusive := false
		defer func() { c.browser.directTimeouts.ProbeDone(key, time.Now(), conclusive) }()
		if actual, err := c.browserProfile(q.Owner); err != nil || actual.network != current.network || !actual.enabled {
			return // Owner/network/activation changed: no conclusion for this key.
		}
		if host := c.browser.directTimeouts.ProbeHost(key); host != "" {
			q.Host = host
			resolver := c.BrowserResolver
			if resolver == nil {
				resolver = net.DefaultResolver
			}
			ips, err := resolver.LookupNetIP(ctx, "ip4", host)
			if err != nil || len(ips) == 0 {
				return
			}
			probePlan.Destination = netip.AddrPortFrom(ips[0].Unmap(), q.Port)
		}
		// A real HTTPS exchange with the origin, not a bare connect: a blackholing path
		// accepts the connect and then swallows the ClientHello.
		open := func(ctx context.Context) (net.Conn, error) { return c.browserOpenUnobserved(ctx, q, probePlan) }
		detail := browserproxy.ProbeOriginDetailed(ctx, q.Host, q.Port, q.Secure, c.BrowserProbeRoots, open)
		if actual, err := c.browserProfile(q.Owner); err != nil || actual.network != current.network || !actual.enabled {
			return
		}
		switch detail.Failure {
		case "":
			c.browser.directTimeouts.RecordSuccess(c.directTimeoutKey(current, q, probePlan)) // Verified TLS + HTTP GET, never bare ACK.
			conclusive = true
		case "NETWORK_TIMEOUT", "CONNECTION_RESET", "TLS_FAILED", "CONNECTION_FAILED":
			c.browser.directTimeouts.RecordTimeout(c.directTimeoutKey(current, q, probePlan), time.Now()) // Still broken.
			c.browser.directTimeouts.RecordTimeout(key, time.Now())                                       // Renew claimed domain TTL.
			c.browser.directTimeouts.SetProbeHost(key, q.Host)
			conclusive = true
		}
	}()
}

// Keep IPC below 64 KiB including all auxiliary diagnostics, not just records.
// Counters remain exact; omitted detail is explicitly marked as truncated.
func (v *browserStatusView) bound() {
	// Optional timings have their own bounded IPC, not routing evidence capacity.
	v.FirstByteMetrics, v.FirstByteLost = nil, 0
	for {
		raw, _ := json.Marshal(v)
		if len(raw) < 57000 {
			return
		}
		v.Truncated = true
		switch {
		case len(v.Records) > 0:
			v.Records = v.Records[:len(v.Records)-1]
		case len(v.FailureDetails) > 0:
			v.FailureDetails = v.FailureDetails[:len(v.FailureDetails)-1]
		case len(v.FirstByteMetrics) > 0:
			v.FirstByteMetrics = v.FirstByteMetrics[:len(v.FirstByteMetrics)-1]
			v.FirstByteLost++
		case len(v.PathMetrics) > 0:
			v.PathMetrics = v.PathMetrics[:len(v.PathMetrics)-1]
		case len(v.RelayUsage.VideoConnections) > 0:
			v.RelayUsage.VideoConnections = v.RelayUsage.VideoConnections[:len(v.RelayUsage.VideoConnections)-1]
			v.RelayUsage.VideoOmitted++
			v.RelayUsage.Truncated = true
		case len(v.RelayUsage.ActiveOrigins) > 0:
			v.RelayUsage.ActiveOrigins = v.RelayUsage.ActiveOrigins[:len(v.RelayUsage.ActiveOrigins)-1]
			v.RelayUsage.Truncated = true
		case len(v.RelayUsage.Minutes) > 0:
			v.RelayUsage.Minutes = v.RelayUsage.Minutes[:len(v.RelayUsage.Minutes)-1]
			v.RelayUsage.Truncated = true
		case len(v.DirectTimeouts.Top) > 0:
			v.DirectTimeouts.Top = v.DirectTimeouts.Top[:len(v.DirectTimeouts.Top)-1]
		default:
			return
		}
	}
}

// A real first-flight stall confirms only the caller's current network/profile.
// The fixed YouTube family shares that evidence; ordinary hosts do not.
func (c *Controller) recordBrowserStall(current profilesResult, q browserproxy.Request, p browserproxy.Plan) {
	if current.network == "" || q.Port == 53 {
		return
	}
	key := c.directTimeoutKey(current, q, p)
	if flowpolicy.BrowserRelayGroup(q.Host) == "youtube-media" {
		c.browser.directTimeouts.RecordOriginStall(key, time.Now())
		c.browser.directTimeouts.SetProbeHost(key, q.Host)
	} else {
		c.browser.directTimeouts.RecordStall(key, time.Now())
	}
}
