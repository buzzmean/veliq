package clientservice

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strings"
	"time"

	"github.com/buzzmean/neexitlag/core/browserproxy"
	"github.com/buzzmean/neexitlag/core/flowpolicy"
	wp "github.com/buzzmean/neexitlag/platform/windows"
)

// Retain verified DNS recovery when replacing ordinary AUTO probes with a known
// relay-first rule. Only a destination OPEN rejection can suggest wrong DNS;
// authentication/session failures must not cause a DNS/probe storm.
func recoverableKnownOriginOpen(err error) bool {
	var typed interface{ FailureReason() string }
	if !errors.As(err, &typed) {
		return false
	}
	switch strings.ToLower(typed.FailureReason()) {
	case "upstream_dial_timeout", "upstream_connection_refused", "upstream_dial_failed":
		return true
	}
	return false
}
func (c *Controller) openKnownBrowserGroup(ctx context.Context, current profilesResult, q browserproxy.Request, p browserproxy.Plan, open func(context.Context, browserproxy.Request, browserproxy.Plan) (net.Conn, error)) (net.Conn, browserproxy.Plan, error) {
	current = c.captureAutomaticScope(current)
	if !c.automaticScopeCurrent(current) {
		return nil, p, errAutomaticScopeChanged
	}
	open = c.automaticScopedOpen(current, open)
	// Warm flows skip quarantined IPs; expiry is a bounded lazy real recheck.
	if q.Secure && p.Policy.Action == flowpolicy.RelayRequired {
		key := c.browserDNSKey(q, current) + ":" + p.Policy.RelayID
		candidates := append([]netip.AddrPort{p.Destination}, p.RelayCandidates...)
		dst, skipped := c.browser.origins.Pick(key, candidates, nil, time.Now())
		if !dst.IsValid() {
			a, e := c.knownOriginResolve(ctx, current, q, p)
			if e == nil {
				for _, ip := range a.Addresses {
					candidates = append(candidates, netip.AddrPortFrom(ip, q.Port))
				}
				dst, _ = c.browser.origins.Pick(key, candidates, nil, time.Now())
			}
			if !dst.IsValid() {
				return nil, p, browserproxy.ErrOriginRecovery
			}
		}
		if dst != p.Destination {
			if err := c.validateKnownCandidate(current, q, dst, p.Policy.RelayID); err != nil {
				return nil, p, err
			}
			p = browserproxy.RetargetOrigin(p, dst)
		}
		p.Destination = dst
		p.OriginNegativeSkips = skipped
	}
	conn, err := open(ctx, q, p)
	if err == nil && q.Secure && p.Policy.Action == flowpolicy.RelayRequired {
		return c.watchKnownOrigin(conn, current, q, p, open), p, nil
	}
	if err == nil || ctx.Err() != nil || !q.Secure || !recoverableKnownOriginOpen(err) {
		return conn, p, err
	}
	if !c.automaticScopeCurrent(current) {
		return nil, p, errAutomaticScopeChanged
	}
	// DNSRecovery already has its own two-worker limit, singleflight and
	// negative cooldown. Do not borrow ordinary AUTO probe slots: background
	// browser origins can fill all four and starve this required DNS repair.

	if current.network != "" {
		c.browser.origins.Failed(c.browserDNSKey(q, current)+":"+p.Policy.RelayID, p.Destination, time.Now())
	}
	p.OriginPrior = append(p.OriginPrior, browserproxy.OriginAttempt{Destination: p.Destination.String(), Reason: "OPEN_FAILED"})
	if automaticApplication(current.profile) {
		ctx = context.WithValue(ctx, automaticScopeKey{}, current)
	}
	recovered, ok := c.recoverBrowserDNS(ctx, q, current, p)
	if !c.automaticScopeCurrent(current) {
		return nil, recovered, errAutomaticScopeChanged
	}
	if !ok {
		return nil, recovered, err
	}
	conn, err = open(ctx, q, recovered)
	if err == nil && recovered.Policy.Action == flowpolicy.RelayRequired {
		conn = c.watchKnownOrigin(conn, current, q, recovered, open)
	}
	return conn, recovered, err
}

// /3 OPEN carries an IP only. Independent DoH resolution travels over the
// authenticated VPS egress (HTTPS/443, never OS DNS/53 or client DIRECT).
// This needs no relay deployment or private production DNS API.
func (c *Controller) knownOriginResolve(ctx context.Context, current profilesResult, q browserproxy.Request, p browserproxy.Plan) (browserproxy.DNSAnswer, error) {
	current = c.captureAutomaticScope(current)
	if !c.automaticScopeCurrent(current) {
		return browserproxy.DNSAnswer{}, errAutomaticScopeChanged
	}
	key := c.browserDNSKey(q, current) + ":" + p.Policy.RelayID
	resolve := c.browser.origins.Resolve
	if current.network == "" {
		resolve = func(ctx context.Context, _ string, lookup func(context.Context) (browserproxy.DNSAnswer, error)) (browserproxy.DNSAnswer, error) {
			return c.browser.origins.Uncached(ctx, lookup)
		}
	}
	answer, err := resolve(ctx, key, func(ctx context.Context) (browserproxy.DNSAnswer, error) {
		if !c.automaticScopeCurrent(current) {
			return browserproxy.DNSAnswer{}, browserproxy.ErrOriginScopeChanged
		}
		lookup := c.BrowserAlternativeDNS
		if lookup == nil {
			lookup = browserproxy.NewDoHResolver().LookupAll
		}
		open := c.automaticScopedOpen(current, c.browserOpenUnobserved)
		answer, err := lookup(ctx, q.Host, func(ctx context.Context, dst netip.AddrPort) (net.Conn, error) {
			candidate := p
			candidate.Destination = dst
			return open(ctx, q, candidate)
		})
		if !c.automaticScopeCurrent(current) {
			return browserproxy.DNSAnswer{}, browserproxy.ErrOriginScopeChanged
		}
		return answer, err
	})
	if !c.automaticScopeCurrent(current) {
		return browserproxy.DNSAnswer{}, errAutomaticScopeChanged
	}
	return answer, err
}
func (c *Controller) watchKnownOrigin(conn net.Conn, current profilesResult, q browserproxy.Request, p browserproxy.Plan, open func(context.Context, browserproxy.Request, browserproxy.Plan) (net.Conn, error)) net.Conn {
	current = c.captureAutomaticScope(current)
	open = c.automaticScopedOpen(current, open)
	if _, ok := conn.(browserproxy.OriginReporter); ok {
		return conn
	}
	key := c.browserDNSKey(q, current) + ":" + p.Policy.RelayID
	health := c.browser.origins
	if current.network == "" {
		health = browserproxy.NewOriginHealth()
	}
	candidates := append([]netip.AddrPort{p.Destination}, p.RelayCandidates...)
	var scopeCurrent func() bool
	if automaticApplication(current.profile) {
		scopeCurrent = func() bool { return c.automaticScopeCurrent(current) }
	}
	return browserproxy.WatchRelayOrigin(conn, browserproxy.OriginConfig{Prior: p.OriginPrior, Skipped: p.OriginNegativeSkips, Context: c.ctx, Health: health, Scope: key, Initial: p.Destination, Candidates: candidates, RetryOpen: recoverableKnownOriginOpen,
		ScopeCurrent: scopeCurrent,
		Resolve: func(ctx context.Context) (browserproxy.DNSAnswer, error) {
			return c.knownOriginResolve(ctx, current, q, p)
		},
		Open: func(ctx context.Context, dst netip.AddrPort) (net.Conn, error) {
			if err := c.validateKnownCandidate(current, q, dst, p.Policy.RelayID); err != nil {
				return nil, err
			}
			next := browserproxy.RetargetOrigin(p, dst)
			return open(ctx, q, next)
		},
	})
}

// Preserve the original logical-flow policy snapshot, including per-IP BLOCK.
// The actual open callback additionally rechecks current owner/network/enabled.
func (c *Controller) validateKnownCandidate(current profilesResult, q browserproxy.Request, dst netip.AddrPort, relayID string) error {
	if rule, ok := flowpolicy.Evaluate(current.profile.Rules, flowpolicy.Input{Protocol: "tcp", Domain: q.Host, Destination: dst, Network: current.network}); ok && rule.Action == flowpolicy.Block {
		return browserproxy.ErrOriginCandidatePolicy
	}
	policy := c.browserFlow(current.profile, current.id, wp.Tuple{Protocol: "tcp", Source: q.Source, Destination: dst}, q.Host, current.network)
	if policy.Action == flowpolicy.Block || policy.Source == "rule" && (policy.Action != flowpolicy.RelayRequired || policy.RelayID != "" && policy.RelayID != relayID) {
		return browserproxy.ErrOriginCandidatePolicy
	}
	return nil
}
