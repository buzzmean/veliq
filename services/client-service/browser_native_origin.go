package clientservice

import (
	"context"
	"net"
	"net/netip"
	"time"

	"github.com/buzzmean/veliq/core/browserproxy"
	"github.com/buzzmean/veliq/core/flowpolicy"
)

// Opaque flows previously bypassed ALL origin health machinery. TLS alert bytes
// cannot be erased/replayed after reaching the browser. Select a TLS/HTTP-verified
// address BEFORE handing its ClientHello to an origin, then retain the ordinary
// no-replay-after-any-origin-byte rule. This is address evidence, not page PASS.
func (c *Controller) prepareHintedRelayOrigin(ctx context.Context, current profilesResult, q browserproxy.Request, p browserproxy.Plan, open browserproxy.DNSOpen) browserproxy.Plan {
	if !relayOriginEligible(q, p) || current.network == "" || (flowpolicy.KnownBrowserRelayGroup(q.Host) == "" && !protectedBrowserDomain(q.Host)) {
		return p
	}
	lookup := c.BrowserAlternativeDNS
	if lookup == nil {
		lookup = browserproxy.NewDoHResolver().LookupAll
	}
	key := c.browserDNSKey(q, current)
	result := c.browser.dns.Recover(ctx, key, q.Host, q.Port, c.BrowserProbeRoots, lookup, func(ctx context.Context, dst netip.AddrPort) (net.Conn, error) {
		if err := c.validateKnownCandidate(current, q, dst, p.Policy.RelayID); err != nil {
			return nil, err
		}
		return open(ctx, dst)
	})
	p.DNSRecovery = &result
	p.Trials = append(p.Trials, result.Trials...)
	// Only origin TLS/HTTP failures can quarantine an address. Auth/session/open
	// errors are not evidence against a destination and never trigger DIRECT.
	scope := key + ":" + p.Policy.RelayID
	for _, trial := range result.Trials {
		if trial.Outcome != "ORIGIN_RESPONSE" && (trial.Phase == "ORIGIN_TLS" || trial.Phase == "ORIGIN_RESPONSE") {
			if dst, e := netip.ParseAddrPort(trial.Destination); e == nil {
				c.browser.origins.Failed(scope, dst, time.Now())
			}
		}
	}
	if result.Usable() {
		p.Destination = result.Destination
		p.HTTPStatus = result.Probe.Status
		p.Probe = result.ProbeName()
		p.RelayCandidates = append([]netip.AddrPort{result.Destination}, p.RelayCandidates...)
	}
	return p
}
