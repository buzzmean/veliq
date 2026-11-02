package clientservice

import (
	"context"
	"errors"
	"github.com/buzzmean/neexitlag/core/browserproxy"
	"github.com/buzzmean/neexitlag/core/flowpolicy"
	wp "github.com/buzzmean/neexitlag/platform/windows"
	"net"
	"net/netip"
	"time"
)

// WinHTTP/WinINET consumers may not support an inline data PAC, and a Chromium
// PAC resolver can fail. The explicit manual proxy fallback is a separate lane:
// browsers get authenticated RELAY for TLS, so connection coalescing cannot
// transfer a later protected authority into a DIRECT/LOCAL upstream. Other
// applications retain their own routing. No MITM, TLS keys or request replay.
func (c *Controller) authorityFallbackPlan(ctx context.Context, q browserproxy.Request) (browserproxy.Plan, error) {
	if _, err := c.authorityCurrent(q); err != nil {
		return browserproxy.Plan{}, err
	}
	if !c.authorityBrowser(q) || !q.Secure {
		return c.authorityPlan(ctx, q)
	}
	current, err := c.browserProfile(q.Owner)
	if err != nil {
		return browserproxy.Plan{}, err
	}
	resolver := c.BrowserResolver
	if resolver == nil {
		resolver = net.DefaultResolver
	}
	lookup, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	addresses, err := resolver.LookupNetIP(lookup, "ip", q.Host)
	if err != nil || len(addresses) == 0 {
		return browserproxy.Plan{}, browserproxy.ErrOriginDNS
	}
	ip := addresses[0].Unmap()
	for _, candidate := range addresses {
		if candidate.Is4() {
			ip = candidate.Unmap()
			break
		}
	}
	destination := netip.AddrPortFrom(ip, q.Port)
	plan := browserproxy.Plan{Enabled: current.enabled, Network: current.network, Destination: destination}
	if current.routingDisabled {
		return disabledBrowserPlan(plan), nil
	}
	relay := current.profile.RelayID
	if relay == "" {
		relay = "VPS-01"
	}
	plan.Policy = flowpolicy.Result{Action: flowpolicy.RelayRequired, RelayID: relay, Fallback: flowpolicy.Required, Source: "browser_authority_fallback_relay", Reason: "system proxy fallback has no per-origin proxy aliases: temporary authenticated relay for browser TLS"}
	rule := c.browserFlow(current.profile, current.id, wp.Tuple{Protocol: "tcp", Source: q.Source, Destination: destination}, q.Host, current.network)
	if rule.Action == flowpolicy.Block {
		plan.Policy = rule
	}
	if q.Port == 53 {
		plan.Policy = flowpolicy.Result{Action: flowpolicy.Block, Fallback: flowpolicy.FailBlock, Source: "authority_tls_dns_port_blocked", Reason: "TLS proxy fallback must not send DNS port 53 through relay"}
	}
	return plan, nil
}
func (c *Controller) authorityFallbackOpen(ctx context.Context, q browserproxy.Request, plan browserproxy.Plan) (net.Conn, error) {
	if _, err := c.authorityCurrent(q); err != nil {
		return nil, err
	}
	if !c.authorityBrowser(q) || !q.Secure {
		return c.authorityOpen(ctx, q, plan)
	}
	if plan.Policy.Action != flowpolicy.RelayRequired && plan.Policy.Action != flowpolicy.Block && plan.Policy.Source != "optimization_disabled" {
		return nil, errors.New("AUTHORITY_FALLBACK_ROUTE_INVALID")
	}
	q.Ingress = "SYSTEM_PROXY_FALLBACK" // Trusted listener provenance, never a browser header.
	return c.browserOpen(ctx, q, plan)
}
