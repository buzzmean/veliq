package clientservice

import (
	"context"
	"errors"
	"net"

	"github.com/buzzmean/neexitlag/core/browserproxy"
	"github.com/buzzmean/neexitlag/core/flowpolicy"
	"github.com/buzzmean/neexitlag/core/transport"
)

func browserCapacityFailure(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, errVideoRelayCapacity) {
		return true
	}
	switch transport.FailureReason(err) {
	case "stream_capacity", "relay_flow_capacity":
		return true
	}
	return false
}

// Called only on OPEN failure, before any application bytes are written. Never
// hides the actual route inside a Conn: both native/PAC receive the DIRECT plan.
func (c *Controller) capacityDirectFallback(ctx context.Context, cur profilesResult, q browserproxy.Request, p browserproxy.Plan, conn net.Conn, err error, open func(context.Context, browserproxy.Request, browserproxy.Plan) (net.Conn, error)) (net.Conn, browserproxy.Plan, error) {
	allowed := p.Enabled && cur.enabled && browserAuto(cur.profile) && p.Policy.Source != "rule" && p.Policy.Action == flowpolicy.RelayRequired
	allowed = allowed && !restrictiveBrowserDomain(q.Host) && !browserproxy.KnownDoHEndpoint(q.Host, p.Destination)
	if q.Host == "" {
		allowed = allowed && p.OrdinaryCapacityDirect
	} else {
		allowed = allowed && browserproxy.ValidPublicDNSName(q.Host)
	}
	if r, ok := flowpolicy.Evaluate(cur.profile.Rules, flowpolicy.Input{Protocol: "tcp", Destination: p.Destination, Domain: q.Host, Network: cur.network}); ok && (r.Action == flowpolicy.Block || r.Action == flowpolicy.RelayRequired || r.Action == flowpolicy.Relay) {
		allowed = false
	}
	if !allowed || ctx.Err() != nil || !browserCapacityFailure(err) {
		return conn, p, err
	}
	if conn != nil {
		conn.Close()
	}
	p.Policy = flowpolicy.Result{Action: flowpolicy.Direct, Fallback: flowpolicy.FailOpen, Source: "browser_ordinary_capacity_direct", Reason: "no relay OPEN capacity; ordinary AUTO origin uses DIRECT before any application bytes; protected origins excluded"}
	p.Probe = "RELAY_CAPACITY_ORDINARY_DIRECT"
	p.DNSRecovery = nil
	u := c.relayUsage()
	u.mu.Lock()
	u.capacityDirectFallbacks++
	u.mu.Unlock()
	conn, err = open(ctx, q, p)
	return conn, p, err
}
