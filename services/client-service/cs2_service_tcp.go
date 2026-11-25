package clientservice

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/buzzmean/veliq/core/browserproxy"
	"github.com/buzzmean/veliq/core/flowpolicy"
	"github.com/buzzmean/veliq/core/profiles"
	"github.com/buzzmean/veliq/core/routing"
	wp "github.com/buzzmean/veliq/platform/windows"
)

const cs2ProxySource = "cs2_system_proxy_direct"

func (c *Controller) cs2RestrictedOrigin(host string) bool {
	policy := c.browserOriginPolicy(host)
	return policy.Protected || policy.Kind == "RELAY"
}

// The driver's ordinary DIRECT decision reinjects the application's original
// TCP packets intact. Never create a probe connection or change its route.
// At this layer only a destination address is known. A fresh association with
// a relay-only domain may restrict it, even when the IP is shared.
func (c *Controller) cs2NativeTCP(id wp.ProcessIdentity, t wp.Tuple, p profiles.Profile) wp.Decision {
	d := cs2DirectDecision(p, id, t)
	if directOnlyFlow(t) {
		return d
	}
	n := c.network.Load()
	if n == nil || n.Error != "" || n.Fingerprint == "" || time.Since(n.ObservedAt) > 45*time.Second {
		return d
	}
	d.Network, d.Flow.Network = n.Fingerprint, n.Fingerprint
	e := c.browser.domains.profileEvidenceFor(n.Fingerprint, p.ID, t.Destination.Addr(), "", time.Now(), c.cs2RestrictedOrigin)
	if e.Restricted {
		d.Block, d.BlockOnFailure = true, true
		d.Flow.PinnedPolicy = &routing.Policy{Block: true, BlockOnFailure: true}
		d.Policy = flowpolicy.Result{Action: flowpolicy.Block, Fallback: flowpolicy.FailBlock, Source: "cs2_auto", Reason: "known relay-only service excluded by CS2 direct-only mode"}
	}
	return d
}

// A CS2 request explicitly using the Windows user proxy has an authority. Keep
// it off the browser resolver, stall watcher and relay fallback. The caller has
// already authenticated the socket owner, birth time and Windows user SID.
func (c *Controller) cs2ProxyPlan(owner wp.ProcessIdentity, q browserproxy.Request) (browserproxy.Plan, bool) {
	if !strings.EqualFold(owner.Path[strings.LastIndexAny(owner.Path, `/\`)+1:], "cs2.exe") {
		return browserproxy.Plan{}, false
	}
	p, ok := c.matchApplication(owner)
	if !ok || !c.cs2AutoProfile(p, owner) {
		return browserproxy.Plan{}, false
	}
	policy := flowpolicy.Result{Action: flowpolicy.Direct, Fallback: flowpolicy.FailOpen, Source: cs2ProxySource, Reason: "CS2 service uses the OS resolver and DIRECT TCP"}
	addr, _ := netip.ParseAddr(q.Host)
	t := wp.Tuple{Protocol: "tcp", Source: q.Source, Destination: netip.AddrPortFrom(addr, q.Port)}
	blocked := c.cs2RestrictedOrigin(q.Host) || c.cs2RouteBlocked(p, t, q.Host)
	if addr.IsValid() && c.cs2NativeTCP(owner, t, p).Block {
		blocked = true
	}
	if blocked {
		policy.Action, policy.Fallback, policy.Reason = flowpolicy.Block, flowpolicy.FailBlock, "relay-only service excluded by CS2 direct-only mode"
	}
	return browserproxy.Plan{Policy: policy}, true
}

func (c *Controller) openCS2ProxyDirect(ctx context.Context, owner wp.ProcessIdentity, q browserproxy.Request) (net.Conn, error) {
	// Let the OS resolver select among the addresses offered by the service.
	// Recheck each resolved IP before connecting so a hostname cannot bypass
	// a protected CIDR rule, including during IPv4/IPv6 connection racing.
	dialer := net.Dialer{Control: func(_, address string, _ syscall.RawConn) error {
		dst, err := netip.ParseAddrPort(address)
		if err != nil {
			return err
		}
		p, ok := c.matchApplication(owner)
		t := wp.Tuple{Protocol: "tcp", Source: q.Source, Destination: dst}
		if !ok || p.ID != q.Owner.Profile || !c.cs2AutoProfile(p, owner) || c.cs2RouteBlocked(p, t, q.Host) || c.cs2NativeTCP(owner, t, p).Block {
			return errors.New("CS2_PROXY_DIRECT_UNAVAILABLE")
		}
		return nil
	}}
	return dialer.DialContext(ctx, "tcp", net.JoinHostPort(q.Host, strconv.Itoa(int(q.Port))))
}
