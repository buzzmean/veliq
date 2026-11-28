package clientservice

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strconv"
	"syscall"
	"time"

	"github.com/buzzmean/veliq/core/browserproxy"
	"github.com/buzzmean/veliq/core/flowpolicy"
	"github.com/buzzmean/veliq/core/profiles"
	wp "github.com/buzzmean/veliq/platform/windows"
)

const applicationProxyDirectSource = "application_system_proxy_direct"

var errApplicationProxyDirectChanged = errors.New("APPLICATION_PROXY_DIRECT_UNAVAILABLE")

func applicationProxyDirectProfile(p profiles.Profile) bool {
	return p.Mode == profiles.Direct && p.Trial == nil && len(p.Rules) == 0 &&
		len(p.BrowserRecoveryRules) == 0 && p.Fallback == "" && p.LocalStrategyID == ""
}

// The owner-wide Windows proxy is also used by game login clients. An explicit
// ordinary DIRECT profile must retain the OS resolver and address fallback,
// rather than depending on browser DNS or one preselected IPv4/IPv6 address.
// Profiles with rules, required fallback or another mode keep their old policy.
func (c *Controller) applicationProxyDirectPlan(id wp.ProcessIdentity, q browserproxy.Request) (browserproxy.Plan, bool) {
	p, ok := c.matchApplication(id)
	if !ok || p.ID != q.Owner.Profile || !applicationProxyDirectProfile(p) {
		return browserproxy.Plan{}, false
	}
	policy := flowpolicy.Result{Action: flowpolicy.Direct, Fallback: flowpolicy.FailOpen, Source: applicationProxyDirectSource, Reason: "DIRECT application uses OS resolution and address selection"}
	addr, _ := netip.ParseAddr(q.Host)
	tuple := wp.Tuple{Protocol: "tcp", Source: q.Source, Destination: netip.AddrPortFrom(addr, q.Port)}
	if c.cs2RestrictedOrigin(q.Host) || addr.IsValid() && c.directProxyRestrictedAddress(p, tuple) {
		policy.Action, policy.Fallback, policy.Reason = flowpolicy.Block, flowpolicy.FailBlock, "protected authority cannot use DIRECT"
	}
	return browserproxy.Plan{Policy: policy}, true
}

// Shared with CS2 AUTO: a fresh restrictive association still applies to every
// address chosen by the OS, including IPv6 and hostname resolution races.
func (c *Controller) directProxyRestrictedAddress(p profiles.Profile, tuple wp.Tuple) bool {
	if directOnlyFlow(tuple) {
		return false
	}
	n := c.network.Load()
	if n == nil || n.Error != "" || n.Fingerprint == "" || time.Since(n.ObservedAt) > 45*time.Second {
		return false
	}
	return c.browser.domains.profileEvidenceFor(n.Fingerprint, p.ID, tuple.Destination.Addr(), "", time.Now(), c.cs2RestrictedOrigin).Restricted
}

// currentOwner is the existing PID/birth/SID authority check in production.
// It runs again after DNS and before each SYN, not just before a slow lookup.
func (c *Controller) applicationProxyDirectDialer(q browserproxy.Request, currentOwner func() (wp.ProcessIdentity, error)) *net.Dialer {
	return &net.Dialer{Control: func(_, address string, _ syscall.RawConn) error {
		if currentOwner == nil {
			return errApplicationProxyDirectChanged
		}
		id, err := currentOwner()
		if err != nil {
			return err
		}
		dst, err := netip.ParseAddrPort(address)
		if err != nil {
			return err
		}
		plan, ok := c.applicationProxyDirectPlan(id, q)
		if !ok || plan.Policy.Action != flowpolicy.Direct {
			return errApplicationProxyDirectChanged
		}
		p, ok := c.matchApplication(id)
		tuple := wp.Tuple{Protocol: "tcp", Source: q.Source, Destination: dst}
		if !ok || c.directProxyRestrictedAddress(p, tuple) {
			return errApplicationProxyDirectChanged
		}
		return nil
	}}
}

func (c *Controller) openApplicationProxyDirect(ctx context.Context, q browserproxy.Request) (net.Conn, error) {
	dialer := c.applicationProxyDirectDialer(q, func() (wp.ProcessIdentity, error) { return c.authorityCurrent(q) })
	return dialer.DialContext(ctx, "tcp", net.JoinHostPort(q.Host, strconv.Itoa(int(q.Port))))
}
