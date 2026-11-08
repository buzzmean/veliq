package clientservice

import (
	"context"
	"errors"
	"github.com/buzzmean/neexitlag/core/browserproxy"
	"github.com/buzzmean/neexitlag/core/flowpolicy"
	"net"
	"net/netip"
	"time"
)

// Restore only an exact owned listener before slow activation/network startup.
// No new Windows setting, credential, relay session or capture is created here.
func (c *Controller) RestoreOwnerAuthorityListener() error {
	if c.customPath == "" || c.BrowserOwnerSID == "" {
		return nil
	}
	a := &c.browser.authority
	a.mu.Lock()
	defer a.mu.Unlock()
	defer a.publish()
	return c.restoreAuthorityListenerLocked(a, true)
}
func (c *Controller) restoreAuthorityListenerLocked(a *browserAuthorityRuntime, existingOnly bool) error {
	if a.server != nil && a.server.Snapshot().Listening {
		return nil
	}
	address := ""
	lease, err := readOwnerProxyLease(c.authorityLeasePath(), c.BrowserOwnerSID)
	if err != nil {
		return err
	}
	if lease == nil && existingOnly {
		return nil
	}
	if lease != nil {
		address = authorityServerAddress(lease.Installed.Server)
		if lease.Installed.PAC != "" {
			address = authorityAddress(lease.Installed.PAC)
		}
		if address == "" {
			return errors.New("OWNER_PROXY_JOURNAL_INVALID")
		}
		a.guardRequired.Store(true)
	}
	server, err := browserproxy.Listen(c.ctx, browserproxy.Config{Address: address, RequireClientHelloReplay: true, Authorize: c.authorityOwner, Plan: c.authorityPlan, Open: c.authorityOpen, OpenPlan: c.authorityOpenPlan, TransformApplied: c.browserTransform, OnStall: c.browserStall, OnDirectAnswered: c.browserDirectAnswered})
	if err != nil {
		return errors.New("AUTHORITY_LISTENER_UNAVAILABLE")
	}
	a.server = server
	return nil
}
func (c *Controller) authorityGuardPending() bool {
	if !c.browser.authority.guardRequired.Load() {
		return false
	}
	c.mu.Lock()
	enabled, automatic := c.enabled, c.settings.Automatic
	c.mu.Unlock()
	return automatic && (!c.activationNetworkAllowed() || !enabled && !c.activation.stopAutomatic.Load())
}
func (c *Controller) authorityGuardPlan(ctx context.Context, q browserproxy.Request) (browserproxy.Plan, error) {
	current, err := c.browserProfile(q.Owner)
	if err != nil {
		return browserproxy.Plan{}, err
	}
	policy := flowpolicy.Result{Action: flowpolicy.Direct, Fallback: flowpolicy.FailOpen, Source: "owner_authority_boot_guard", Reason: "owned CONNECT startup: ordinary DIRECT until activation/capture are available"}
	if protectedBrowserDomain(q.Host) || c.browserOriginPolicy(q.Host).Kind == "RELAY" || youtubeRelayDomain(q.Host) || browserGuardedRule(current.profile, q.Host) {
		policy.Action = flowpolicy.Block
		policy.Fallback = flowpolicy.FailBlock
		policy.Reason = "owned CONNECT startup: protected authority remains blocked until activation"
		return browserproxy.Plan{Network: current.network, Policy: policy}, nil
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
	return browserproxy.Plan{Network: current.network, Destination: netip.AddrPortFrom(ip, q.Port), Policy: policy}, nil
}
