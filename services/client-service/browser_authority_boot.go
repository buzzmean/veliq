package clientservice

import (
	"context"
	"errors"
	"github.com/buzzmean/neexitlag/core/browserproxy"
	"github.com/buzzmean/neexitlag/core/flowpolicy"
	"net"
	"net/netip"
	"path/filepath"
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
	directory := filepath.Dir(c.customPath)
	if err := prepareAuthorityEndpoints(directory, c.BrowserOwnerSID, ""); err != nil {
		return err
	}
	endpoints, err := readAuthorityEndpoints(directory, c.BrowserOwnerSID)
	if err != nil {
		return err
	}
	address := ""
	lease, err := readOwnerProxyLease(c.authorityLeasePath(), c.BrowserOwnerSID)
	if err != nil {
		return err
	}
	if lease == nil && endpoints == nil && existingOnly {
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
	if endpoints != nil {
		address = endpoints.Primary
		a.guardRequired.Store(true)
	}
	a.endpoints = []authorityListenerPublished{{Role: "primary", Address: address}}
	if a.server == nil || !a.server.Snapshot().Listening {
		server, err := c.listenOwnerAuthority(address)
		if err != nil {
			a.endpoints[0].Error = "AUTHORITY_LISTENER_UNAVAILABLE"
			return errors.New("AUTHORITY_LISTENER_UNAVAILABLE")
		}
		if endpoints == nil {
			endpoints = &ownerAuthorityEndpoints{Version: 1, Owner: c.BrowserOwnerSID, Primary: server.Address()}
			if err := writeAuthorityEndpoints(directory, *endpoints); err != nil {
				server.Close()
				return err
			}
		}
		a.server = server
	}
	if endpoints == nil {
		endpoints = &ownerAuthorityEndpoints{Version: 1, Owner: c.BrowserOwnerSID, Primary: a.server.Address()}
		if err := writeAuthorityEndpoints(directory, *endpoints); err != nil {
			return err
		}
	}
	a.endpoints[0].Address, a.endpoints[0].Server = a.server.Address(), a.server
	if a.compatibility == nil {
		a.compatibility = map[string]*browserproxy.Server{}
	}
	var bindError error
	for _, address := range endpoints.Compatibility {
		server := a.compatibility[address]
		view := authorityListenerPublished{Role: "compatibility", Address: address}
		if server == nil || !server.Snapshot().Listening {
			var err error
			server, err = c.listenOwnerAuthority(address)
			if err != nil {
				view.Error = "AUTHORITY_COMPAT_LISTENER_UNAVAILABLE"
				bindError = errors.New(view.Error)
			} else {
				a.compatibility[address] = server
			}
		}
		view.Server = server
		a.endpoints = append(a.endpoints, view)
	}
	return bindError
}

func (c *Controller) listenOwnerAuthority(address string) (*browserproxy.Server, error) {
	return browserproxy.Listen(c.ctx, browserproxy.Config{Address: address, RequireClientHelloReplay: true, Authorize: c.authorityOwner, Plan: c.authorityPlan, Open: c.authorityOpen, OpenPlan: c.authorityOpenPlan, TransformApplied: c.browserTransform, OnStall: c.browserStall, OnDirectAnswered: c.browserDirectAnswered, OnDiagnostic:c.observeProxyDiagnostic})
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
