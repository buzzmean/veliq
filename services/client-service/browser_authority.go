package clientservice

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/buzzmean/neexitlag/core/browserproxy"
	"github.com/buzzmean/neexitlag/core/flowpolicy"
	"github.com/buzzmean/neexitlag/core/routing"
	wp "github.com/buzzmean/neexitlag/platform/windows"
	"net"
	"net/netip"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"
)

type browserAuthorityRuntime struct {
	published atomic.Pointer[browserAuthorityPublished]
	mu        sync.Mutex
	server    *browserproxy.Server
	pac       string
	applied   bool
	appliedAt time.Time
	checked   time.Time
	lastError string
	guardKey  string
	exchange  ownerProxyExchange // isolated test seam; never an IPC setting
}
type browserAuthorityPublished struct {
	server    *browserproxy.Server
	applied   bool
	appliedAt time.Time
	reason    string
}

func (a *browserAuthorityRuntime) publish() {
	a.published.Store(&browserAuthorityPublished{a.server, a.applied, a.appliedAt, a.lastError})
}

func (c *Controller) authorityOwner(ctx context.Context, source, local netip.AddrPort) (browserproxy.Owner, error) {
	id, err := wp.LookupTCPPeer(source, local)
	if err != nil || !wp.IsCurrent(id) {
		return browserproxy.Owner{}, browserproxy.ErrOwnerLookup
	}
	sid, err := wp.ProcessUserSID(id)
	if err != nil || c.BrowserOwnerSID == "" || sid != c.BrowserOwnerSID {
		return browserproxy.Owner{}, browserproxy.ErrOwnerSID
	}
	p, ok := c.matchApplication(id)
	profile := "owner-system-passthrough"
	if ok {
		profile = p.ID
	}
	return browserproxy.Owner{PID: id.PID, Birth: id.CreationTime, Exe: id.Path, Profile: profile}, nil
}
func (c *Controller) authorityCurrent(q browserproxy.Request) (wp.ProcessIdentity, error) {
	id := browserIdentity(q)
	if !wp.IsCurrent(id) {
		return id, browserproxy.ErrOwnerLookup
	}
	sid, err := wp.ProcessUserSID(id)
	if err != nil || c.BrowserOwnerSID == "" || sid != c.BrowserOwnerSID {
		return id, browserproxy.ErrOwnerSID
	}
	p, ok := c.matchApplication(id)
	if ok && p.ID != q.Owner.Profile || !ok && q.Owner.Profile != "owner-system-passthrough" {
		return id, browserproxy.ErrOwnerProfile
	}
	return id, nil
}
func (c *Controller) authorityBrowser(q browserproxy.Request) bool {
	p, ok := c.matchApplication(browserIdentity(q))
	return ok && nativeBrowserProfile(p)
}
func (c *Controller) authorityPlan(ctx context.Context, q browserproxy.Request) (browserproxy.Plan, error) {
	id, err := c.authorityCurrent(q)
	if err != nil {
		return browserproxy.Plan{}, err
	}
	if c.authorityBrowser(q) {
		return c.browserPlan(ctx, q)
	}
	resolver := c.BrowserResolver
	if resolver == nil {
		resolver = net.DefaultResolver
	}
	lookup, cancel := context.WithTimeout(ctx, time.Second)
	addresses, err := resolver.LookupNetIP(lookup, "ip", q.Host)
	cancel()
	if err != nil || len(addresses) == 0 {
		return browserproxy.Plan{}, browserproxy.ErrOriginDNS
	}
	address := addresses[0].Unmap()
	for _, ip := range addresses {
		if ip.Is4() {
			address = ip.Unmap()
			break
		}
	}
	destination := netip.AddrPortFrom(address, q.Port)
	tuple := wp.Tuple{Protocol: "tcp", Source: q.Source, Destination: destination}
	d := c.Classify(id, tuple)
	if d.ResolveDomain != nil {
		d = d.ResolveDomain(q.Host)
	}
	r := d.Policy
	if r.Action == "" {
		r = flowpolicy.Result{Action: flowpolicy.Direct, Fallback: flowpolicy.FailOpen, Source: "owner_system_passthrough", Reason: "same-owner application keeps its existing routing policy"}
		if d.Block {
			r.Action = flowpolicy.Block
			r.Fallback = flowpolicy.FailBlock
		} else if d.Route.Local() {
			r.Action = flowpolicy.DirectPlus
			r.Strategy = d.LocalStrategyID
		} else if d.Route.RelayID != "" {
			r.Action = flowpolicy.Relay
			r.RelayID = d.Route.RelayID
			if d.BlockOnFailure {
				r.Fallback = flowpolicy.Required
			}
		}
	}
	c.mu.Lock()
	enabled := c.enabled
	c.mu.Unlock()
	return browserproxy.Plan{Enabled: enabled, Network: d.Network, Destination: destination, Policy: r}, nil
}
func (c *Controller) authorityOpen(ctx context.Context, q browserproxy.Request, plan browserproxy.Plan) (net.Conn, error) {
	id, err := c.authorityCurrent(q)
	if err != nil {
		return nil, err
	}
	if c.authorityBrowser(q) {
		return c.browserOpen(ctx, q, plan)
	}
	fresh, err := c.authorityPlan(ctx, q)
	if err != nil || fresh.Enabled != plan.Enabled || fresh.Network != plan.Network || fresh.Policy != plan.Policy {
		return nil, errors.New("OWNER_PROXY_APPLICATION_POLICY_CHANGED")
	}
	if plan.Policy.Action == flowpolicy.Block {
		return nil, errors.New("OWNER_PROXY_APPLICATION_BLOCKED")
	}
	p, _ := c.matchApplication(id)
	d := applyFlowResult(p, wp.Decision{}, plan.Policy, plan.Network, c.Local)
	d.Flow = routing.Flow{Protocol: "tcp", Source: q.Source, Destination: plan.Destination, PID: id.PID, ProcessPath: id.Path, ApplicationID: q.Owner.Profile, Network: plan.Network, PinnedPolicy: d.Flow.PinnedPolicy}
	if d.Route.Local() {
		backend, ok := c.Backend.(interface {
			OpenBrowserLocalTCP(context.Context, wp.ProcessIdentity, netip.AddrPort, netip.AddrPort, wp.Decision) (net.Conn, error)
		})
		if !ok {
			return nil, errors.New("OWNER_PROXY_LOCAL_UNAVAILABLE")
		}
		return backend.OpenBrowserLocalTCP(ctx, id, q.Source, plan.Destination, d)
	}
	if !plan.Enabled || q.Owner.Profile == "owner-system-passthrough" {
		return (&net.Dialer{}).DialContext(ctx, "tcp", plan.Destination.String())
	}
	return c.Engine.OpenTCP(ctx, d.Flow)
}
func (c *Controller) authorityOpenPlan(ctx context.Context, q browserproxy.Request, plan browserproxy.Plan) (net.Conn, browserproxy.Plan, error) {
	if c.authorityBrowser(q) {
		return c.browserOpenPlan(ctx, q, plan)
	}
	conn, err := c.authorityOpen(ctx, q, plan)
	return conn, plan, err
}

func (c *Controller) authorityLeasePath() string {
	return filepath.Join(filepath.Dir(c.customPath), "browser-owner-proxy.json")
}

// One shared owner lane is needed because Windows exposes one system PAC per
// user. Unselected programs pass through their own normal policy, never through
// a browser profile. Existing per-browser owned PAC listeners remain valid.
func (c *Controller) RetryBrowserAuthority() {
	if c.customPath == "" || c.BrowserOwnerSID == "" {
		return
	}
	c.browser.mu.Lock()
	chromeOwned := append([]string{}, c.browser.silent.Owned...)
	edgeOwned := []string{}
	if c.browser.edge != nil {
		edgeOwned = append(edgeOwned, c.browser.edge.saved.Owned...)
	}
	c.browser.mu.Unlock()
	a := &c.browser.authority
	a.mu.Lock()
	defer a.mu.Unlock()
	defer a.publish()
	if time.Since(a.checked) < 5*time.Second {
		return
	}
	a.checked = time.Now()
	c.mu.Lock()
	enabled := c.enabled && c.settings.Automatic
	c.mu.Unlock()
	guards := []string{}
	strict := false
	wanted := false
	chromeWanted, edgeWanted := false, false
	for _, p := range c.Profiles.List() {
		if nativeBrowserProfile(p) {
			wanted = true
			if edgeProfile(p) {
				edgeWanted = true
			} else {
				chromeWanted = true
			}
			domains, s := edgeGuard(p)
			guards = append(guards, domains...)
			strict = strict || s
		}
	}
	exchange := a.exchange
	if exchange == nil {
		exchange = exchangeOwnerProxy
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	if !enabled || !wanted {
		if err := releaseOwnerProxy(ctx, c.authorityLeasePath(), c.BrowserOwnerSID, exchange); err != nil {
			a.lastError = err.Error()
		} else {
			a.applied = false
			a.lastError = ""
		}
		return
	}
	// Preserve an installed guard while activation/capture/relay recover. A fresh
	// lane is published only after owner activation and a configured capture path.
	if !c.activationNetworkAllowed() || !c.nativeBackendConfigured() {
		a.lastError = "AUTHORITY_ACTIVATION_PENDING"
		return
	}
	if a.exchange == nil {
		if chromeWanted {
			if err := wp.OwnerBrowserProxyPolicyAvailable(c.BrowserOwnerSID, false, chromeOwned); err != nil {
				a.lastError = err.Error()
				return
			}
		}
		if edgeWanted {
			if err := wp.OwnerBrowserProxyPolicyAvailable(c.BrowserOwnerSID, true, edgeOwned); err != nil {
				a.lastError = err.Error()
				return
			}
		}
	}
	if a.server == nil {
		address := ""
		lease, err := readOwnerProxyLease(c.authorityLeasePath(), c.BrowserOwnerSID)
		if err != nil {
			a.lastError = err.Error()
			return
		}
		if lease != nil {
			address = authorityAddress(lease.Installed.PAC)
			if address == "" {
				a.lastError = "OWNER_PROXY_JOURNAL_INVALID"
				return
			}
		}
		server, err := browserproxy.Listen(c.ctx, browserproxy.Config{Address: address, RequireClientHelloReplay: true, Authorize: c.authorityOwner, Plan: c.authorityPlan, Open: c.authorityOpen, OpenPlan: c.authorityOpenPlan, TransformApplied: c.browserTransform, OnStall: c.browserStall, OnDirectAnswered: c.browserDirectAnswered})
		if err != nil {
			a.lastError = "AUTHORITY_LISTENER_UNAVAILABLE"
			return
		}
		a.server = server
	}
	guardKey := fmt.Sprint(strict, guards)
	if a.pac == "" || guardKey != a.guardKey {
		epoch := make([]byte, 16)
		if _, err := rand.Read(epoch); err != nil {
			a.lastError = "AUTHORITY_EPOCH_UNAVAILABLE"
			return
		}
		pac, err := authorityPAC(a.server.Address(), hex.EncodeToString(epoch), guards, strict)
		if err != nil {
			a.lastError = "AUTHORITY_PAC_UNAVAILABLE"
			return
		}
		a.pac = pac
		a.guardKey = guardKey
		a.applied = false
	}
	at := time.Now()
	if err := acquireOwnerProxy(ctx, c.authorityLeasePath(), c.BrowserOwnerSID, a.pac, exchange); err != nil {
		a.lastError = err.Error()
		return
	}
	if !a.applied {
		a.appliedAt = at
	}
	a.applied = true
	a.lastError = ""
}

func (c *Controller) nativeAuthorityLane(edge bool) bool {
	for _, p := range c.Profiles.List() {
		if nativeBrowserProfile(p) && edgeProfile(p) == edge {
			return true
		}
	}
	return false
}

// Deliberate OFF/SCM stop restores the full original snapshot while listeners
// still answer cached PAC. Infrastructure failures do not call this operation.
func (c *Controller) releaseBrowserAuthority() error {
	if c.customPath == "" || c.BrowserOwnerSID == "" {
		return nil
	}
	a := &c.browser.authority
	a.mu.Lock()
	defer a.mu.Unlock()
	defer a.publish()
	exchange := a.exchange
	if exchange == nil {
		exchange = exchangeOwnerProxy
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	err := releaseOwnerProxy(ctx, c.authorityLeasePath(), c.BrowserOwnerSID, exchange)
	if err == nil {
		a.applied = false
		a.lastError = ""
	} else {
		a.lastError = err.Error()
	}
	return err
}

// RestoreOwnerBrowserProxy is the explicit installer/uninstaller cleanup path.
// It conditionally restores only the persisted installation owner's own lease.
func (c *Controller) RestoreOwnerBrowserProxy() error { return c.releaseBrowserAuthority() }
