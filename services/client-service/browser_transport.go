package clientservice

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"github.com/buzzmean/neexitlag/core/browserproxy"
	"github.com/buzzmean/neexitlag/core/flowpolicy"
	"github.com/buzzmean/neexitlag/core/localstrategy"
	"github.com/buzzmean/neexitlag/core/profiles"
	"github.com/buzzmean/neexitlag/core/routing"
	"github.com/buzzmean/neexitlag/core/security"
	wp "github.com/buzzmean/neexitlag/platform/windows"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

type browserRuntime struct {
	authority browserAuthorityRuntime
	youtube   *youtubeRuntime
	dnsWire   *browserDNSRuntime
	domains   browserDomainIndex
	readiness browserPolicyReadiness

	youtubeLocalBetaProbes chan struct{}

	silent          browserSilentState
	chromeWrite     func(string, []string, string) error
	chromeRemove    func(string, []string) error
	chromeActive    func(string, string) bool
	origins         *browserproxy.OriginHealth
	native          nativeBrowserRuntime
	riot            nativeBrowserRuntime
	applications    nativeBrowserRuntime
	usage           *browserRelayUsage
	edge            *edgeRuntime // Independent Edge transport; Chrome fields stay unchanged.
	dns             *browserproxy.DNSRecovery
	address         string
	lastError       string
	expectedPAC     string
	recoveryAddress string
	mu              sync.Mutex
	server          *browserproxy.Server
	learned         *flowpolicy.BrowserLearning
	probes          chan struct{}
	local           map[string]*localstrategy.LocalStrategyEngine
	plans           map[flowpolicy.LearnKey]chan struct{}
	directTimeouts  *flowpolicy.DirectTimeoutCache
}

func newBrowserRuntime() *browserRuntime {
	return &browserRuntime{youtube: newYoutubeRuntime(), dnsWire: newBrowserDNSRuntime(), origins: browserproxy.NewOriginHealth(), dns: browserproxy.NewDNSRecovery(), learned: flowpolicy.NewBrowserLearning(), probes: make(chan struct{}, 4), youtubeLocalBetaProbes: make(chan struct{}, 4), local: map[string]*localstrategy.LocalStrategyEngine{}, plans: map[flowpolicy.LearnKey]chan struct{}{}, directTimeouts: flowpolicy.NewDirectTimeoutCache()}
}
func (c *Controller) browserOwner(ctx context.Context, source, local netip.AddrPort) (browserproxy.Owner, error) {
	id, err := wp.LookupTCPPeer(source, local)
	if err != nil {
		return browserproxy.Owner{}, browserproxy.ErrOwnerLookup
	}
	sid, sidErr := wp.ProcessUserSID(id)
	if sidErr != nil {
		return browserproxy.Owner{}, browserproxy.ErrOwnerToken
	}
	if c.BrowserOwnerSID == "" || sid != c.BrowserOwnerSID {
		return browserproxy.Owner{}, browserproxy.ErrOwnerSID
	}
	p, ok := c.matchApplication(id)
	if !ok || !chromeProfile(p) || p.Trial != nil {
		return browserproxy.Owner{}, browserproxy.ErrOwnerProfile
	}
	return browserproxy.Owner{PID: id.PID, Birth: id.CreationTime, Exe: id.Path, Profile: p.ID}, nil
}
func (c *Controller) browserProfile(owner browserproxy.Owner) (profilesResult, error) {
	if profiles.RiotLauncherPath(owner.Exe) {
		return c.riotOwnerProfile(owner)
	}
	if edgeExecutable(owner.Exe) {
		return c.edgeOwnerProfile(owner)
	}
	if p, ok := c.automaticProfile(wp.ProcessIdentity{PID: owner.PID, CreationTime: owner.Birth, Path: owner.Exe}); ok && p.ID == owner.Profile && automaticApplication(p) {
		return c.automaticOwnerProfile(owner)
	}
	id := wp.ProcessIdentity{PID: owner.PID, CreationTime: owner.Birth, Path: owner.Exe}
	if !wp.IsCurrent(id) {
		return profilesResult{}, errors.New("Chrome owner exited/reused")
	}
	p, ok := c.matchApplication(id)
	if !ok || p.ID != owner.Profile || !chromeProfile(p) {
		return profilesResult{}, errors.New("Chrome AUTO profile changed")
	}
	network := ""
	if n := c.network.Load(); n != nil && n.Error == "" && time.Since(n.ObservedAt) <= 45*time.Second {
		network = n.Fingerprint
	}
	c.mu.Lock()
	routingEnabled := c.enabled && c.settings.Automatic
	enabled := routingEnabled && p.Mode == profiles.Auto
	c.mu.Unlock()
	if routingEnabled && p.Mode != profiles.Auto && p.Mode != profiles.Direct {
		return profilesResult{}, errors.New("Chrome AUTO profile changed")
	}
	return profilesResult{profile: p, id: id, network: network, enabled: enabled, routingDisabled: !routingEnabled}, nil
}

// Keep mutable ownership resolution separate from immutable request plans.
type profilesResult struct {
	profile           profiles.Profile
	id                wp.ProcessIdentity
	network           string
	enabled           bool
	routingDisabled   bool
	automaticRevision string
}

func (c *Controller) browserLocalAllowed(network string) bool {
	n := c.network.Load()
	return c.Local.Config().Enabled && n != nil && n.Fingerprint == network && n.Error == "" && time.Since(n.ObservedAt) <= 45*time.Second && len(n.VPN) == 0 && len(n.Conflicts) == 0
}
func (c *Controller) browserScopedLocal(p profiles.Profile, host, network string, port uint16) (string, *localstrategy.LocalStrategyEngine) {
	if !c.hasBaseline(p, network) || !c.browserLocalAllowed(network) {
		return "", nil
	}
	var selected *localstrategy.Profile
	for _, v := range c.Local.Config().User {
		if v.ID == p.LocalStrategyID && v.Enabled {
			copy := v
			selected = &copy
			break
		}
	}
	if selected == nil {
		return "", nil
	}
	if youtubeDomain(host) {
		return selected.ID, c.Local
	}
	raw, _ := json.Marshal([]any{host, port, p.AutoRevision})
	sum := sha256.Sum256(raw)
	key := "br-" + hex.EncodeToString(sum[:12])
	c.browser.mu.Lock()
	defer c.browser.mu.Unlock()
	if engine := c.browser.local[key]; engine != nil {
		return key, engine
	}
	// Bound ephemeral candidates separately; never edit the user's working preset
	// or its revision, and never activate a candidate for another domain.
	if len(c.browser.local) >= 512 {
		return "", nil
	}
	selected.ID = key
	selected.Domains = []string{host}
	selected.IPs = nil
	selected.QuicFallback = false
	selected.Ports = []uint16{port}
	engine := localstrategy.New()
	if engine.Reload(localstrategy.Config{Version: 1, Enabled: true, User: []localstrategy.Profile{*selected}}) != nil {
		return "", nil
	}
	c.browser.local[key] = engine
	return key, engine
}
func (c *Controller) browserLocal(strategy string) *localstrategy.LocalStrategyEngine {
	if e := c.browser.youtube.engine(strategy); e != nil {
		return e
	}
	for _, v := range c.Local.Config().User {
		if v.ID == strategy && v.Enabled {
			return c.Local
		}
	}
	c.browser.mu.Lock()
	defer c.browser.mu.Unlock()
	return c.browser.local[strategy]
}
func browserIdentity(q browserproxy.Request) wp.ProcessIdentity {
	return wp.ProcessIdentity{PID: q.Owner.PID, CreationTime: q.Owner.Birth, Path: q.Owner.Exe}
}
func (c *Controller) browserOpen(ctx context.Context, q browserproxy.Request, plan browserproxy.Plan) (net.Conn, error) {
	return c.openBrowser(ctx, q, plan, true)
}

// browserOpenUnobserved opens like browserOpen but does not feed the DIRECT-timeout cache
// (the background recheck reports its own, application-level verdict).
func (c *Controller) browserOpenUnobserved(ctx context.Context, q browserproxy.Request, plan browserproxy.Plan) (net.Conn, error) {
	return c.openBrowser(ctx, q, plan, false)
}
func (c *Controller) openBrowser(ctx context.Context, q browserproxy.Request, plan browserproxy.Plan, observe bool) (conn net.Conn, err error) {
	if scope, ok := ctx.Value(automaticScopeKey{}).(profilesResult); ok {
		// Automatic recovery has no cached-PAC DIRECT compatibility entitlement.
		if !c.automaticScopeCurrent(scope) {
			return nil, errAutomaticScopeChanged
		}
		defer func() {
			if !c.automaticScopeCurrent(scope) {
				if conn != nil {
					_ = conn.Close()
				}
				conn, err = nil, errAutomaticScopeChanged
			}
		}()
	}
	current, err := c.browserProfile(q.Owner)
	if err != nil {
		return nil, err
	}
	if scoped := c.youtubeLocalBetaOriginScope(q); scoped != plan.YouTubeLocalGeneration {
		return nil, errYouTubeLocalScopeChanged
	}
	if plan.YouTubeLocalGeneration != 0 && (plan.Policy.Action == flowpolicy.Relay || plan.Policy.Action == flowpolicy.RelayRequired || plan.Policy.RelayID != "") {
		c.youtubeLocalBetaOutcome(plan.YouTubeLocalGeneration, "DPI_LOCAL_RELAY_FORBIDDEN")
		return nil, errors.New("YOUTUBE_LOCAL_RELAY_FORBIDDEN")
	}
	if scope, ok := ctx.Value(youtubeBackgroundScopeKey{}).(youtubeBackgroundScope); ok && !c.youtubeBackgroundScopeCurrent(scope, current) {
		scope.cancel()
		return nil, errors.New("background browser policy changed before upstream open")
	}
	if scope, ok := ctx.Value(automaticScopeKey{}).(profilesResult); ok && !c.automaticScopeCurrent(scope) {
		return nil, errAutomaticScopeChanged
	}
	// Cached PAC can still reach this listener after policy removal. Authenticated
	// browser ownership was checked above; bypass the stopped engine/WinDivert.
	if current.routingDisabled {
		return openBrowserDirectCompatibility(ctx, disabledBrowserPlan(plan))
	}
	if current.network != plan.Network || current.enabled != plan.Enabled {
		return nil, errors.New("browser policy changed before upstream open")
	}
	if protectedBrowserDomain(q.Host) && plan.Policy.Action != flowpolicy.RelayRequired {
		return nil, errors.New("protected origin cannot downgrade")
	}
	if current.enabled && q.Port != 53 && c.browserOriginPolicy(q.Host).Kind == "RELAY" && (plan.Policy.Action != flowpolicy.RelayRequired || plan.Policy.Fallback != flowpolicy.Required) {
		return nil, errors.New("known relay-first browser group cannot downgrade")
	}
	d := applyFlowResult(current.profile, wp.Decision{}, plan.Policy, current.network, c.browserLocal(plan.Policy.Strategy))
	d.OriginDomain = q.Host
	d.OriginHintOnly = q.HintOnly
	d.Flow = routing.Flow{OriginDomain: q.Host, OriginService: c.browserOriginPolicy(q.Host).Group, OriginReason: c.browserTrafficReason(current, q, plan), Protocol: "tcp", Source: q.Source, Destination: plan.Destination, PID: q.Owner.PID, ProcessPath: q.Owner.Exe, ApplicationID: q.Owner.Profile, Network: current.network, PinnedPolicy: d.Flow.PinnedPolicy}
	if riotAuto(current.profile) && riotHost(q.Host) {
		d.Flow.OriginService = "riot-client"
	}
	if d.Block {
		return nil, errors.New("browser route blocked")
	}
	if observe && current.enabled && nativeBrowserProfile(current.profile) && (q.Ingress == "PAC_CONNECT" || q.Ingress == "PAC_RECOVERY") && plan.Destination.Addr().Is4() && (c.BrowserResolver != nil || !directOnlyFlow(wp.Tuple{Protocol: "tcp", Destination: plan.Destination})) {
		// A CONNECT already supplies the owner-validated authority. Capturing
		// its service-owned upstream is needed for LOCAL packet transforms,
		// while plain DIRECT/authenticated RELAY can use the existing engine
		// when capture is down. All owner/network/protected-floor checks above
		// still apply. Never retry here after a delegated open has begun.
		if c.nativeBackendReady() || d.Route.Local() {
			return c.openNativePAC(ctx, q, plan, d)
		}
	}
	if d.Route.Local() {
		managedLocal := plan.Policy.Source == youtubeLadderSource || plan.YouTubeLocalGeneration != 0 && plan.Policy.Source == youTubeLocalBetaSource
		if !c.browserLocalAllowed(current.network) && !(managedLocal && c.youtubeLocalAllowed(current.network)) {
			return nil, errors.New("native local strategy unavailable on current network")
		}
		backend, ok := c.Backend.(interface {
			OpenBrowserLocalTCP(context.Context, wp.ProcessIdentity, netip.AddrPort, netip.AddrPort, wp.Decision) (net.Conn, error)
		})
		if !ok {
			return nil, errors.New("native DIRECT+ unavailable")
		}
		return backend.OpenBrowserLocalTCP(ctx, browserIdentity(q), q.Source, plan.Destination, d)
	}
	release := func() {}
	var videoID uint64
	if observe && d.Route.RelayID != "" && isVideo(q) {
		videoID = c.relayUsage().beginVideo(videoPerformance{Port: q.Port, Network: current.network, Profile: current.profile.ID, Domain: q.Host, Destination: plan.Destination.String(), Ingress: q.Ingress, Started: time.Now()})
	}
	opaqueGoogle := otherGoogleWebAdmission(q, plan) && (q.Host == "" || browserAuto(current.profile))
	if observe && d.Route.RelayID != "" && (isVideo(q) || opaqueGoogle) {
		var ok bool
		release, ok = c.relayUsage().acquireVideoContext(ctx, opaqueGoogle)
		if !ok {
			admissionErr := errVideoRelayCapacity
			if ctx.Err() != nil {
				admissionErr = ctx.Err()
			} else if opaqueGoogle {
				admissionErr = errOpaqueGoogleCapacity
			}
			failedAt := time.Now()
			c.relayUsage().videoOpened(videoID, failedAt, failedAt, admissionErr)
			return nil, admissionErr
		}
	}
	admitted := time.Now()
	conn, err = c.Engine.OpenTCP(ctx, d.Flow)
	if videoID != 0 {
		c.relayUsage().videoOpened(videoID, admitted, time.Now(), err)
	}
	err = browserFlowOpenError(err)
	if err != nil {
		release()
	} else if observe && d.Route.RelayID != "" {
		usage := c.relayUsage()
		domain := q.Host
		if domain == "" {
			domain = "<opaque>"
		}
		closeCount := usage.openedTunnel(current.profile.ID, domain, time.Now())
		videoRelease := release
		meter := &relayMeterConn{Conn: conn, videoID: videoID, usage: usage, profile: current.profile.ID, domain: domain, release: func() { videoRelease(); closeCount() }}
		if isVideo(q) || opaqueGoogle {
			idle := browserVideoIdle
			if opaqueGoogle {
				idle = browserOpaqueGoogleIdle
			}
			meter.armIdle(browserRelayFirstIOIdle, idle, opaqueGoogle)
		}
		conn = meter
	}

	if observe {
		c.observeDirectOpen(current, q, plan, err, time.Now())
	}
	if err == nil && observe && plan.Enabled && isVideo(q) && directTimeoutEligible(q, plan) {
		conn = browserproxy.WatchMidstream(conn, browserproxy.DefaultMidstreamTimeout, func() {
			if current.network != "" {
				c.recordBrowserStall(current, q, plan)
			}
		})
	}

	return conn, err
}
func (c *Controller) browserTransform(q browserproxy.Request, plan browserproxy.Plan) bool {
	backend, ok := c.Backend.(interface {
		BrowserTransformApplied(wp.ProcessIdentity, netip.AddrPort, netip.AddrPort) bool
	})
	return ok && backend.BrowserTransformApplied(browserIdentity(q), q.Source, plan.Destination)
}
func (c *Controller) browserPlan(ctx context.Context, q browserproxy.Request) (browserproxy.Plan, error) {
	current, err := c.browserProfile(q.Owner)
	if err != nil {
		return browserproxy.Plan{}, err
	}
	if generation := c.youtubeLocalBetaOriginScope(q); generation != 0 {
		return c.planYouTubeLocalBeta(ctx, current, q, generation)
	}
	if cached, ok := c.browserDNSCachedPlan(q, current); ok {
		return cached, nil
	}
	lookup, stop := context.WithTimeout(ctx, time.Second)
	resolver := c.BrowserResolver
	if resolver == nil {
		resolver = net.DefaultResolver
	}
	addresses, err := resolver.LookupNetIP(lookup, "ip", q.Host)
	stop()
	if err != nil || len(addresses) == 0 {
		base := browserproxy.Plan{Network: current.network, Enabled: current.enabled, Policy: browserDNSPolicy(current)}
		recovered, ok := c.recoverBrowserDNS(ctx, q, current, base)
		if ok {
			return recovered, nil
		}
		// Preserve bounded DoH/TLS/HTTP failure evidence instead of hiding it behind
		// ORIGIN_DNS_FAILED (including negative cooldown hits).
		return recovered, browserproxy.ErrOriginDNS
	}
	// Prefer IPv4 for the existing native DIRECT+ backend. IPv6 relay/direct can
	// use the existing authenticated transport, not an unsupported native bypass.
	sort.SliceStable(addresses, func(i, j int) bool { return addresses[i].Is4() && !addresses[j].Is4() })
	// Cap candidates and remove duplicates; never use arbitrary fallback IPs or
	// relay-side DNS with different policy attribution.
	candidates := []netip.AddrPort{}
	for _, ip := range addresses {
		a := netip.AddrPortFrom(ip.Unmap(), q.Port)
		duplicate := false
		for _, prev := range candidates {
			if a == prev {
				duplicate = true
			}
		}
		if !duplicate {
			candidates = append(candidates, a)
		}
		if len(candidates) == 64 {
			break
		}
	}
	relayCandidates := append([]netip.AddrPort(nil), candidates...)
	// Ordinary route probes keep their existing three-address budget.
	if len(candidates) > 3 && flowpolicy.BrowserRelayGroup(q.Host) == "" && !protectedBrowserDomain(q.Host) {
		candidates = candidates[:3]
	}
	dest := candidates[0]
	tuple := wp.Tuple{Protocol: "tcp", Source: q.Source, Destination: dest}
	result := c.browserFlow(current.profile, current.id, tuple, q.Host, current.network)
	if current.routingDisabled {
		result = flowpolicy.Result{Action: flowpolicy.Direct, Fallback: flowpolicy.FailOpen, Source: "optimization_disabled", Reason: "cached PAC: optimization disabled, ordinary OS DIRECT"}
	} else if !current.enabled && browserGuardedRule(current.profile, q.Host) {
		result = flowpolicy.Result{Action: flowpolicy.Block, Fallback: flowpolicy.Required, Source: "browser_recovery_guard", Reason: "protected origin while profile is not enabled"}
	} else if !current.enabled && !protectedBrowserDomain(q.Host) {
		result = flowpolicy.Result{Action: flowpolicy.Direct, Fallback: flowpolicy.FailOpen, Source: "profile_direct", Reason: "ordinary origin in DIRECT profile"}
	}
	plan := browserproxy.Plan{DirectCandidates: candidates, RelayCandidates: relayCandidates, Network: current.network, Enabled: current.enabled, Policy: result, Destination: dest, Probe: "NOT_PROBED"}
	if riotAuto(current.profile) && riotHost(q.Host) && !protectedBrowserDomain(q.Host) && result.Source != "rule" {
		plan.Policy = flowpolicy.Result{Action: flowpolicy.Direct, Fallback: flowpolicy.FailBlock, Source: "riot_direct_first", Reason: "Launcher: bounded TLS first flight; prefer healthy DNS address before LOCAL/RELAY"}
		plan.DirectCandidates = candidates
		return plan, nil
	}
	if !current.enabled || protectedBrowserDomain(q.Host) || result.Source == "rule" {
		return plan, nil
	}
	if c.browserOriginPolicy(q.Host).Kind == "RELAY" {
		plan.Probe = "KNOWN_RELAY_FIRST"
		return plan, nil
	}
	if c.browserOriginPolicy(q.Host).Kind == "DPI" {
		if plan.Policy.Source == "configured_baseline" && plan.Policy.Action == flowpolicy.DirectPlus {
			return plan, nil
		}
		plan.Policy.Source = youtubeLadderSource
		plan.Policy.Action = flowpolicy.Direct
		plan.Policy.Strategy = ""
		plan.Policy.RelayID = ""
		plan.Policy.Fallback = flowpolicy.FailBlock
		plan.Policy.Reason = "Known DPI group: background verified LOCAL selection; unproven foreground RELAY, no DIRECT stall"
		plan.Probe = "YOUTUBE_LOCAL_LADDER"
		return plan, nil
	}

	// Ordinary AUTO never needs a speculative relay GET to authorize DIRECT.
	// The finite address stepper handles actual failures before any relay open.
	if q.Secure && q.Port == 443 && browserAuto(current.profile) && c.browserOriginPolicy(q.Host).Kind == "" && plan.Policy.Action == flowpolicy.Direct && browserproxy.PublicDNSAddress(dest.Addr()) {
		plan.Probe = "ORDINARY_DIRECT_FIRST"
		return plan, nil
	}
	if dest.Addr().IsPrivate() || dest.Addr().IsLoopback() || dest.Addr().IsLinkLocalUnicast() {
		if c.BrowserResolver == nil {
			plan.Probe = "PRIVATE_ORIGIN_NO_AUTOPROBE"
			return plan, nil
		}
	}
	if current.network == "" {
		plan.Probe = "NETWORK_IDENTITY_UNAVAILABLE"
		return plan, nil
	}
	if _, ipErr := netip.ParseAddr(q.Host); ipErr == nil {
		plan.Probe = "IP_LITERAL_NO_DOMAIN_LEARNING"
		return plan, nil
	}
	key := c.learnKey(current.profile, current.network, "tcp", q.Host, q.Port)
	if q.Secure {
		key.Revision += ":https"
	} else {
		key.Revision += ":http"
	}
	// Confirmed network failures override stale learned DIRECT results, but never
	// explicit rules, protected routes or verified DIRECT+ policy.
	if steered, ok := c.steerTimedOutOrigin(plan, current, q, time.Now()); ok {
		return steered, nil
	}
	if cached, ok := c.browser.learned.Lookup(key, time.Now()); ok && (cached.Confirmed || !cached.RetryAfter.IsZero()) {
		if cached.Destination != "" {
			pinned, e := netip.ParseAddrPort(cached.Destination)
			found := false
			for _, a := range candidates {
				if e == nil && pinned == a {
					found = true
				}
			}
			if !found {
				c.browser.learned.Forget(key)
			} else {
				plan.Destination = pinned
			}
		}
	}
	if cached, ok := c.browser.learned.Lookup(key, time.Now()); ok && (cached.Confirmed || !cached.RetryAfter.IsZero()) {
		if cached.Confirmed || cached.BrowserTrial || cached.Route.Action != flowpolicy.RelayRequired {
			plan.Policy = cached.Route
		}
		plan.Probe = cached.Outcome
		plan.HTTPStatus = cached.HTTPStatus
		return plan, nil
	}
	// One bounded probe sequence per origin/network/revision; waiters never create
	// independent duplicate probes or borrow another domain's result.
	c.browser.mu.Lock()
	pending, exists := c.browser.plans[key]
	if !exists {
		if len(c.browser.plans) >= 32 {
			c.browser.mu.Unlock()
			plan.Probe = "PROBE_CAPACITY_DIRECT_UNVERIFIED"
			return plan, nil
		}
		pending = make(chan struct{})
		c.browser.plans[key] = pending
	}
	c.browser.mu.Unlock()
	if exists {
		select {
		case <-pending:
			if cached, ok := c.browserDNSCachedPlan(q, current); ok {
				return cached, nil
			}
			if v, ok := c.browser.learned.Lookup(key, time.Now()); ok {
				if v.Confirmed || v.BrowserTrial || v.Route.Action != flowpolicy.RelayRequired {
					plan.Policy = v.Route
					if a, e := netip.ParseAddrPort(v.Destination); e == nil {
						plan.Destination = a
					}
				}
				plan.Probe = v.Outcome
				plan.HTTPStatus = v.HTTPStatus
				return plan, nil
			}
			plan.Probe = "PROBE_UNAVAILABLE_DIRECT_UNVERIFIED"
			return plan, nil
		case <-ctx.Done():
			return plan, ctx.Err()
		}
	}
	defer func() { c.browser.mu.Lock(); delete(c.browser.plans, key); close(pending); c.browser.mu.Unlock() }()
	// Bound admission separately from network/probe timeouts. Browser startup
	// has speculative background origins: a brief queue prevents those from
	// starving the foreground origin, without retaining an unbounded request.
	admission := time.NewTimer(500 * time.Millisecond)
	defer admission.Stop()
	select {
	case c.browser.probes <- struct{}{}:
		defer func() { <-c.browser.probes }()
	case <-ctx.Done():
		return plan, ctx.Err()
	case <-admission.C:
		plan.Probe = "PROBE_CAPACITY_DIRECT_UNVERIFIED"
		return plan, nil
	}
	strategy, _ := c.browserScopedLocal(current.profile, q.Host, current.network, q.Port)
	relay := current.profile.RelayID
	if relay == "" {
		relay = "VPS-01"
	}
	ordinary := plan.Policy
	attempt, err := c.browser.learned.Begin(key, strategy, relay, time.Now())
	if err != nil {
		plan.Probe = "PROBE_CACHE_CAPACITY_DIRECT_UNVERIFIED"
		return plan, nil
	}
	for tries := 0; tries < 3; tries++ {
		plan.Policy = attempt.Route

		var status int
		var rx uint64
		var networkError string
		var originTLS bool
		// One budget per route, at most three DNS candidates. Failed addresses get a
		// bounded share rather than consuming every subsequent address's budget.
		routeCtx, routeStop := context.WithTimeout(ctx, 1500*time.Millisecond)
		for i, candidate := range candidates {
			plan.Destination = candidate
			started := time.Now()
			budget := time.Until(started.Add(1500 * time.Millisecond))
			if deadline, ok := routeCtx.Deadline(); ok {
				budget = time.Until(deadline) / time.Duration(len(candidates)-i)
			}
			probe, stop := context.WithTimeout(routeCtx, budget)
			detail := browserproxy.ProbeOriginDetailed(probe, q.Host, q.Port, q.Secure, c.BrowserProbeRoots, func(ctx context.Context) (net.Conn, error) { return c.browserOpenUnobserved(ctx, q, plan) })
			stop()
			status, rx, networkError = detail.Status, detail.Bytes, detail.Failure
			originTLS = detail.Phase == "ORIGIN_TLS"
			applied := plan.Policy.Action == flowpolicy.DirectPlus && c.browserTransform(q, plan)
			outcome := networkError
			if outcome == "" {
				outcome = "ORIGIN_RESPONSE"
			}
			if plan.Policy.Action == flowpolicy.DirectPlus {
				if networkError == "" && !applied {
					networkError = "NO_TRANSFORM"
					outcome = networkError
					rx = 0
					status = 0
				} else if networkError != "" && applied && networkError != "TLS_CERTIFICATE_ERROR" {
					outcome = "TRANSFORM_APPLIED_CONNECTION_FAILED"
				}
			}
			plan.Trials = append(plan.Trials, browserproxy.Trial{Route: string(plan.Policy.Action), Destination: candidate.String(), Phase: detail.Phase, Detail: detail.Detail, ALPN: detail.ALPN, TLSVersion: detail.TLSVersion, Outcome: outcome, HTTPStatus: status, TransformApplied: applied, DurationMS: time.Since(started).Milliseconds()})
			// Never retry a certificate failure on a different address/route. HTTP errors
			// are application responses, not evidence of routing failure.
			if networkError == "" || networkError == "TLS_CERTIFICATE_ERROR" || routeCtx.Err() != nil {
				break
			}
		}
		routeStop()
		after, ownerErr := c.browserProfile(q.Owner)
		if ownerErr != nil || after.network != current.network || after.enabled != current.enabled {
			return plan, errors.New("network/activation changed during origin probe")
		}
		// Invalid/non-TLS/certificate replies can be a wrong system-DNS address.
		// Retry independently resolved candidates through REQUIRED relay, with full
		// hostname certificate and HTTP validation. Never relabel TCP OPEN as success.
		if q.Secure && networkError != "" && (attempt.Stage == 2 || networkError == "TLS_CERTIFICATE_ERROR") {
			recovered, ok := c.recoverBrowserDNS(ctx, q, current, plan)
			if ok {
				return recovered, nil
			}
			plan.DNSRecovery = recovered.DNSRecovery
			// An invalid TLS record is categorically not a Chrome/Go fingerprint
			// difference. Do not offer it as an unverified browser relay candidate.
			if len(plan.Trials) > 0 && plan.Trials[len(plan.Trials)-1].Detail == "INVALID_TLS_RECORD" {
				originTLS = false
			}
		}
		attempt, err = c.browser.learned.Observe(key, flowpolicy.BrowserObservation{Token: attempt.Token, HTTPStatus: status, NetworkError: networkError, OriginTLS: originTLS, Destination: plan.Destination.String(), ResponseBytes: rx, Correlated: true}, strategy, relay, time.Now())
		if err != nil {
			return plan, err
		}
		if attempt.Confirmed || !attempt.RetryAfter.IsZero() {
			plan.Policy = attempt.Route
			if !attempt.Confirmed && !attempt.BrowserTrial && attempt.Route.Action == flowpolicy.RelayRequired && !attempt.RetryAfter.IsZero() {
				plan.Policy = ordinary
			}
			plan.Probe = attempt.Outcome
			plan.HTTPStatus = status
			return plan, nil
		}
	}
	return plan, errors.New("bounded origin probes exhausted")
}
func (c *Controller) handleBrowser(method string, raw json.RawMessage) (result any, err error) {
	c.browser.mu.Lock()
	defer c.browser.mu.Unlock()
	defer func() {
		if method != "browser.status" {
			if err != nil {
				c.browser.lastError = method + ": " + chromeReadinessError(err)
			} else {
				c.browser.lastError = ""
			}
		}
	}()
	if method == "browser.status" {
		if c.browser.server == nil {
			view := browserStatusView{PolicyRefresh: wp.BrowserPolicyRefreshStatus(), Snapshot: browserproxy.Snapshot{ReadyProfiles: []string{}, Failures: map[string]uint64{}, Records: []browserproxy.Record{}}, DirectTimeouts: c.browser.directTimeouts.Stats(), RelayUsage: c.relayUsageLocked(), LastError: c.browser.lastError, ReadinessState: "NOT_PREPARED"}
			if state := c.nativeBrowserReadiness(false); state != "" {
				view.ReadinessState = state
			}
			view.bound()
			return view, nil
		}
		view := browserStatusView{PolicyRefresh: wp.BrowserPolicyRefreshStatus(), Snapshot: c.browser.server.Snapshot(), DirectTimeouts: c.browser.directTimeouts.Stats(), RelayUsage: c.relayUsageLocked()}
		view.LastError = c.browser.lastError
		view.ReadinessState = "PREPARED"
		view.RecoveryAddress = c.browser.recoveryAddress
		view.PolicyReady = c.chromePolicyActive()
		if c.browser.readiness.enforced.Load() {
			view.PolicyReady = view.PolicyReady && c.browser.readiness.laneReady(0) && c.browserPolicyBaseReason() == ""
		}
		if view.PolicyReady && len(view.ReadyProfiles) > 0 {
			view.ReadinessState = "PAC_READY"
		}
		sort.Slice(view.Records, func(i, j int) bool { return view.Records[i].ID > view.Records[j].ID })
		view.SilentActivation = c.silentViewLocked(false, view.Snapshot)
		if len(view.SilentActivation.ConfiguredProfiles) > 0 {
			view.ReadinessState = view.SilentActivation.State
		}
		if state := c.nativeBrowserReadiness(false); state != "" {
			view.ReadinessState = state
		}
		view.bound()
		return view, nil
	}
	var q struct {
		Profile   string `json:"profile_id"`
		Directory string `json:"directory"`
		HealthURL string `json:"health_url"`
		Recovery  string `json:"recovery_address"`
	}
	if err := security.Parse(raw, &q); err != nil {
		return nil, err
	}
	if method == "browser.confirm" {
		if c.browser.server == nil || !c.browser.server.HealthVerified(q.Profile, q.HealthURL) {
			return nil, errors.New("Chrome PAC readiness not observed: check Chrome policy, TCP owner/SID and browser.status failures")
		}
		if !c.chromePolicyActive() {
			return nil, errors.New("Chrome mandatory online PAC not installed for the owner SID")
		}
		for _, p := range c.Profiles.List() {
			if p.ID == q.Profile && p.LocalStrategyID != "" {
				n := c.network.Load()
				if n == nil || n.Error != "" || n.Fingerprint == "" || n.ObservedAt.IsZero() || time.Since(n.ObservedAt) > 45*time.Second || len(n.VPN) > 0 || len(n.Conflicts) > 0 {
					return nil, errors.New("Chrome local strategy requires a fresh VPN/conflict-free network snapshot")
				}
				if p.AutoNetwork != "" && !c.hasBaseline(p, n.Fingerprint) {
					return nil, errors.New("YouTube DIRECT+ baseline is not confirmed on the current network/revision")
				}
			}
		}
		if !c.browser.server.AuthorizeProfile(q.Profile, q.HealthURL) {
			return nil, errors.New("Chrome activation proof expired/changed")
		}
		if c.customPath != "" {
			if err := c.saveBrowserAddress(); err != nil {
				return nil, err
			}
		}
		return map[string]bool{"ready": true}, nil
	}
	found := false
	extra := []string{}
	strict := false
	for _, p := range c.Profiles.List() {
		if p.ID == q.Profile && chromeProfile(p) && p.Trial == nil {
			found = true
			for _, rule := range append(append([]flowpolicy.Rule{}, p.Rules...), p.BrowserRecoveryRules...) {
				if rule.Action != flowpolicy.Direct {
					if len(rule.Domains) == 0 {
						strict = true
					} else {
						extra = append(extra, rule.Domains...)
					}
				}
			}
		}
	}
	if c.BrowserOwnerSID == "" {
		return nil, errors.New("installation owner SID required for Chrome transport")
	}
	c.mu.Lock()
	enabled := c.enabled && c.settings.Automatic
	c.mu.Unlock()
	if !enabled && method != "browser.prepare" {
		return nil, errors.New("Chrome site routing requires enabled optimization and automatic routing")
	}
	if !found || q.Directory == "" || len(q.Directory) > 2048 {
		return nil, errors.New("selected Chrome AUTO profile and persistent user directory required")
	}
	if c.browser.server == nil {
		server, err := browserproxy.Listen(c.ctx, browserproxy.Config{TransportCheck: c.transportCheckSettings, RequireClientHelloReplay: true, Address: c.browser.address, Authorize: c.browserOwner, AuthorizeForwarded: c.browserRecoveryOwner, Plan: c.browserPlan, Open: c.browserOpen, OpenPlan: c.browserOpenPlan, TransformApplied: c.browserTransform, OnStall: c.browserStall, OnDirectAnswered: c.browserDirectAnswered})
		if err != nil {
			return nil, errors.New("CHROME_LISTENER_BIND_FAILED")
		}
		c.browser.server = server
		c.browser.address = server.Address()
		if c.customPath != "" {
			if err := c.saveBrowserAddress(); err != nil {
				c.browser.server = nil
				c.browser.mu.Unlock()
				server.Close()
				c.browser.mu.Lock()
				return nil, err
			}
		}
	}
	healthURL := ""
	if method == "browser.prepare" {
		var err error
		healthURL, err = c.browser.server.Challenge(q.Profile)
		if err != nil {
			return nil, err
		}
	}
	args, err := browserproxy.ChromeArgumentsGuarded(c.browser.server.Address(), q.Directory, extra, strict)
	if err != nil {
		return nil, err
	}
	recovery, err := browserproxy.ChromeRecoveryArguments(c.browser.server.Address(), q.Directory, extra, strict)
	if err != nil {
		return nil, err
	}
	if q.Recovery != "" {
		args, err = browserproxy.ChromeArgumentsWithRecovery(c.browser.server.Address(), q.Directory, extra, strict, q.Recovery)
		if err != nil {
			return nil, err
		}
		recovery = append([]string(nil), args...)
		c.browser.recoveryAddress = q.Recovery
	}
	// Adopt only an exact already-active legacy owner PAC before changing it.
	if len(c.browser.silent.Owned) == 0 && c.chromePolicyActive() {
		c.browser.silent.Owned = []string{edgePolicyValue(c.browser.expectedPAC)}
	}
	if c.browser.readiness.enforced.Load() {
		available, err := browserproxy.AvailabilityPAC(strings.TrimPrefix(args[1], "--proxy-pac-url="))
		if err != nil {
			return nil, err
		}
		args[1] = "--proxy-pac-url=" + available
	}
	c.browser.expectedPAC = strings.TrimPrefix(args[1], "--proxy-pac-url=")
	if c.customPath != "" {
		if err := c.saveBrowserAddress(); err != nil {
			return nil, err
		}
	}
	program, _ := os.Executable()
	return map[string]any{"recovery_program": program, "recovery_settings": browserproxy.RecoverySettings{CheckTarget: c.browser.readiness.target, CheckToken: c.browser.readiness.token, GuardFile: c.browserGuardFile(), Primary: c.browser.server.Address(), Domains: extra, Strict: strict, Profile: q.Profile}, "health_url": healthURL, "arguments": args, "recovery_arguments": recovery, "address": c.browser.server.Address(), "scope": "Chrome launch only; system proxy unchanged", "http3": "HTTP CONNECT uses TCP; QUIC relay transport unchanged", "verification": "origin probe only; authenticated browser page result is not observed"}, nil
}

func (c *Controller) saveBrowserAddress() error {
	if c.customPath == "" {
		return nil
	}
	path := filepath.Join(filepath.Dir(c.customPath), "browser-transport.json")
	raw, _ := json.Marshal(map[string]any{"address": c.browser.address, "ready_profiles": c.browser.server.Snapshot().ReadyProfiles, "expected_pac": c.browser.expectedPAC, "recovery_address": c.browser.recoveryAddress, "silent_activation": c.browser.silent})
	f, err := os.CreateTemp(filepath.Dir(path), ".browser-transport-*")
	if err != nil {
		return err
	}
	name := f.Name()
	defer os.Remove(name)
	f.Chmod(0600)
	if _, err = f.Write(raw); err != nil {
		f.Close()
		return err
	}
	if err = f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	return os.Rename(name, path)
}

// Restore the existing non-secret local port before normal service startup
// starts capture. A service restart must not require changing Chrome's PAC.
func (c *Controller) RestoreBrowserTransport() error {
	if !c.activationNetworkAllowed() {
		return nil
	}
	c.restoreEdgeTransport() // Edge failure is diagnosed separately; never prevents Chrome restore.
	if err := c.publishBrowserGuard(false); err != nil {
		return err
	}
	if c.customPath == "" {
		return nil
	}
	raw, err := os.ReadFile(filepath.Join(filepath.Dir(c.customPath), "browser-transport.json"))
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	var saved struct {
		Address         string             `json:"address"`
		ReadyProfiles   []string           `json:"ready_profiles"`
		ExpectedPAC     string             `json:"expected_pac"`
		RecoveryAddress string             `json:"recovery_address"`
		Silent          browserSilentState `json:"silent_activation"`
	}
	if err = security.Parse(raw, &saved); err != nil {
		return err
	}
	host, p, err := net.SplitHostPort(saved.Address)
	port, pe := strconv.ParseUint(p, 10, 16)
	if err != nil || pe != nil || host != "127.0.0.1" || port == 0 {
		return errors.New("invalid saved Chrome loopback port")
	}
	c.browser.mu.Lock()
	defer c.browser.mu.Unlock()
	c.browser.silent = saved.Silent
	c.browser.address = saved.Address
	c.browser.expectedPAC = saved.ExpectedPAC
	c.browser.recoveryAddress = saved.RecoveryAddress
	server, err := browserproxy.Listen(c.ctx, browserproxy.Config{TransportCheck: c.transportCheckSettings, RequireClientHelloReplay: true, Address: saved.Address, Authorize: c.browserOwner, AuthorizeForwarded: c.browserRecoveryOwner, Plan: c.browserPlan, Open: c.browserOpen, OpenPlan: c.browserOpenPlan, TransformApplied: c.browserTransform, OnStall: c.browserStall, OnDirectAnswered: c.browserDirectAnswered})
	if err != nil {
		return err
	}
	c.browser.server = server
	server.RestoreConfirmed(saved.ReadyProfiles)
	if len(c.browser.silent.Profiles) > 0 {
		return c.reapplySilentLocked(false)
	}
	return nil
}

func (c *Controller) requireChromeActivation() error {
	if err := c.requireEdgeActivation(); err != nil {
		return err
	}
	if c.BrowserOwnerSID == "" {
		return nil
	} // portable/demo controllers have no Windows owner.
	c.browser.mu.Lock()
	defer c.browser.mu.Unlock()
	for _, p := range c.Profiles.List() {
		if edgeSitesProfile(p) {
			continue
		} // Edge has its own PAC readiness.
		if nativeBrowserProfile(p) {
			if err := c.nativeGuardReadyLocked(p); err != nil {
				return err
			}
			if !c.nativeBackendConfigured() {
				return errors.New("NATIVE_CAPTURE_NOT_CONFIGURED")
			}
			continue
		}
		if browserAuto(p) && (c.browser.recoveryAddress == "" || c.browser.server == nil || (!c.browser.server.Confirmed(p.ID) && !c.silentConfiguredLocked(p.ID, false)) || !c.chromePolicyActive()) {
			return errors.New("Chrome AUTO requires verified CONNECT/PAC activation in Applications before Optimize; no capture state changed")
		}
	}
	return nil
}

func (c *Controller) browserRecoveryOwner(ctx context.Context, source, local, original, listener netip.AddrPort) (browserproxy.Owner, error) {
	helper, err := wp.LookupTCPPeer(source, local)
	if err != nil {
		return browserproxy.Owner{}, browserproxy.ErrOwnerLookup
	}
	executable, err := os.Executable()
	if c.BrowserRecoveryExecutable != "" {
		executable = c.BrowserRecoveryExecutable
	}
	if err != nil || !strings.EqualFold(helper.Path, executable) {
		return browserproxy.Owner{}, browserproxy.ErrOwnerProfile
	}
	sid, err := wp.ProcessUserSID(helper)
	if err != nil || sid != c.BrowserOwnerSID {
		return browserproxy.Owner{}, browserproxy.ErrOwnerSID
	}
	return c.browserOwner(ctx, original, listener)
}

func browserGuardedRule(p profiles.Profile, host string) bool {
	for _, rule := range append(append([]flowpolicy.Rule{}, p.Rules...), p.BrowserRecoveryRules...) {
		if rule.Action == flowpolicy.Direct {
			continue
		}
		if len(rule.Domains) == 0 {
			return true
		}
		for _, d := range rule.Domains {
			if host == d || strings.HasSuffix(host, "."+d) {
				return true
			}
		}
	}
	return false
}
