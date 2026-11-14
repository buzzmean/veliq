package clientservice

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"time"

	"github.com/buzzmean/neexitlag/core/browserproxy"
	"github.com/buzzmean/neexitlag/core/flowpolicy"
	"github.com/buzzmean/neexitlag/core/localstrategy"
	"github.com/buzzmean/neexitlag/core/originpolicy"
	wp "github.com/buzzmean/neexitlag/platform/windows"
)

const browserDPILocalSource = "browser_dpi_local_only"
const browserDPILocalTimeout = 900 * time.Millisecond
const browserDPILocalAttempts = 4
const browserDPILocalConcurrentProbes = 4

// Linked into the field build only. The installed service and ordinary builds
// keep the existing AUTO policy.
var BrowserDPILocalField = ""

func browserDPILocalFieldEnabled() bool { return BrowserDPILocalField == "pc24" }

func (c *Controller) browserDPILocalOrigin(host string) bool {
	if !browserDPILocalFieldEnabled() || !browserproxy.ValidPublicDNSName(host) {
		return false
	}
	policy := c.browserOriginPolicy(host)
	return policy.Kind == "DPI" && !policy.Protected && originpolicy.Floor(host).Kind != "RELAY"
}

func (c *Controller) browserDPILocalRequest(cur profilesResult, q browserproxy.Request) bool {
	return cur.enabled && !cur.routingDisabled && (browserAuto(cur.profile) || automaticApplication(cur.profile)) && c.browserDPILocalOrigin(q.Host)
}

func dpiLocalBlocked(reason string) flowpolicy.Result {
	return flowpolicy.Result{Action: flowpolicy.Block, Fallback: flowpolicy.FailBlock, Source: browserDPILocalSource, Reason: reason}
}

func dpiLocalHasAuthority(q browserproxy.Request) bool {
	return !q.HintOnly && !q.OriginAmbiguous && (q.Ingress == "PAC_CONNECT" || q.Ingress == "PAC_RECOVERY")
}

func (c *Controller) dpiLocalEvidenceHost(host, outer string, evidence browserDomainEvidence) string {
	for _, name := range []string{host, outer, evidence.Domain} {
		if c.browserDPILocalOrigin(name) {
			return name
		}
	}
	for _, name := range evidence.Candidates {
		if c.browserDPILocalOrigin(name) {
			return name
		}
	}
	return ""
}

func (c *Controller) dpiLocalRelayEvidence(host, outer string, evidence browserDomainEvidence) bool {
	if c.browserOriginPolicy(host).Kind == "RELAY" || c.browserOriginPolicy(outer).Kind == "RELAY" || c.browserOriginPolicy(evidence.Domain).Kind == "RELAY" {
		return true
	}
	for _, name := range evidence.Candidates {
		if c.browserOriginPolicy(name).Kind == "RELAY" {
			return true
		}
	}
	return false
}

func dpiLocalDoHPolicy(host string, destination netip.AddrPort) (flowpolicy.Result, bool) {
	if !browserDPILocalFieldEnabled() || !browserproxy.KnownDoHEndpoint(host, destination) {
		return flowpolicy.Result{}, false
	}
	// A dedicated encrypted resolver can be used unchanged on the local path.
	// A bare IP or ambiguous raw authority is insufficient for a local bypass.
	if !browserproxy.KnownDoHEndpoint(host, netip.AddrPortFrom(netip.Addr{}, destination.Port())) {
		return dpiLocalBlocked("DPI_LOCAL_DOH_AUTHORITY_UNKNOWN"), true
	}
	return flowpolicy.Result{Action: flowpolicy.Direct, Fallback: flowpolicy.FailBlock,
		Source: browserDPILocalSource, Reason: "DPI_LOCAL_ENCRYPTED_RESOLVER_DIRECT"}, true
}

func dpiLocalDNS(ctx context.Context, host string, lookup func(context.Context, string, string) ([]netip.Addr, error)) (netip.Addr, error) {
	// Reuse the operating system resolver, with a bounded lookup and no
	// alternative relay-side DNS or relay-side verification.
	work, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	addresses, err := lookup(work, "ip4", host)
	if err != nil {
		return netip.Addr{}, err
	}
	for _, addr := range addresses {
		if addr = addr.Unmap(); addr.Is4() && browserproxy.PublicDNSAddress(addr) {
			return addr, nil
		}
	}
	return netip.Addr{}, browserproxy.ErrOriginDNS
}

func (c *Controller) planDPILocal(ctx context.Context, current profilesResult, q browserproxy.Request) (browserproxy.Plan, error) {
	plan := browserproxy.Plan{Enabled: current.enabled, Network: current.network, Probe: "DPI_LOCAL_ONLY",
		Policy: flowpolicy.Result{Action: flowpolicy.Direct, Fallback: flowpolicy.FailBlock, Source: browserDPILocalSource, Reason: "DPI_LOCAL_SELECTION_PENDING"}}
	if !dpiLocalHasAuthority(q) || q.Port != 443 || !q.Secure {
		plan.Policy = dpiLocalBlocked("DPI_LOCAL_CONNECT_AUTHORITY_REQUIRED")
		return plan, nil
	}
	resolver := c.BrowserResolver
	if resolver == nil {
		resolver = net.DefaultResolver
	}
	address, err := dpiLocalDNS(ctx, q.Host, resolver.LookupNetIP)
	if err != nil {
		plan.Policy = dpiLocalBlocked("DPI_LOCAL_DNS_FAILED")
		c.browser.youtube.startOriginDecision(q, cdnDecisionEvent{Phase: "DENIED", Stage: "BLOCK", Reason: plan.Policy.Reason})
		return plan, browserproxy.ErrOriginDNS
	}
	plan.Destination = netip.AddrPortFrom(address, q.Port)
	tuple := wp.Tuple{Protocol: "tcp", Source: q.Source, Destination: plan.Destination}
	policy := c.browserFlow(current.profile, current.id, tuple, q.Host, current.network)
	if policy.Action == flowpolicy.Block || policy.Source == "configured_baseline" {
		plan.Policy = policy
	}
	return plan, nil
}

type dpiLocalCandidate struct {
	id     string
	reason string
}

// Caller holds r.mu. A remembered proof is tried before the compiled prior,
// and every candidate is checked against the exact endpoint's active denial.
func (r *youtubeRuntime) dpiLocalCandidatesLocked(key youtubeKey, endpoint cdnEndpoint, baseline bool, now time.Time) []dpiLocalCandidate {
	v := r.cache[key]
	candidates := make([]dpiLocalCandidate, 0, browserDPILocalAttempts)
	seen := make(map[string]bool, browserDPILocalAttempts)
	add := func(id, reason string) {
		if id == "" || seen[id] || len(candidates) == browserDPILocalAttempts ||
			id == "baseline" && !baseline || r.endpointBlockedLocked(key, id, endpoint, now) {
			return
		}
		seen[id] = true
		candidates = append(candidates, dpiLocalCandidate{id, reason})
	}
	if v.Confirmed && v.Stage == "LOCAL" && now.Before(v.Until) {
		add(v.Strategy, "LEARNED_LOCAL")
	}
	if youtubeCDN(key) {
		last := time.Time{}
		recent := ""
		for _, id := range r.order {
			proof := youtubeQualification{key.Network, key.Profile, id, key.HintOnly}
			if !now.Before(r.peerProofs[proof]) || now.Before(r.peerDenied[youtubeScoreKey{key, id}]) ||
				r.endpointBlockedLocked(key, id, endpoint, now) {
				continue
			}
			if recent == "" || r.peerSeen[proof].After(last) {
				last, recent = r.peerSeen[proof], id
			}
		}
		add(recent, "RECENT_LOCAL_PROOF")
	}
	if baseline {
		add("baseline", "CONFIGURED_BASELINE")
	}
	if r.qualified(key, v.Qualified, now) {
		add(v.Qualified, "QUALIFIED_LOCAL")
	}
	// A bounded sample of the current catalog, with a different local recipe
	// available even when the first catalog transform and its peers failed.
	if len(r.order) > 0 {
		add(r.order[0], "COLD_LOCAL_PROBE")
	}
	add("split1", "COLD_LOCAL_PROBE")
	add("fake5x2-disorder", "COLD_LOCAL_PROBE")
	for _, id := range r.order {
		if len(candidates) == browserDPILocalAttempts {
			break
		}
		add(id, "COLD_LOCAL_PROBE")
	}
	return candidates
}

func (c *Controller) openDPILocal(ctx context.Context, cur profilesResult, q browserproxy.Request, p browserproxy.Plan, open func(context.Context, browserproxy.Request, browserproxy.Plan) (net.Conn, error)) (net.Conn, browserproxy.Plan, error) {
	key := youtubeScope(cur, q)
	endpoint := cdnEndpoint{q.Host, p.Destination.String()}
	r := c.browser.youtube
	if c.catalog != nil {
		r.setPlans(c.catalog.snapshot().Plans)
	}
	now := time.Now()
	r.mu.Lock()
	v, found := r.cache[key]
	candidates := r.dpiLocalCandidatesLocked(key, endpoint, p.Policy.Source == "configured_baseline", now)
	evidence := cdnSelectionEvidence{CheckedAt: now.UTC(), Scope: key, Cache: cdnCacheSnapshot(v, found)}
	if found && v.Strategy != "" {
		check := r.endpointCheckLocked(key, v.Strategy, endpoint, now)
		evidence.Endpoint = &check
	}
	r.mu.Unlock()

	ref := &youtubePlanRef{}
	p.FirstFlightManaged = true
	p.DirectCandidates, p.RelayCandidates, p.DirectDeadline = nil, nil, time.Time{}
	p.Probe = "DPI_LOCAL_ONLY"
	decision := cdnDecisionEvent{Destination: endpoint.Address, Selection: &evidence, Stage: "LOCAL", Admission: "ADMITTED_LOCAL_ONLY"}
	block := func(event cdnDecisionEvent, reason string) (net.Conn, browserproxy.Plan, error) {
		blocked := p
		blocked.Policy = dpiLocalBlocked(reason)
		ref.set(blocked, nil)
		event.Stage, event.Reason, event.Admission, event.Phase = "BLOCK", reason, reason, "DENIED"
		if event.ConnectionID == 0 {
			r.startOriginDecision(q, event)
		} else {
			event.Selection = nil
			r.mu.Lock()
			r.addCDNDecisionLocked(event)
			r.mu.Unlock()
		}
		return nil, blocked, errors.New(reason)
	}
	if p.Policy.Action == flowpolicy.Block {
		return block(decision, p.Policy.Reason)
	}
	if !dpiLocalHasAuthority(q) {
		return block(decision, "DPI_LOCAL_CONNECT_AUTHORITY_REQUIRED")
	}
	if !p.Enabled || !q.Secure || q.Port != 443 || !endpoint.valid() {
		return block(decision, "DPI_LOCAL_UNSUPPORTED_ENDPOINT")
	}
	if explicit, ok := flowpolicy.Evaluate(cur.profile.Rules, flowpolicy.Input{Protocol: "tcp", Destination: p.Destination, Domain: q.Host, Network: cur.network}); ok {
		switch explicit.Action {
		case flowpolicy.Block:
			return block(decision, "DPI_LOCAL_EXPLICIT_BLOCK_RULE")
		case flowpolicy.Relay, flowpolicy.RelayRequired:
			return block(decision, "DPI_LOCAL_EXPLICIT_RELAY_RULE")
		case flowpolicy.Direct, flowpolicy.DirectPlus:
			p.Policy = explicit
			p.Policy.Fallback, p.Policy.RelayID = flowpolicy.FailBlock, ""
			conn, err := open(ctx, q, p)
			return conn, p, err
		}
	}
	if !c.youtubeLocalAllowed(cur.network) {
		return block(decision, "DPI_LOCAL_NETWORK_GUARD")
	}
	if len(candidates) == 0 {
		return block(decision, "DPI_LOCAL_ALL_CANDIDATES_DENIED")
	}

	cur = c.captureAutomaticScope(cur)
	scopeCurrent := func() bool { return c.youtubeLocalAllowed(cur.network) && c.automaticScopeCurrent(cur) }
	open = c.automaticScopedOpen(cur, open)
	decision.Strategy, decision.Reason = candidates[0].id, candidates[0].reason
	decision = r.startOriginDecision(q, decision)
	service := c.browserOriginPolicy(q.Host).Group
	var step func(context.Context, int, string) (net.Conn, browserproxy.Plan, error)
	step = func(work context.Context, index int, reason string) (net.Conn, browserproxy.Plan, error) {
		for ; index < len(candidates); index++ {
			if work.Err() != nil || !scopeCurrent() {
				return block(decision, "DPI_LOCAL_SCOPE_OR_BUDGET_EXPIRED")
			}
			candidate := candidates[index]
			r.mu.Lock()
			denied := r.endpointBlockedLocked(key, candidate.id, endpoint, time.Now())
			r.mu.Unlock()
			if denied {
				continue
			}
			var releaseProbe func()
			if candidate.reason != "LEARNED_LOCAL" && candidate.reason != "RECENT_LOCAL_PROOF" {
				select {
				case c.browser.dpiLocalProbes <- struct{}{}:
					releaseProbe = func() { <-c.browser.dpiLocalProbes }
				default:
					return block(decision, "DPI_LOCAL_PROBE_CAPACITY")
				}
			}
			actual := p
			id, _ := c.youtubeEngine(cur, q, actual, candidate.id)
			if id == "" {
				if releaseProbe != nil {
					releaseProbe()
				}
				return block(decision, "DPI_LOCAL_STRATEGY_UNAVAILABLE")
			}
			actual.Policy = flowpolicy.Result{Action: flowpolicy.DirectPlus, Strategy: id, Fallback: flowpolicy.FailBlock, Source: youtubeLadderSource, Reason: "DPI_LOCAL_ONLY " + candidate.reason}
			started := time.Now()
			attempt, cancel := context.WithTimeout(work, 550*time.Millisecond)
			conn, err := open(attempt, q, actual)
			cancel()
			if !scopeCurrent() {
				if conn != nil {
					conn.Close()
				}
				if releaseProbe != nil {
					releaseProbe()
				}
				return block(decision, "DPI_LOCAL_SCOPE_OR_BUDGET_EXPIRED")
			}
			event := decision
			event.Phase, event.Strategy, event.Reason, event.Selection = "OPENED", candidate.id, reason, nil
			label := service + ":LOCAL:" + candidate.id
			r.mu.Lock()
			record := r.addYoutubeRecordLocked(youtubeRecord{OpenMS: milliseconds(time.Since(started)), Service: service,
				Active: err == nil, Profile: cur.profile.ID, Domain: q.Host, Destination: endpoint.Address,
				Stage: "LOCAL", Strategy: candidate.id, Reason: "OPEN", Updated: time.Now()})
			if _, exists := r.stats[label]; !exists && len(r.stats) >= 128 {
				label = "other:LOCAL:CATALOG_OVERFLOW"
			}
			stats := r.stats[label]
			stats.Service, stats.Stage, stats.Strategy = service, "LOCAL", candidate.id
			stats.Connections++
			if err != nil {
				if releaseProbe != nil {
					releaseProbe()
				}
				event.Phase, event.Reason = "OPEN_FAILED", "DPI_LOCAL_OPEN_FAILED"
				rec := r.records[record]
				rec.Reason = event.Reason
				r.records[record] = rec
				stats.Failures++
			}
			r.stats[label] = stats
			event.RecordID = record
			r.addCDNDecisionLocked(event)
			r.mu.Unlock()

			if err != nil {
				if conn != nil {
					conn.Close()
				}
				if work.Err() != nil {
					return block(decision, "DPI_LOCAL_SCOPE_OR_BUDGET_EXPIRED")
				}
				r.endpointFailed(key, candidate.id, endpoint, event.Reason, time.Now())
				reason = event.Reason
				continue
			}

			observer := &youtubeMeter{Conn: conn, r: r, id: record, label: label, key: key, stage: "LOCAL", strategy: candidate.id,
				started: time.Now(), host: q.Host, destination: endpoint.Address, recoveryCurrent: scopeCurrent,
				inspection:         func() *localstrategy.Inspection { return c.localPacketInspection(q, actual) },
				transform:          func() bool { return c.browserTransform(q, actual) },
				rememberLocalProof: youtubeCDN(key),
				releaseProbe:       releaseProbe,
			}
			onFailure := func(failure string) {
				observer.failure(failure)
				failed := event
				failed.Phase, failed.Reason = "FAILED", failure
				r.mu.Lock()
				r.addCDNDecisionLocked(failed)
				r.mu.Unlock()
			}
			monitored := browserproxy.WatchMidstream(observer, 6*time.Second, func() { onFailure("MIDSTREAM_STALL_NEW_CONNECTION_REQUIRED") })
			watched := browserproxy.WatchRelayOrigin(monitored, browserproxy.OriginConfig{
				Context: c.ctx, Health: browserproxy.NewOriginHealth(), Initial: actual.Destination,
				Silence: browserDPILocalTimeout, ScopeCurrent: scopeCurrent, OnFailure: onFailure,
				NextFlow: func(next context.Context, failure string) (net.Conn, error) {
					conn, _, err := step(next, index+1, failure)
					return conn, err
				},
			})
			ref.set(actual, watched)
			return watched, actual, nil
		}
		return block(decision, "DPI_LOCAL_CANDIDATES_EXHAUSTED")
	}
	conn, actual, err := step(ctx, 0, "")
	if err != nil {
		return nil, actual, err
	}
	return &youtubePlanConn{Conn: conn, ref: ref}, actual, nil
}
