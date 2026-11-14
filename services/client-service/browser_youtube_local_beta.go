package clientservice

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strings"
	"time"

	"github.com/buzzmean/neexitlag/core/browserproxy"
	"github.com/buzzmean/neexitlag/core/flowpolicy"
	"github.com/buzzmean/neexitlag/core/localstrategy"
	"github.com/buzzmean/neexitlag/core/originpolicy"
	wp "github.com/buzzmean/neexitlag/platform/windows"
)

const youTubeLocalBetaSource = "youtube_local_only"
const youTubeLocalBetaAttempts = 4
const youTubeLocalDirectCandidate = "plain-direct"

var errYouTubeLocalScopeChanged = errors.New("DPI_LOCAL_SCOPE_CHANGED")

func youtubeLocalBetaOrigin(host string) bool {
	return browserproxy.ValidPublicDNSName(host) && originpolicy.Floor(host).Group == "youtube-media"
}

func (c *Controller) youtubeLocalBetaOriginScope(q browserproxy.Request) uint64 {
	if !youtubeLocalBetaOrigin(q.Host) {
		return 0
	}
	return c.youtubeLocalBetaScope(q)
}

func (c *Controller) youtubeLocalBetaNativeScope(q browserproxy.Request, cur profilesResult, dest netip.AddrPort, outer string) uint64 {
	if q.Host != "" {
		return c.youtubeLocalBetaOriginScope(q)
	}
	generation := c.youtubeLocalBetaScope(q)
	if generation == 0 {
		return 0
	}
	evidence := c.browser.domains.profileEvidence(cur.network, cur.profile.ID, dest.Addr(), outer, time.Now())
	// These are restrictive hints, never authorization for a LOCAL transform.
	// Shared or encrypted authorities without specific evidence stay outside beta.
	if evidence.YoutubeOnly && len(evidence.Candidates) != 0 {
		for _, host := range evidence.Candidates {
			if !youtubeLocalBetaOrigin(host) {
				return 0
			}
		}
		return generation
	}
	return 0
}

func youtubeLocalBetaBlock(reason string) flowpolicy.Result {
	return flowpolicy.Result{Action: flowpolicy.Block, Fallback: flowpolicy.FailBlock, Source: youTubeLocalBetaSource, Reason: reason}
}

func youtubeLocalBetaAuthority(q browserproxy.Request) bool {
	return !q.HintOnly && !q.OriginAmbiguous && (q.Ingress == "PAC_CONNECT" || q.Ingress == "PAC_RECOVERY")
}

func (c *Controller) planYouTubeLocalBeta(ctx context.Context, cur profilesResult, q browserproxy.Request, generation uint64) (browserproxy.Plan, error) {
	p := browserproxy.Plan{Enabled: cur.enabled, Network: cur.network, FirstFlightManaged: true,
		YouTubeLocalGeneration: generation, Probe: "YOUTUBE_LOCAL_ONLY",
		Policy: flowpolicy.Result{Action: flowpolicy.Direct, Fallback: flowpolicy.FailBlock, Source: youTubeLocalBetaSource}}
	deny := func(reason string) (browserproxy.Plan, error) {
		c.youtubeLocalBetaOutcome(generation, reason)
		p.Policy = youtubeLocalBetaBlock(reason)
		return p, errors.New(reason)
	}
	if !cur.enabled || cur.routingDisabled || !c.nativeBackendReady() {
		return deny("DPI_LOCAL_CHROME_CAPTURE_NOT_READY")
	}
	if !youtubeLocalBetaAuthority(q) || q.Port != 443 || !q.Secure {
		return deny("DPI_LOCAL_CONNECT_AUTHORITY_REQUIRED")
	}
	if !c.youtubeLocalAllowed(cur.network) {
		return deny("DPI_LOCAL_NETWORK_GUARD")
	}
	if policy := c.browserOriginPolicy(q.Host); policy.Protected || policy.Kind == "RELAY" {
		return deny("DPI_LOCAL_ORIGIN_POLICY_BLOCKED")
	}
	if !c.youtubeLocalBetaCurrent(generation) {
		return deny(errYouTubeLocalScopeChanged.Error())
	}
	resolver := c.BrowserResolver
	if resolver == nil {
		resolver = net.DefaultResolver
	}
	work, stop := context.WithTimeout(ctx, time.Second)
	defer stop()
	c.youtubeLocalBetaCount(generation, 0, 1)
	addresses, err := resolver.LookupNetIP(work, "ip4", q.Host)
	if err != nil {
		return deny("DPI_LOCAL_DNS_FAILED")
	}
	if !c.youtubeLocalBetaCurrent(generation) || !c.youtubeLocalAllowed(cur.network) {
		return deny(errYouTubeLocalScopeChanged.Error())
	}
	for _, address := range addresses {
		if address = address.Unmap(); address.Is4() && browserproxy.PublicDNSAddress(address) {
			p.Destination = netip.AddrPortFrom(address, q.Port)
			t := wp.Tuple{Protocol: "tcp", Source: q.Source, Destination: p.Destination}
			policy := c.browserFlow(cur.profile, cur.id, t, q.Host, cur.network)
			if policy.Action == flowpolicy.Block || policy.Source == "configured_baseline" {
				p.Policy = policy
			}
			return p, nil
		}
	}
	return deny("DPI_LOCAL_DNS_NO_PUBLIC_IPV4")
}

type youtubeLocalCandidate struct {
	id, reason string
}

// Caller holds r.mu. Beta observations occupy their own scope to leave ordinary
// routing decisions and endpoint failures unchanged when the mode is disabled.
func (r *youtubeRuntime) youtubeLocalBetaCandidatesLocked(key, ordinary youtubeKey, endpoint cdnEndpoint, baseline bool, now time.Time) []youtubeLocalCandidate {
	candidates := make([]youtubeLocalCandidate, 0, youTubeLocalBetaAttempts)
	add := func(id, reason string) {
		if id == "" || id == "baseline" && !baseline || len(candidates) == youTubeLocalBetaAttempts ||
			r.endpointBlockedLocked(key, id, endpoint, now) || r.endpointBlockedLocked(ordinary, id, endpoint, now) {
			return
		}
		for _, candidate := range candidates {
			if candidate.id == id {
				return
			}
		}
		candidates = append(candidates, youtubeLocalCandidate{id, reason})
	}
	known := r.cache[key]
	prior := r.cache[ordinary]
	if !known.Confirmed || !now.Before(known.Until) || prior.Confirmed && now.Before(prior.Until) && prior.Until.After(known.Until) {
		known, prior = prior, known
	}
	for _, entry := range []youtubeLearn{known, prior} {
		if entry.Confirmed && now.Before(entry.Until) {
			switch entry.Stage {
			case "LOCAL":
				add(entry.Strategy, "LEARNED_LOCAL")
			case "DIRECT":
				add(youTubeLocalDirectCandidate, "LEARNED_DIRECT")
			}
		}
	}
	if youtubeCDN(ordinary) {
		recent, latest := "", time.Time{}
		for _, scope := range []youtubeKey{key, ordinary} {
			for _, id := range r.order {
				proof := youtubeQualification{scope.Network, scope.Profile, id, scope.HintOnly}
				if !now.Before(r.peerProofs[proof]) || now.Before(r.peerDenied[youtubeScoreKey{scope, id}]) ||
					r.endpointBlockedLocked(key, id, endpoint, now) || r.endpointBlockedLocked(ordinary, id, endpoint, now) {
					continue
				}
				if recent == "" || r.peerSeen[proof].After(latest) {
					recent, latest = id, r.peerSeen[proof]
				}
			}
		}
		add(recent, "RECENT_LOCAL_PROOF")
	}
	if baseline {
		add("baseline", "CONFIGURED_BASELINE")
	}
	if r.qualified(ordinary, r.cache[ordinary].Qualified, now) {
		add(r.cache[ordinary].Qualified, "QUALIFIED_LOCAL")
	}
	if len(r.order) > 0 && len(candidates) < youTubeLocalBetaAttempts-1 {
		add(r.order[0], "COLD_LOCAL_PROBE")
	}
	for _, id := range append([]string{"split1", "fake5x2-disorder"}, r.order...) {
		if len(candidates) >= youTubeLocalBetaAttempts-1 {
			break
		}
		add(id, "COLD_LOCAL_PROBE")
	}
	add(youTubeLocalDirectCandidate, "PLAIN_DIRECT_PROBE")
	return candidates
}

func (c *Controller) openYouTubeLocalBeta(ctx context.Context, cur profilesResult, q browserproxy.Request, p browserproxy.Plan, open func(context.Context, browserproxy.Request, browserproxy.Plan) (net.Conn, error)) (net.Conn, browserproxy.Plan, error) {
	gen := p.YouTubeLocalGeneration
	r := c.browser.youtube
	ordinary := youtubeScope(cur, q)
	key := ordinary
	key.Profile = "youtube-local-only:" + ordinary.Profile
	endpoint := cdnEndpoint{q.Host, p.Destination.String()}
	ref := &youtubePlanRef{}
	decision := cdnDecisionEvent{Host: q.Host, Ingress: q.Ingress, HintOnly: q.HintOnly, Destination: endpoint.Address}
	deny := func(reason string) (net.Conn, browserproxy.Plan, error) {
		blocked := p
		blocked.Policy = youtubeLocalBetaBlock(reason)
		ref.set(blocked, nil)
		event := decision
		event.Stage, event.Phase, event.Reason, event.Admission, event.Selection = "BLOCK", "DENIED", reason, reason, nil
		r.mu.Lock()
		r.addCDNDecisionLocked(event)
		r.mu.Unlock()
		c.youtubeLocalBetaOutcome(gen, reason)
		return nil, blocked, errors.New(reason)
	}
	if p.Policy.Action == flowpolicy.Block {
		return deny("DPI_LOCAL_EXPLICIT_BLOCK_RULE")
	}
	if !p.Enabled || !youtubeLocalBetaAuthority(q) || !q.Secure || q.Port != 443 || !endpoint.valid() {
		return deny("DPI_LOCAL_CONNECT_AUTHORITY_REQUIRED")
	}
	if cur.network != p.Network || !cur.enabled || cur.routingDisabled || !c.youtubeLocalAllowed(cur.network) {
		return deny("DPI_LOCAL_NETWORK_GUARD")
	}
	revision := c.policyRevision(cur.profile)
	scopeCurrent := func() bool {
		return c.youtubeLocalBetaCurrent(gen) && c.youtubeLocalAllowed(cur.network)
	}
	if !scopeCurrent() {
		return deny(errYouTubeLocalScopeChanged.Error())
	}
	if policy := c.browserOriginPolicy(q.Host); policy.Protected || policy.Kind == "RELAY" {
		return deny("DPI_LOCAL_ORIGIN_POLICY_BLOCKED")
	}
	if explicit, ok := flowpolicy.Evaluate(cur.profile.Rules, flowpolicy.Input{Protocol: "tcp", Destination: p.Destination, Domain: q.Host, Network: cur.network}); ok {
		switch explicit.Action {
		case flowpolicy.Block:
			return deny("DPI_LOCAL_EXPLICIT_BLOCK_RULE")
		case flowpolicy.Relay, flowpolicy.RelayRequired:
			return deny("DPI_LOCAL_EXPLICIT_RELAY_RULE")
		case flowpolicy.Direct, flowpolicy.DirectPlus:
			p.Policy = explicit
			p.Policy.Fallback, p.Policy.RelayID = flowpolicy.FailBlock, ""
			conn, err := open(ctx, q, p)
			if err != nil || conn == nil {
				if conn != nil {
					conn.Close()
				}
				return deny("DPI_LOCAL_OPEN_FAILED")
			}
			if !scopeCurrent() {
				conn.Close()
				return deny(errYouTubeLocalScopeChanged.Error())
			}
			if explicit.Action == flowpolicy.DirectPlus && isVideo(q) {
				conn = &youtubeLocalBetaCountedConn{Conn: conn, count: func(rx uint64) { c.youtubeLocalBetaCount(gen, rx, 0) }}
			}
			return conn, p, nil
		}
	}

	if c.catalog != nil {
		r.setPlans(c.catalog.snapshot().Plans)
	}
	now := time.Now()
	r.mu.Lock()
	candidates := r.youtubeLocalBetaCandidatesLocked(key, ordinary, endpoint, p.Policy.Source == "configured_baseline", now)
	v, found := r.cache[key]
	if !found {
		v, found = r.cache[ordinary]
	}
	decision.Selection = &cdnSelectionEvidence{CheckedAt: now.UTC(), Scope: ordinary, Cache: cdnCacheSnapshot(v, found)}
	r.mu.Unlock()
	if len(candidates) == 0 {
		return deny("DPI_LOCAL_ALL_CANDIDATES_DENIED")
	}

	var attempt func(context.Context, int) (net.Conn, browserproxy.Plan, error)
	attempt = func(work context.Context, index int) (net.Conn, browserproxy.Plan, error) {
		for ; index < len(candidates); index++ {
			if work.Err() != nil || !scopeCurrent() || c.policyRevision(cur.profile) != revision {
				return deny(errYouTubeLocalScopeChanged.Error())
			}
			candidate := candidates[index]
			r.mu.Lock()
			blocked := r.endpointBlockedLocked(key, candidate.id, endpoint, time.Now()) || r.endpointBlockedLocked(ordinary, candidate.id, endpoint, time.Now())
			r.mu.Unlock()
			if blocked {
				continue
			}
			var release func()
			if !strings.HasPrefix(candidate.reason, "LEARNED_") && candidate.reason != "RECENT_LOCAL_PROOF" {
				select {
				case c.browser.youtubeLocalBetaProbes <- struct{}{}:
					release = func() { <-c.browser.youtubeLocalBetaProbes }
				default:
					return deny("DPI_LOCAL_PROBE_CAPACITY")
				}
			}
			actual, stage := p, "DIRECT"
			actual.Policy = flowpolicy.Result{Action: flowpolicy.Direct, Fallback: flowpolicy.FailBlock, Source: youTubeLocalBetaSource, Reason: candidate.reason}
			if candidate.id != youTubeLocalDirectCandidate {
				id, _ := c.youtubeEngine(cur, q, actual, candidate.id)
				if id == "" {
					if release != nil {
						release()
					}
					continue
				}
				stage = "LOCAL"
				actual.Policy.Action, actual.Policy.Strategy = flowpolicy.DirectPlus, id
			}
			event := decision
			event.Stage, event.Phase, event.Strategy, event.Reason, event.Admission = stage, "SELECTED", candidate.id, candidate.reason, "ADMITTED_LOCAL_ONLY"
			r.mu.Lock()
			event.ConnectionID = r.addCDNDecisionLocked(event)
			decision.ConnectionID = event.ConnectionID
			r.mu.Unlock()
			event.Selection = nil
			start := time.Now()
			openCtx, stop := context.WithTimeout(work, 550*time.Millisecond)
			conn, err := open(openCtx, q, actual)
			stop()
			if err != nil || conn == nil || !scopeCurrent() || c.policyRevision(cur.profile) != revision {
				if conn != nil {
					conn.Close()
				}
				if release != nil {
					release()
				}
				if !scopeCurrent() || c.policyRevision(cur.profile) != revision {
					return deny(errYouTubeLocalScopeChanged.Error())
				}
				event.Phase, event.Reason = "OPEN_FAILED", "DPI_LOCAL_OPEN_FAILED"
				r.mu.Lock()
				r.addCDNDecisionLocked(event)
				r.mu.Unlock()
				r.noteEndpointFailure(key, candidate.id, endpoint, event.Reason, time.Now())
				continue
			}
			label := "youtube-media:" + stage + ":" + candidate.id
			r.mu.Lock()
			record := r.addYoutubeRecordLocked(youtubeRecord{OpenMS: milliseconds(time.Since(start)), Service: "youtube-media",
				Active: true, Profile: cur.profile.ID, Domain: q.Host, Destination: endpoint.Address,
				Stage: stage, Strategy: candidate.id, Reason: "OPEN", Updated: time.Now()})
			if _, exists := r.stats[label]; !exists && len(r.stats) >= 128 {
				label = "other:" + stage + ":CATALOG_OVERFLOW"
			}
			stats := r.stats[label]
			stats.Service, stats.Stage, stats.Strategy = "youtube-media", stage, candidate.id
			stats.Connections++
			r.stats[label] = stats
			event.Phase, event.RecordID = "OPENED", record
			r.addCDNDecisionLocked(event)
			r.mu.Unlock()

			observer := &youtubeMeter{Conn: conn, r: r, id: record, label: label, key: key, stage: stage, strategy: candidate.id,
				started: time.Now(), host: q.Host, destination: endpoint.Address, recoveryCurrent: scopeCurrent,
				inspection: func() *localstrategy.Inspection { return c.localPacketInspection(q, actual) },
				transform:  func() bool { return c.browserTransform(q, actual) },
				betaLocal:  true, releaseProbe: release}
			if stage == "LOCAL" && isVideo(q) {
				observer.betaBytes = func(rx uint64) { c.youtubeLocalBetaCount(gen, rx, 0) }
			}
			observer.betaConfirmed = func() { c.youtubeLocalBetaOutcome(gen, "OPENED_LOCAL") }
			failed := func(reason string) {
				observer.failure(reason)
				c.youtubeLocalBetaOutcome(gen, "DPI_LOCAL_"+reason)
				failure := event
				failure.Phase, failure.Reason = "FAILED", reason
				r.mu.Lock()
				r.addCDNDecisionLocked(failure)
				r.mu.Unlock()
			}
			monitored := browserproxy.WatchMidstream(observer, 6*time.Second, func() { failed("MIDSTREAM_STALL_NEW_CONNECTION_REQUIRED") })
			watched := browserproxy.WatchRelayOrigin(monitored, browserproxy.OriginConfig{
				Context: c.ctx, Health: browserproxy.NewOriginHealth(), Initial: actual.Destination, Silence: browserproxy.OriginSilenceTimeout,
				ScopeCurrent: scopeCurrent, OnFailure: failed,
				NextFlow: func(next context.Context, _ string) (net.Conn, error) {
					conn, _, err := attempt(next, index+1)
					return conn, err
				},
			})
			ref.set(actual, watched)
			return watched, actual, nil
		}
		return deny("DPI_LOCAL_NO_WORKING_STRATEGY")
	}
	conn, actual, err := attempt(ctx, 0)
	if err != nil {
		return nil, actual, err
	}
	return &youtubePlanConn{Conn: conn, ref: ref}, actual, nil
}

type youtubeLocalBetaCountedConn struct {
	net.Conn
	count func(uint64)
}

func (c *youtubeLocalBetaCountedConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n > 0 {
		c.count(uint64(n))
	}
	return n, err
}

func (c *youtubeLocalBetaCountedConn) CloseWrite() error {
	if upstream, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return upstream.CloseWrite()
	}
	return nil
}
