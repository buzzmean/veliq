package clientservice

import (
	"context"
	"errors"
	"net"
	"time"

	"github.com/buzzmean/veliq/core/browserproxy"
	"github.com/buzzmean/veliq/core/flowpolicy"
	"github.com/buzzmean/veliq/core/localstrategy"
)

var errBrowserAutoLocalBusy = errors.New("AUTO_LOCAL_PROBE_CAPACITY")

// Only the browser's authenticated CONNECT carries a reliable authority.
// Raw TLS, encrypted DNS and required relay policies keep their own rules.
func (c *Controller) browserAutoLocalEligible(cur profilesResult, q browserproxy.Request, p browserproxy.Plan) bool {
	if !cur.enabled || cur.routingDisabled || !browserAuto(cur.profile) ||
		!youtubeLocalBetaAuthority(q) || !localBrowserRequestEligible(q, p) ||
		browserproxy.KnownDoHEndpoint(q.Host, p.Destination) || c.browserOriginPolicy(q.Host).Kind == "RELAY" {
		return false
	}
	_, explicit := flowpolicy.Evaluate(cur.profile.Rules, flowpolicy.Input{Protocol: "tcp", Destination: p.Destination, Domain: q.Host, Network: cur.network})
	return !explicit
}

func (c *Controller) openBrowserAutoLocal(ctx context.Context, cur profilesResult, q browserproxy.Request, p browserproxy.Plan, open func(context.Context, browserproxy.Request, browserproxy.Plan) (net.Conn, error)) (net.Conn, browserproxy.Plan, error) {
	return c.openBrowserAutoCandidates(ctx, cur, q, p, open, true)
}

func (c *Controller) openBrowserAutoLocalAfterDirect(ctx context.Context, cur profilesResult, q browserproxy.Request, p browserproxy.Plan, open func(context.Context, browserproxy.Request, browserproxy.Plan) (net.Conn, error)) (net.Conn, browserproxy.Plan, error) {
	return c.openBrowserAutoCandidates(ctx, cur, q, p, open, false)
}

func (c *Controller) openBrowserAutoCandidates(ctx context.Context, cur profilesResult, q browserproxy.Request, p browserproxy.Plan, open func(context.Context, browserproxy.Request, browserproxy.Plan) (net.Conn, error), tryDirect bool) (net.Conn, browserproxy.Plan, error) {
	r := c.browser.youtube
	if c.catalog != nil {
		r.setPlans(c.catalog.snapshot().Plans)
	}
	key := youtubeScope(cur, q)
	endpoint := cdnEndpoint{q.Host, p.Destination.String()}
	scope := youtubeBackgroundScope{network: cur.network, revision: c.policyRevision(cur.profile)}
	scopeCurrent := func() bool {
		fresh, err := c.browserProfile(q.Owner)
		return err == nil && fresh.enabled && !fresh.routingDisabled && fresh.network == scope.network &&
			c.policyRevision(fresh.profile) == scope.revision && c.youtubeLocalBetaOriginScope(q) == 0 &&
			c.browserAutoLocalEligible(fresh, q, p)
	}
	if !scopeCurrent() {
		return nil, p, errAutomaticScopeChanged
	}

	now := time.Now()
	r.mu.Lock()
	directOrder := "skip"
	if tryDirect {
		directOrder = "first"
	}
	candidates := r.youtubeLocalCandidatesLocked(key, key, endpoint, p.Policy.Source == "configured_baseline", directOrder, now)
	cached, found := r.cache[key]
	selection := cdnSelectionEvidence{CheckedAt: now.UTC(), Scope: key, Cache: cdnCacheSnapshot(cached, found)}
	r.mu.Unlock()

	ref := &youtubePlanRef{}
	var connectionID uint64 // Set by the initial synchronous attempt, before a socket can be read.
	emit := func(stage, phase, strategy, reason, admission, destination string, record uint64, evidence *cdnSelectionEvidence) {
		if !youtubeCDN(key) {
			return
		}
		event := cdnDecisionEvent{ConnectionID: connectionID, Destination: destination, Host: q.Host, Ingress: q.Ingress,
			HintOnly: q.HintOnly, Stage: stage, Phase: phase, Strategy: strategy, Reason: reason,
			Admission: admission, RecordID: record, Selection: evidence}
		if connectionID == 0 {
			event = r.startCDNDecision(q, event)
			connectionID = event.ConnectionID
		} else {
			r.mu.Lock()
			r.addCDNDecisionLocked(event)
			r.mu.Unlock()
		}
	}
	actual := p
	actual.FirstFlightManaged = true
	actual.DirectCandidates = nil
	actual.DirectDeadline = time.Time{}
	actual.Probe = "BROWSER_AUTO_LOCAL"

	var attempt func(context.Context, int, time.Time) (net.Conn, browserproxy.Plan, error)
	attempt = func(work context.Context, index int, deadline time.Time) (net.Conn, browserproxy.Plan, error) {
		for ; index < len(candidates); index++ {
			if err := work.Err(); err != nil {
				return nil, actual, err
			}
			if !scopeCurrent() {
				return nil, actual, errAutomaticScopeChanged
			}
			candidate := candidates[index]
			direct := candidate.id == youTubeLocalDirectCandidate
			if direct && c.directAddressFailed(cur, q, actual) {
				continue
			}

			stage, admission := "DIRECT", "NOT_NEEDED"
			plan := actual
			plan.Policy = flowpolicy.Result{Action: flowpolicy.Direct, Fallback: flowpolicy.FailBlock, Source: youtubeLadderSource, Reason: candidate.reason}
			var release func()
			if !direct {
				if !c.youtubeLocalAllowed(cur.network) {
					continue
				}
				stage, admission = "LOCAL", "ADMITTED"
				if candidate.reason != "LEARNED_LOCAL" && candidate.reason != "RECENT_LOCAL_PROOF" {
					wait, stop := context.WithTimeout(work, 550*time.Millisecond)
					select {
					case c.browser.youtubeLocalBetaProbes <- struct{}{}:
						release = func() { <-c.browser.youtubeLocalBetaProbes }
					case <-wait.Done():
						stop()
						if work.Err() != nil {
							return nil, plan, work.Err()
						}
						emit(stage, "DENIED", candidate.id, "AUTO_LOCAL_PROBE_CAPACITY", "PROBE_SLOT_BUSY", endpoint.Address, 0, &selection)
						return nil, plan, errBrowserAutoLocalBusy
					}
					stop()
				}
				id, engine := c.youtubeEngine(cur, q, plan, candidate.id)
				if id == "" || engine == nil {
					if release != nil {
						release()
					}
					if c.youtubeLocalAllowed(cur.network) && candidate.id != "baseline" {
						// The candidate may be eligible but unable to allocate an
						// engine. Do not turn local resource pressure into VPS use.
						return nil, plan, errors.New("BROWSER_AUTO_LOCAL_ENGINE_UNAVAILABLE")
					}
					continue
				}
				plan.Policy.Action, plan.Policy.Strategy = flowpolicy.DirectPlus, id
			}
			if work.Err() != nil || !scopeCurrent() {
				if release != nil {
					release()
				}
				if work.Err() != nil {
					return nil, plan, work.Err()
				}
				return nil, plan, errAutomaticScopeChanged
			}
			r.mu.Lock()
			check := r.endpointCheckLocked(key, candidate.id, endpoint, time.Now())
			r.mu.Unlock()
			if check.Blocked {
				if release != nil {
					release()
				}
				continue
			}
			evidence := selection
			evidence.Endpoint = &check
			emit(stage, "SELECTED", candidate.id, candidate.reason, admission, endpoint.Address, 0, &evidence)
			started := time.Now()
			dial, stop := context.WithTimeout(work, 550*time.Millisecond)
			conn, err := open(dial, q, plan)
			stop()
			if err != nil || conn == nil || !scopeCurrent() {
				if conn != nil {
					conn.Close()
				}
				if release != nil {
					release()
				}
				if work.Err() != nil {
					return nil, plan, work.Err()
				}
				if !scopeCurrent() {
					return nil, plan, errAutomaticScopeChanged
				}
				emit(stage, "OPEN_FAILED", candidate.id, "OPEN_FAILED", admission, endpoint.Address, 0, nil)
				if direct && !retryableDirectOpen(err) {
					if err == nil {
						err = errors.New("BROWSER_AUTO_DIRECT_OPEN_UNAVAILABLE")
					}
					return nil, plan, err
				}
				if retryableDirectOpen(err) {
					r.noteEndpointFailure(key, candidate.id, endpoint, "OPEN_FAILED", time.Now())
				}
				continue
			}
			label, record := r.recordBrowserAutoOpen(c.browserOriginPolicy(q.Host).Group, cur, q, plan, stage, candidate.id, started)
			emit(stage, "OPENED", candidate.id, "", admission, endpoint.Address, record, nil)
			meter := &youtubeMeter{Conn: conn, r: r, id: record, label: label, key: key, stage: stage, strategy: candidate.id,
				started: time.Now(), host: q.Host, destination: endpoint.Address, recoveryCurrent: scopeCurrent,
				inspection: func() *localstrategy.Inspection { return c.localPacketInspection(q, plan) },
				transform:  func() bool { return c.browserTransform(q, plan) }, endpointScoped: true, releaseProbe: release}
			fail := func(reason string) {
				meter.failure(reason)
				emit(stage, "FAILED", candidate.id, reason, admission, endpoint.Address, record, nil)
			}
			monitored := browserproxy.WatchMidstream(meter, 6*time.Second, func() { fail("MIDSTREAM_STALL_NEW_CONNECTION_REQUIRED") })
			watched := browserproxy.WatchRelayOrigin(monitored, browserproxy.OriginConfig{
				Context: c.ctx, Initial: plan.Destination, Health: browserproxy.NewOriginHealth(),
				Silence: browserproxy.OriginSilenceTimeout, RecoveryDeadline: deadline, ScopeCurrent: scopeCurrent, OnFailure: fail,
				NextFlow: func(next context.Context, _ string) (net.Conn, error) {
					limit, _ := next.Deadline()
					conn, _, err := attempt(next, index+1, limit)
					return conn, err
				},
			})
			ref.set(plan, conn)
			return watched, plan, nil
		}
		if err := work.Err(); err != nil {
			return nil, actual, err
		}
		if !scopeCurrent() {
			return nil, actual, errAutomaticScopeChanged
		}
		reason := "AUTO_LOCAL_CANDIDATES_EXHAUSTED"
		if !c.youtubeLocalAllowed(cur.network) {
			reason = "AUTO_LOCAL_NETWORK_GUARD"
		}
		plan := stallRetryPlan(cur, actual)
		plan.Policy.Source, plan.Policy.Reason = youtubeLadderSource, reason
		plan.FirstFlightManaged = true
		emit("RELAY", "SELECTED", "", reason, reason, endpoint.Address, 0, &selection)
		started := time.Now()
		dial, stop := context.WithTimeout(work, 5*time.Second)
		conn, plan, err := c.openKnownBrowserGroup(dial, cur, q, plan, open)
		stop()
		if err != nil || conn == nil {
			if conn != nil {
				conn.Close()
			}
			emit("RELAY", "OPEN_FAILED", "", reason, reason, plan.Destination.String(), 0, nil)
			if err == nil {
				err = errors.New("BROWSER_AUTO_RELAY_OPEN_UNAVAILABLE")
			}
			return nil, plan, err
		}
		if !scopeCurrent() {
			conn.Close()
			return nil, plan, errAutomaticScopeChanged
		}
		label, record := r.recordBrowserAutoOpen(c.browserOriginPolicy(q.Host).Group, cur, q, plan, "RELAY", "", started)
		emit("RELAY", "OPENED", "", reason, reason, plan.Destination.String(), record, nil)
		ref.set(plan, conn)
		return &youtubeMeter{Conn: conn, r: r, id: record, label: label, key: key, stage: "RELAY", started: time.Now()}, plan, nil
	}
	conn, plan, err := attempt(ctx, 0, time.Time{})
	if err != nil {
		return nil, plan, err
	}
	return &youtubePlanConn{Conn: conn, ref: ref}, plan, nil
}

func (r *youtubeRuntime) recordBrowserAutoOpen(service string, cur profilesResult, q browserproxy.Request, p browserproxy.Plan, stage, candidate string, started time.Time) (string, uint64) {
	if service == "" {
		service = "ordinary"
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	record := r.addYoutubeRecordLocked(youtubeRecord{OpenMS: milliseconds(time.Since(started)), Service: service,
		Active: true, Profile: cur.profile.ID, Domain: q.Host, Destination: p.Destination.String(),
		Stage: stage, Strategy: candidate, Reason: "OPEN", Updated: time.Now()})
	label := service + ":" + stage + ":" + candidate
	if _, exists := r.stats[label]; !exists && len(r.stats) >= 128 {
		label = "other:" + stage + ":CATALOG_OVERFLOW"
	}
	stats := r.stats[label]
	stats.Service, stats.Stage, stats.Strategy = service, stage, candidate
	stats.Connections++
	r.stats[label] = stats
	return label, record
}
