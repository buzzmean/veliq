package clientservice

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/buzzmean/neexitlag/core/browserproxy"
	"github.com/buzzmean/neexitlag/core/flowpolicy"
	"github.com/buzzmean/neexitlag/core/localstrategy"
)

const youtubeTrialCooldown = 3 * time.Minute
const youtubeTrialSuccesses = 3

type youtubeSelectionSnapshot struct {
	ActiveTrialID       uint64    `json:"active_trial_id"`
	ActiveRecordID      uint64    `json:"active_record_id"`
	ActiveHost          string    `json:"active_host,omitempty"`
	ActiveDestination   string    `json:"active_destination,omitempty"`
	ActiveRecordResult  string    `json:"active_record_result,omitempty"`
	ActiveRecordMatches bool      `json:"active_record_matches"`
	ActiveStartedAt     time.Time `json:"active_started_at"`
	cdnTrialSlot
	BackgroundAttempts, BackgroundFailures                              uint64 `json:",omitempty"`
	Trials, TrialSuccesses, TrialFailures, FailedAfterReply             uint64
	DataTrials                                                          uint64
	PostTrialFailures                                                   uint64
	TrialInconclusive                                                   uint64
	ClientInitiatedTrialCloses                                          uint64
	StrongPromotions, PostPromotionFailures, RemoteSmallEOFInconclusive uint64
	BurstPromotions                                                     uint64
	PeerProvisional, PeerProvisionalFailures, PeerRevocations           uint64
	PeerRenewals, PeerRestored                                          uint64
	PeerProofs                                                          int
	ActiveDomain                                                        string `json:"active_domain,omitempty"`
	ActiveAgeMS                                                         int64  `json:"active_age_ms"`
	ActiveLastRXAgeMS                                                   int64  `json:"active_last_rx_age_ms"`
	ActiveState                                                         string `json:"active_state,omitempty"`
	ActiveTrial                                                         bool   `json:"active_trial"`
	BackgroundActive                                                    bool   `json:"background_active"`
	Contract                                                            string `json:"contract"`
}
type youtubeQualification struct {
	Network, Profile, Strategy string
	HintOnly                   bool
}

type youtubeScoreKey struct {
	Scope    youtubeKey
	Strategy string
}
type youtubeScore struct {
	Good, Bad uint32
	Updated   time.Time
}

type youtubePending struct {
	Current profilesResult
	Request browserproxy.Request
	Plan    browserproxy.Plan
	Seen    time.Time
}

// Background probes have no cached-PAC compatibility entitlement. Carry their
// admission policy through both DoH and origin opens, including nested timeouts.
type youtubeBackgroundScopeKey struct{}
type youtubeBackgroundScope struct {
	network, revision string
	cancel            context.CancelFunc
}

func (c *Controller) youtubeBackgroundScopeCurrent(scope youtubeBackgroundScope, cur profilesResult) bool {
	return cur.enabled && !cur.routingDisabled && cur.network == scope.network &&
		c.youtubeLocalAllowed(scope.network) && c.policyRevision(cur.profile) == scope.revision
}

// Admission observations do not own Retry. Ignore only those diagnostics when
// comparing the background reservation; media/qualification/cooldown state stays
// in the comparison, including the monotonic trial identity on a shared tick.
func backgroundRetryState(v youtubeLearn) youtubeLearn {
	v.TrialAdmission = ""
	v.TrialChecks, v.TrialDenials = 0, 0
	v.Sibling = relaySiblingEvidence{}
	v.SiblingWaits = 0
	v.LastTrialCheck = time.Time{}
	return v
}

func (r *youtubeRuntime) cancelBackgroundRecheck(key youtubeKey, reservation youtubeLearn) {
	r.mu.Lock()
	defer r.mu.Unlock()
	v, ok := r.cache[key]
	// Release only this worker's scheduling delay. A real flow may have
	// installed a newer cooldown/confirmation while the probe was in flight.
	// Retry timestamps alone are not ownership: distinct Windows events can
	// occupy the same clock tick. Preserve intervening learning transitions.
	if !ok || backgroundRetryState(v) != backgroundRetryState(reservation) || r.trialActive && r.trialKey == key {
		return
	}
	v.Retry = time.Time{}
	v.Reason = "BACKGROUND_POLICY_CHANGED"
	r.cache[key] = v
}

func (r *youtubeRuntime) register(k youtubeKey, cur profilesResult, q browserproxy.Request, p browserproxy.Plan, now time.Time) {
	if !q.Source.IsValid() || q.Source.Addr().IsUnspecified() || k.Network == "" {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	for key, v := range r.pending {
		if now.Sub(v.Seen) > 30*time.Minute {
			delete(r.pending, key)
		}
	}
	if _, ok := r.pending[k]; !ok && len(r.pending) >= 64 {
		return
	}
	r.pending[k] = youtubePending{cur, q, p, now}
}
func (r *youtubeRuntime) stop() { r.mu.Lock(); r.stopped = true; r.mu.Unlock(); r.workers.Wait() }
func (c *Controller) watchLocalSelection() {
	timer := time.NewTicker(15 * time.Second)
	defer timer.Stop()
	for {
		select {
		case <-c.ctx.Done():
			return
		case now := <-timer.C:
			c.recheckPendingLocal(now)
		}
	}
}
func (c *Controller) recheckPendingLocal(now time.Time) {
	r := c.browser.youtube
	r.mu.Lock()
	work := make(map[youtubeKey]youtubePending)
	for k, v := range r.pending {
		if now.Sub(v.Seen) > 30*time.Minute {
			delete(r.pending, k)
			continue
		}
		if !now.Before(r.cache[k].Retry) {
			work[k] = v
		}
	}
	r.mu.Unlock()
	for k, v := range work {
		// Re-resolve the owner and policy. A background recheck must never retain
		// permission after disable, process replacement, VPN or a network change.
		cur, err := c.browserProfile(v.Request.Owner)
		if err != nil || !cur.enabled || cur.network != k.Network || c.policyRevision(cur.profile) != c.policyRevision(v.Current.profile) {
			continue
		}
		c.youtubeBackgroundRecheck(cur, v.Request, v.Plan, k)
	}
}

// Caller holds r.mu. Bounded and network/subgroup scoped; no device identifiers.
func (r *youtubeRuntime) score(k youtubeKey, strategy string, good bool, now time.Time) {
	key := youtubeScoreKey{k, strategy}
	v, ok := r.scores[key]
	if !ok && len(r.scores) >= 2048 {
		for key, v := range r.scores {
			if now.Sub(v.Updated) > 24*time.Hour {
				delete(r.scores, key)
			}
		}
		if len(r.scores) >= 2048 {
			return
		}
	}
	if now.Sub(v.Updated) > 24*time.Hour {
		v = youtubeScore{}
	}
	if v.Good+v.Bad >= 100 {
		v.Good /= 2
		v.Bad /= 2
	}
	if good {
		v.Good++
	} else {
		v.Bad++
	}
	v.Updated = now
	r.scores[key] = v
}

// LOCAL results are deliberately NOT the family-wide DIRECT-timeout key.
// A single account endpoint cannot poison the video CDN or www/thumbnail origin.
func youtubeSubgroup(host string) string {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	if host == "googlevideo.com" || strings.HasSuffix(host, ".googlevideo.com") {
		for _, label := range strings.Split(host, ".") {
			if i := strings.Index(label, "---sn-"); i >= 0 {
				return "googlevideo:" + label[i+3:]
			}
		}
		return "googlevideo:unclassified"
	}
	return host
}
func youtubeCDN(k youtubeKey) bool {
	return strings.HasPrefix(k.Domain, "googlevideo:") || k.Domain == "googlevideo.com"
}
func youtubeBackoff(failures uint32) time.Duration {
	if failures > 5 {
		failures = 5
	}
	pause := 15 * time.Second * time.Duration(uint64(1)<<failures)
	if pause > 5*time.Minute {
		pause = 5 * time.Minute
	}
	return pause
}
func (r *youtubeRuntime) room(k youtubeKey, now time.Time) bool {
	for key, v := range r.cache {
		if now.Sub(v.Until) > 24*time.Hour {
			delete(r.cache, key)
		}
	}
	_, ok := r.cache[k]
	return ok || len(r.cache) < 256
}
func (r *youtubeRuntime) setPlans(plans []localstrategy.CatalogPlan) {
	r.mu.Lock()
	defer r.mu.Unlock()
	old := strings.Join(r.order, "|")
	r.plans = map[string]localstrategy.CatalogPlan{}
	r.order = nil
	for _, p := range plans {
		if len(r.order) >= 48 {
			break
		}
		if _, ok := r.plans[p.ID]; !ok {
			r.plans[p.ID] = p
			r.order = append(r.order, p.ID)
		}
	}
	r.order = append(r.order, youtubeLegacyOrder...)
	if old != "" && old != strings.Join(r.order, "|") {
		for k, v := range r.cache {
			v.Next = 0
			v.Tried = 0
			r.cache[k] = v
		}
	}
}

// Compilation order is a prior; measured outcomes of this subgroup rank plans.
// Every failed candidate is tried once per sweep before any candidate is repeated.
func (r *youtubeRuntime) nextCandidate(k youtubeKey, v youtubeLearn) string {
	if len(r.order) == 0 {
		return ""
	}
	best := ""
	bestScore := -1000000
	for n := 0; n < len(r.order); n++ {
		i := (v.Next + n) % len(r.order)
		if v.Tried&(1<<uint(i)) == 0 {
			measured := r.scores[youtubeScoreKey{k, r.order[i]}]
			score := 0
			if time.Since(measured.Updated) < 24*time.Hour {
				score = int(measured.Good)*8 - int(measured.Bad)*2
			}
			if best == "" || score > bestScore {
				best = r.order[i]
				bestScore = score
			}
		}
	}
	if best != "" {
		return best
	}
	return r.order[v.Next%len(r.order)]
}
func (r *youtubeRuntime) takeRecheck(k youtubeKey, now time.Time) (youtubeLearn, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if k.Network == "" || r.stopped || r.selecting || !r.room(k, now) {
		return youtubeLearn{}, false
	}
	v := r.cache[k]
	if now.Before(v.Retry) {
		return youtubeLearn{}, false
	}
	if v.Stage == "" {
		v.Stage = "RELAY"
		v.Until = now.Add(youtubeLearnTTL)
	}
	if v.Tried == (uint64(1)<<uint(len(r.order)))-1 {
		v.Tried = 0
	}
	v.Retry = now.Add(youtubeTrialCooldown)
	r.cache[k] = v
	r.selecting = true
	r.workers.Add(1)
	r.selection.BackgroundActive = true
	return v, true
}
func (r *youtubeRuntime) endRecheck() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.selecting = false
	r.selection.BackgroundActive = false
	r.workers.Done()
}
func (r *youtubeRuntime) qualified(k youtubeKey, strategy string, now time.Time) bool {
	return now.Before(r.qualifications[youtubeQualification{k.Network, k.Profile, strategy, k.HintOnly}])
}

// Caller holds mu. Prefer actual sustained YouTube proof over a transform-only
// witness, never transfer evidence across network/profile/hint mode or retry a
// failed candidate within this sweep. Stable catalog order breaks ties.
func (r *youtubeRuntime) cdnCandidate(k youtubeKey, v youtubeLearn, now time.Time) string {
	best := ""
	strength := 0
	for i, id := range r.order {
		if v.Tried&(uint64(1)<<uint(i)) != 0 || !r.qualified(k, id, now) {
			continue
		}
		score := 1
		if now.Before(r.sustained[youtubeQualification{k.Network, k.Profile, id, k.HintOnly}]) {
			score = 2
		}
		if score > strength {
			best = id
			strength = score
		}
	}
	return best
}
func (r *youtubeRuntime) takeTrial(k youtubeKey, now time.Time, peer relaySiblingEvidence) (string, bool) {
	id, _, ok := r.takeEndpointTrial(k, now, peer, cdnEndpoint{})
	return id, ok
}
func (r *youtubeRuntime) takeEndpointTrial(k youtubeKey, now time.Time, peer relaySiblingEvidence, endpoint cdnEndpoint) (string, uint64, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	v := r.cache[k]
	if !youtubeCDN(k) {
		return "", 0, false
	}
	reason := "ADMITTED"
	switch {
	case r.trialActive:
		reason = "GLOBAL_TRIAL_ACTIVE"
	case now.Before(v.TrialAfter):
		reason = "SUBGROUP_COOLDOWN"
	case v.Qualified == "":
		reason = "NO_QUALIFIED_STRATEGY"
	case !r.qualified(k, v.Qualified, now):
		reason = "STRATEGY_PROOF_EXPIRED"
	case endpoint.valid() && r.endpointBlockedLocked(k, v.Qualified, endpoint, now):
		reason = "ENDPOINT_STRATEGY_NEGATIVE_TTL"
	case peer.MediaRequired && peer.MediaBytes <= cdnStrongBytes:
		reason = "SCOPED_BULK_RELAY_NOT_OBSERVED"
	case !peer.Eligible:
		reason = "RECENT_RELAY_SIBLING_NOT_OBSERVED"
	}
	v.Sibling = peer
	if reason == "RECENT_RELAY_SIBLING_NOT_OBSERVED" {
		v.SiblingWaits++
	}
	v.TrialChecks++
	v.LastTrialCheck = now
	v.TrialAdmission = reason
	if reason != "ADMITTED" {
		v.TrialDenials++
		if r.room(k, now) {
			r.cache[k] = v
		}
		return "", 0, false
	}
	if v.NeutralShortStreak >= cdnNeutralShortLimit {
		v.NeutralShortStreak = 0
	}
	// Retry is a BACKGROUND probe deadline; only TrialAfter gates real trials.
	r.trialSeq++
	r.trialID = r.trialSeq
	r.trialEndpoint = endpoint
	r.trialActive = true
	r.trialKey = k
	r.trialStrategy = v.Qualified
	r.trialStarted = now
	r.trialRecord = 0
	r.selection.ActiveTrial = true
	r.selection.Trials++
	v.Retry = now.Add(youtubeTrialCooldown)
	v.TrialAfter = v.Retry
	r.cache[k] = v
	return v.Qualified, r.trialID, true
}
func (r *youtubeRuntime) finishTrial(k youtubeKey, strategy string, success, afterReply bool, now time.Time, received ...uint64) {
	n := uint64(0)
	if len(received) > 0 {
		n = received[0]
	}
	verdict := "FAILED"
	if success {
		verdict = "SUCCESS"
	}
	r.finishTrialOutcome(k, strategy, verdict, afterReply, now, n)
}
func (r *youtubeRuntime) finishTrialOutcome(k youtubeKey, strategy, verdict string, afterReply bool, now time.Time, received uint64) cdnTrialSlot {
	return r.finishTrialOutcomeFor(0, k, strategy, verdict, afterReply, now, received)
}
func (r *youtubeRuntime) finishTrialOutcomeFor(token uint64, k youtubeKey, strategy, verdict string, afterReply bool, now time.Time, received uint64) (slot cdnTrialSlot) {
	success := verdict == "SUCCESS"
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.trialActive || r.trialKey != k || r.trialStrategy != strategy || token != 0 && token != r.trialID {
		return
	}
	slot = cdnTrialSlot{TrialID: r.trialID, SlotReleasedAt: now, SlotReleaseReason: verdict, NeutralShortAttempt: r.cache[k].NeutralShortStreak + 1}
	// Runs under r.mu and after the outcome has chosen its cooldown.
	defer func() { r.releaseTrialSlotLocked(slot) }()
	shortReply := verdict == "REMOTE_SMALL_EOF" || verdict == "CLIENT_INITIATED_CLOSE" || verdict == cdnShortReplyIdle
	if verdict == "INCONCLUSIVE" || shortReply {
		r.selection.TrialInconclusive++
		if verdict == "CLIENT_INITIATED_CLOSE" {
			r.selection.ClientInitiatedTrialCloses++
		}
		v := r.cache[k]
		v.Retry = now.Add(youtubeTrialCooldown)
		v.TrialAfter = v.Retry
		v.Reason = "CDN_TRIAL_INCONCLUSIVE"
		if verdict == "REMOTE_SMALL_EOF" {
			r.selection.RemoteSmallEOFInconclusive++
			v.Reason = "CDN_TRIAL_SMALL_EOF_INCONCLUSIVE"
		}
		if verdict == "CLIENT_INITIATED_CLOSE" {
			v.Reason = "CDN_TRIAL_CLIENT_CLOSE_INCONCLUSIVE"
		}
		short := shortReply && received > 0 && received < cdnDataTrialBytes
		if short {
			v.NeutralShortStreak++
			if v.NeutralShortStreak < cdnNeutralShortLimit {
				v.TrialAfter = now
				v.Reason = "CDN_TRIAL_NEUTRAL_SHORT_NEXT_NEW_FLOW"
			} else {
				v.Reason = "CDN_TRIAL_ALL_SMALL_NO_DATA_LIMIT_COOLDOWN"
			}
		} else {
			v.NeutralShortStreak = 0
		}
		slot.CooldownUntil = v.TrialAfter
		v.cdnTrialSlot = slot
		if r.room(k, now) {
			r.cache[k] = v
		}
		return
	}
	if !r.room(k, now) {
		r.selection.TrialFailures++
		if afterReply {
			r.selection.FailedAfterReply++
		}
		return
	}
	v := r.cache[k]
	v.NeutralShortStreak = 0
	if success && v.Qualified == strategy && r.qualified(k, strategy, now) {
		r.score(k, strategy, true, now)
		r.selection.TrialSuccesses++
		if received > 64*1024 {
			v.VerifiedBytes = received
		}
		v.Streak++
		if v.Streak >= youtubeTrialSuccesses {
			v.Stage = "LOCAL"
			v.Strategy = strategy
			v.Confirmed = true
			v.Reason = "THREE_SUSTAINED_CDN_TRIALS"
			r.notePeerProofLocked(k, strategy, now)
		}
	} else {
		r.selection.TrialFailures++
		if afterReply {
			r.selection.FailedAfterReply++
		}
		if !r.trialEndpoint.valid() && v.Qualified != "" {
			v.Failures++
			for i, id := range r.order {
				if id == strategy {
					v.Next = (i + 1) % len(r.order)
					v.Tried |= 1 << uint(i)
				}
			}
		}
		if r.trialEndpoint.valid() {
			v.Reason = "CDN_ENDPOINT_FAILED_QUALIFICATION_RETAINED"
		} else {
			v.Qualified = ""
			v.Streak = 0
			v.Stage = "RELAY"
			v.Strategy = ""
			v.Confirmed = false
			v.Reason = "CDN_TRIAL_FAILED_NEXT_CONNECTION_RELAY"
		}
	}
	pause := youtubeTrialCooldown
	if b := youtubeBackoff(v.Failures); b > pause {
		pause = b
	}
	v.Retry = now.Add(pause)
	v.TrialAfter = v.Retry
	v.Until = now.Add(youtubeLearnTTL)
	slot.CooldownUntil = v.TrialAfter
	v.cdnTrialSlot = slot
	r.cache[k] = v
	return
}

func youtubeTransferOK(p browserproxy.ProbeResult) bool {
	return p.Failure == "" && p.TLSVersion >= 0x0303 && p.Status >= 200 && p.Status < 300 && p.BodyBytes > 64*1024
}

func (c *Controller) youtubeBackgroundRecheck(cur profilesResult, q browserproxy.Request, p browserproxy.Plan, key youtubeKey) {
	if !q.Source.IsValid() || q.Source.Addr().IsUnspecified() || !c.youtubeLocalAllowed(cur.network) {
		return
	}
	// Do not let a recheck postpone an already-qualified CDN trial's cooldown.
	r := c.browser.youtube
	allowed, sharedCandidate := true, ""
	if c.sharedScopeAllowed(key) {
		allowed, sharedCandidate = r.shared.decision(key, time.Now())
	}
	if !allowed {
		return
	}
	r.mu.Lock()
	v := r.cache[key]
	// Any committed YouTube transform of this same scoped plan permits a
	// guarded real CDN trial, not a LOCAL confirmation or a page-success claim.
	candidate := r.nextCandidate(key, v)
	if youtubeCDN(key) {
		if qualified := r.cdnCandidate(key, v, time.Now()); qualified != "" {
			candidate = qualified
		}
	}
	if sharedCandidate != "" && (!youtubeCDN(key) || !r.qualified(key, candidate, time.Now())) {
		candidate = sharedCandidate
	}
	transformProof := youtubeCDN(key) && candidate != "" && r.qualified(key, candidate, time.Now())
	waitingTrial := r.trialActive || v.Qualified != "" && r.qualified(key, v.Qualified, time.Now()) && (candidate == v.Qualified || candidate == "")
	r.mu.Unlock()
	if waitingTrial {
		return
	}
	if transformProof {
		r.completeCDNQualification(key, candidate, time.Now())
		return
	}
	learned, ok := r.takeRecheck(key, time.Now())
	if !ok {
		return
	}
	select {
	case c.browser.probes <- struct{}{}:
	default:
		r.endRecheck()
		return
	}
	scope := youtubeBackgroundScope{network: cur.network, revision: c.policyRevision(cur.profile)}
	go func() {
		cancelled := false
		defer func() {
			if cancelled {
				r.cancelBackgroundRecheck(key, learned)
			}
			<-c.browser.probes
			r.endRecheck()
		}()
		ctx, cancel := context.WithTimeout(c.ctx, 12*time.Second)
		defer cancel()
		scope.cancel = cancel
		ctx = context.WithValue(ctx, youtubeBackgroundScopeKey{}, scope)
		current := func() bool {
			fresh, err := c.browserProfile(q.Owner)
			if errors.Is(ctx.Err(), context.Canceled) || err != nil || !c.youtubeBackgroundScopeCurrent(scope, fresh) {
				cancelled = true
				cancel()
				return false
			}
			return true
		}
		probeQ := q
		probeQ.Ingress = "YOUTUBE_BACKGROUND_RECHECK"
		r.mu.Lock()
		strategy := r.nextCandidate(key, learned)
		if sharedCandidate != "" {
			strategy = sharedCandidate
		}
		r.selection.BackgroundAttempts++
		r.mu.Unlock()
		if strategy == "" {
			return
		}
		// For a CDN no signed media URL is visible without MITM. These are necessary
		// prerequisites only, never a claim that the actual CDN has been validated.
		var verifiedBytes uint64
		var controlClass string
		passed := youtubePrerequisites(key, q.Host, func(origin [2]string) bool {
			if !current() {
				return false
			}
			// Separate held source reservations prevent the second origin from borrowing
			// the first origin's committed-transform evidence on a shared CDN address.
			socket, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IP(q.Source.Addr().AsSlice())})
			if err != nil {
				return false
			}
			defer socket.Close()
			probeQ.Source = socket.LocalAddr().(*net.UDPAddr).AddrPort()
			probeQ.Host = origin[0]
			work, stop := context.WithTimeout(ctx, 5*time.Second)
			relay := p
			relay.Policy = browserDNSPolicy(cur)
			answer, e := c.knownOriginResolve(work, cur, probeQ, relay)
			if !current() {
				stop()
				return false
			}
			if e != nil {
				stop()
				c.recordLocalProbe(probeQ, p, strategy, browserproxy.ProbeResult{Phase: "ORIGIN_DNS", Failure: "DNS_FAILED", Detail: "RESOLVE_FAILED"}, false)
				r.backgroundFailure(key, strategy, "BACKGROUND_DNS_FAILED")
				return false
			}
			addresses := append([]netip.Addr(nil), answer.Addresses...)
			sort.SliceStable(addresses, func(i, j int) bool { return addresses[i].Is4() && !addresses[j].Is4() })
			var dst netip.AddrPort
			for _, ip := range addresses {
				if ip.Is4() && browserproxy.PublicDNSAddress(ip) {
					dst = netip.AddrPortFrom(ip, 443)
					break
				}
			}
			if !dst.IsValid() {
				stop()
				c.recordLocalProbe(probeQ, p, strategy, browserproxy.ProbeResult{Phase: "ORIGIN_DNS", Failure: "DNS_FAILED", Detail: "NO_PUBLIC_IPV4"}, false)
				r.backgroundFailure(key, strategy, "BACKGROUND_NO_PUBLIC_IPV4")
				return false
			}
			candidate := p
			candidate.Destination = dst
			candidate.DirectCandidates = nil
			candidate.DirectDeadline = time.Time{}
			id, _ := c.youtubeEngine(cur, probeQ, candidate, strategy)
			if id == "" {
				stop()
				c.recordLocalProbe(probeQ, candidate, strategy, browserproxy.ProbeResult{Phase: "LOCAL_GUARD", Failure: "LOCAL_GUARD", Detail: "NETWORK_OR_PROFILE_GUARD"}, false)
				r.backgroundFailure(key, strategy, "BACKGROUND_LOCAL_GUARD")
				return false
			}
			candidate.Policy = flowpolicy.Result{Action: flowpolicy.DirectPlus, Strategy: id, Fallback: flowpolicy.FailBlock, Source: youtubeLadderSource}
			var wire *localProbeConn
			var probeOpenError error
			probe := func(ctx context.Context) (net.Conn, error) {
				conn, err := c.browserOpenUnobserved(ctx, probeQ, candidate)
				probeOpenError = err
				if err != nil {
					return nil, err
				}
				wire = &localProbeConn{Conn: conn}
				return wire, nil
			}
			var result browserproxy.ProbeResult
			if publicProbeHost(probeQ.Host) {
				result = probePublicService(work, probeQ.Host, c.BrowserProbeRoots, probe)
			} else {
				result = browserproxy.ProbeOriginTransfer(work, probeQ.Host, origin[1], c.BrowserProbeRoots, probe)
			}
			if !current() {
				stop()
				return false
			}
			var socketError *os.SyscallError
			if result.Phase == "RELAY_OR_TCP_OPEN" && errors.As(probeOpenError, &socketError) && socketError.Syscall == "LOCAL_TCP_TIMESTAMPS_UNAVAILABLE" {
				result.Phase = "LOCAL_GUARD"
				result.Failure = "LOCAL_SOCKET_OPTION_FAILED"
				result.Detail = "TCP_TIMESTAMPS_UNAVAILABLE"
			}
			applied := c.browserTransform(probeQ, candidate)
			sent := uint64(0)
			if wire != nil {
				sent = wire.sent.Load()
			}
			c.recordLocalProbe(probeQ, candidate, strategy, result, applied, sent)
			stop()
			if !localProbeSuccess(probeQ.Host, result) || !applied {
				r.backgroundFailure(key, strategy, "BACKGROUND_NOT_SUSTAINED_OR_NO_TRANSFORM")
				return false
			}
			verifiedBytes = result.BodyBytes
			if result.Phase == "PUBLIC_WS_CONTROL" || result.Phase == "PUBLIC_REDIRECT_CONTROL" {
				controlClass = result.Phase
			}
			return true
		})
		if !passed || !current() {
			return
		}

		now := time.Now()
		if youtubeCDN(key) {
			r.completeCDNQualification(key, strategy, now)
		} else {
			r.confirmed(key, "LOCAL", strategy, now)
			r.recordVerification(key, verifiedBytes)
			if controlClass != "" {
				r.mu.Lock()
				v := r.cache[key]
				v.Reason = "BACKGROUND_" + controlClass + "_NOT_BULK_PROOF"
				r.cache[key] = v
				r.mu.Unlock()
			}
		}
	}()
}
func (r *youtubeRuntime) backgroundFailure(k youtubeKey, strategy, reason string) {
	r.mu.Lock()
	r.selection.BackgroundFailures++
	if r.trialActive && r.trialKey == k {
		r.mu.Unlock()
		return
	}
	if reason == "BACKGROUND_DNS_FAILED" || reason == "BACKGROUND_NO_PUBLIC_IPV4" || reason == "BACKGROUND_LOCAL_GUARD" {
		v := r.cache[k]
		v.Reason = reason
		v.Retry = time.Now().Add(youtubeTrialCooldown)
		r.cache[k] = v
		r.mu.Unlock()
		return
	}
	if reason == "BACKGROUND_NOT_SUSTAINED_OR_NO_TRANSFORM" && youtubeCDN(k) {
		now := time.Now()
		v := r.cache[k]
		if candidate := r.cdnCandidate(k, v, now); candidate != "" {
			// The public response failed, but recordLocalProbe may have
			// witnessed a committed transform. Keep it eligible for the
			// existing guarded media trial; this is not a CDN failure or
			// success. Tried candidates and expired/foreign proofs stay out.
			// Preserve a live media confirmation without extending its TTL.
			if !v.Confirmed || v.Stage != "LOCAL" || !now.Before(v.Until) {
				r.completeCDNQualificationLocked(k, candidate, now)
			}
			r.mu.Unlock()
			return
		}
	}
	r.mu.Unlock()
	r.failed(k, "LOCAL", strategy, reason, time.Now())
}

// Mixed account/page/CDN hints may select the stricter RELAY route, but may not
// authorize LOCAL for whichever name sorts first on a shared address.
func youtubeSameHintSubgroup(e browserDomainEvidence) bool {
	return e.YoutubeOnly && e.YoutubeSubgroup != ""
}

func youtubePrerequisites(k youtubeKey, host string, probe func([2]string) bool) bool {
	origins := [][2]string{{host, "/"}}
	if youtubeCDN(k) {
		origins = [][2]string{{"www.youtube.com", "/"}, {"i.ytimg.com", "/vi/aqz-KE-bpKQ/maxresdefault.jpg"}}
	}
	for _, origin := range origins {
		if !probe(origin) {
			return false
		}
	}
	return true
}

func (r *youtubeRuntime) recordVerification(k youtubeKey, bytes uint64) {
	r.mu.Lock()
	v, ok := r.cache[k]
	if !ok {
		r.mu.Unlock()
		return
	}
	v.VerifiedBytes = bytes
	r.cache[k] = v
	r.mu.Unlock()
	r.shared.notify()
}

// Public prerequisites do not extend a real CDN confirmation deadline.
func (r *youtubeRuntime) completeCDNQualification(key youtubeKey, strategy string, now time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.completeCDNQualificationLocked(key, strategy, now)
}

// Caller holds mu so a real CDN failure cannot race selection and restore a
// just-rejected strategy between the proof check and qualification update.
func (r *youtubeRuntime) completeCDNQualificationLocked(key youtubeKey, strategy string, now time.Time) {
	if r.trialActive {
		return
	} // Never change binding beneath an established trial.
	if best := r.cdnCandidate(key, r.cache[key], now); best != "" {
		strategy = best
	}
	if !r.room(key, now) {
		return
	}
	if len(r.qualifications) >= 256 {
		for k, until := range r.qualifications {
			if !now.Before(until) {
				delete(r.qualifications, k)
			}
		}
	}
	if len(r.qualifications) >= 256 {
		return
	}
	proof := youtubeQualification{key.Network, key.Profile, strategy, key.HintOnly}
	if !now.Before(r.qualifications[proof]) {
		r.qualifications[proof] = now.Add(youtubeLearnTTL)
	}
	v := r.cache[key]
	stillConfirmed := v.Confirmed && v.Stage == "LOCAL" && v.Strategy == strategy && now.Before(v.Until)
	if !stillConfirmed {
		v.Streak = 0
		v.Confirmed = false
		v.Stage = "RELAY"
		v.Strategy = ""
		v.VerifiedBytes = 0
		v.Until = now.Add(youtubeLearnTTL)
	}
	v.Qualified = strategy
	if v.TrialAfter.After(now) {
		v.Retry = v.TrialAfter
	} else {
		v.Retry = now
	}
	v.Reason = "SAME_STRATEGY_TRANSFORM_PROVEN_CDN_TRIAL_PENDING"
	if stillConfirmed {
		v.Reason = "PUBLIC_RECHECK_PASSED; EXISTING_MEDIA_CONFIRMATION_DEADLINE_PRESERVED"
	}
	r.cache[key] = v
}
