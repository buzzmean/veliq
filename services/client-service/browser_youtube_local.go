package clientservice

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/buzzmean/neexitlag/core/browserproxy"
	"github.com/buzzmean/neexitlag/core/flowpolicy"
	"github.com/buzzmean/neexitlag/core/localstrategy"
	"github.com/buzzmean/neexitlag/core/originpolicy"
)

const youtubeLadderSource = "youtube_local_ladder"
const youtubeLearnTTL = 10 * time.Minute
const youtubeRetryAfter = time.Minute

var youtubeLegacyOrder = []string{"fake5x2-disorder", "fake8x2-disorder", "fake5", "fake8-disorder", "fake2", "disorder", "sni", "split1", "fake5-only"}

type youtubeKey struct {
	Network  string `json:"network"`
	Profile  string `json:"profile"`
	Domain   string `json:"domain"`
	Port     uint16 `json:"port"`
	HintOnly bool   `json:"hint_only"`
}
type cdnTrialStreak struct {
	strategy string
	count    uint32
}
type youtubeLearn struct {
	cdnTrialSlot
	NeutralShortStreak        uint32
	Stage, Strategy           string
	Until, Retry              time.Time
	TrialAfter                time.Time
	TrialAdmission            string
	TrialChecks, TrialDenials uint64
	Sibling                   relaySiblingEvidence
	SiblingWaits              uint64
	LastTrialCheck            time.Time
	Next                      int
	Tried                     uint64
	Failures, Streak          uint32
	alternateTrialStreak      cdnTrialStreak
	Qualified                 string
	VerifiedBytes             uint64
	Reason                    string
	Confirmed                 bool
}
type youtubeStage struct {
	Service                                            string `json:"service,omitempty"`
	Stage                                              string `json:"stage"`
	Strategy                                           string `json:"strategy,omitempty"`
	Connections, TX, RX, Failures, Confirmed           uint64
	Inconclusive, HelloSamples, HelloSumMS, HelloMaxMS uint64
}
type youtubeRecord struct {
	cdnTrialSlot
	DataTrial              bool                  `json:"data_trial"`
	TrialResult            string                `json:"trial_result,omitempty"`
	Failure                *localFailureEvidence `json:"-"`
	OpenMS                 float64               `json:"open_ms"`
	Timing                 youtubeTimings        `json:"-"`
	LastRX                 time.Time             `json:"-"`
	IOFailure              string                `json:"io_failure,omitempty"`
	Service                string                `json:"service,omitempty"`
	Active                 bool                  `json:"active"`
	ID                     uint64                `json:"id"`
	Profile                string                `json:"profile"`
	Domain                 string                `json:"domain"`
	Destination            string                `json:"destination"`
	Stage                  string                `json:"stage"`
	Strategy               string                `json:"strategy,omitempty"`
	Reason                 string                `json:"reason"`
	TX, RX                 uint64
	ServerHello, Transform bool
	Trial                  bool                      `json:"trial"`
	Inspection             *localstrategy.Inspection `json:"-"`
	TransformKnown         bool
	Updated                time.Time `json:"updated_at"`
}
type youtubeCacheView struct {
	cdnTrialSlot
	NeutralShortStreak                                uint32
	CooldownWaitMS                                    int64
	HintOnly                                          bool
	Network, Profile, Domain, Stage, Strategy, Reason string
	Port                                              uint16
	Until, Retry                                      time.Time
	Tried                                             uint64
	Streak                                            uint32
	Qualified                                         string
	TrialAdmission                                    string
	TrialChecks, TrialDenials                         uint64
	LastTrialCheck                                    time.Time
	TrialAfter                                        time.Time
	Sibling                                           relaySiblingEvidence
	SiblingWaits                                      uint64
}
type youtubeSnapshot struct {
	RecordsOmitted uint64                   `json:"records_omitted"`
	CacheOmitted   int                      `json:"cache_entries_omitted"`
	Cache          []youtubeCacheView       `json:"cache"`
	CacheEntries   int                      `json:"cache_entries"`
	Stages         []youtubeStage           `json:"stages"`
	Records        []youtubeRecord          `json:"records"`
	Shared         sharedLearningSnapshot   `json:"shared_learning"`
	Selection      youtubeSelectionSnapshot `json:"selection"`
	Replays        string                   `json:"replay_contract"`
}
type youtubeEngine struct {
	Engine *localstrategy.LocalStrategyEngine
	Until  time.Time
}
type youtubeRuntime struct {
	ordinaryDirectAttempts, ordinaryDenials uint64
	trialID, trialSeq                       uint64
	trialEndpoint                           cdnEndpoint
	endpointNegative                        map[cdnEndpointKey]cdnEndpointFailure
	cdnDecisionSeq                          uint64
	cdnDecisions                            [cdnDecisionLimit]cdnDecisionEvent

	ordinary       []ordinaryFlowEvidence
	ordinarySeq    uint64
	probeEvidence  []localProbeEvidence
	failures       []localFailureEvidence
	trials         []cdnTrialEvidence
	mu             sync.Mutex
	cache          map[youtubeKey]youtubeLearn
	engines        map[string]youtubeEngine
	stats          map[string]youtubeStage
	records        map[uint64]youtubeRecord
	seq            uint64
	plans          map[string]localstrategy.CatalogPlan
	order          []string
	qualifications map[youtubeQualification]time.Time
	sustained      map[youtubeQualification]time.Time
	peerProofs     map[youtubeQualification]time.Time
	peerDenied     map[youtubeScoreKey]time.Time
	peerSeen       map[youtubeQualification]time.Time
	peerPath       string
	peerWritten    time.Time
	peerWriteSeq   uint64
	peerWriteDone  uint64
	peerWriteMu    sync.Mutex
	selecting      bool
	trialKey       youtubeKey
	trialStrategy  string
	trialStarted   time.Time
	trialRecord    uint64
	trialActive    bool
	selection      youtubeSelectionSnapshot
	scores         map[youtubeScoreKey]youtubeScore
	pending        map[youtubeKey]youtubePending
	workers        sync.WaitGroup
	stopped        bool
	shared         *browserSharedLearning
}

func newYoutubeRuntime() *youtubeRuntime {
	r := &youtubeRuntime{cache: map[youtubeKey]youtubeLearn{}, engines: map[string]youtubeEngine{}, stats: map[string]youtubeStage{}, records: map[uint64]youtubeRecord{}, qualifications: map[youtubeQualification]time.Time{}, sustained: map[youtubeQualification]time.Time{}, scores: map[youtubeScoreKey]youtubeScore{}, pending: map[youtubeKey]youtubePending{}}
	r.shared = newSharedLearning()
	r.selection.Contract = "max1 unproven CDN trial; 3min/subgroup except at most 3 consecutive neutral short probes; same network/profile live/recent30s RELAY media required; same scoped transform; LOCAL10min after running >=1MiB/16 completed TLS type23 records/3s RX span, or 3 weaker closed sustained flows; late real failure revokes future LOCAL; no playback proof/replay"
	plans, _ := localstrategy.BundledCatalog().Compile()
	r.setPlans(plans)
	return r
}
func youtubeLadderEligible(q browserproxy.Request, p browserproxy.Plan) bool {
	return localBrowserRequestEligible(q, p) && originpolicy.Floor(q.Host).Kind == "DPI"
}

func (c *Controller) youtubeLocalAllowed(network string) bool {
	n := c.network.Load()
	return network != "" && n != nil && n.Fingerprint == network && n.Error == "" && time.Since(n.ObservedAt) < 45*time.Second && len(n.VPN) == 0 && len(n.Conflicts) == 0 && !n.ConflictsObservedAt.IsZero() && time.Since(n.ConflictsObservedAt) < 3*time.Minute
}
func youtubeScope(cur profilesResult, q browserproxy.Request) youtubeKey {
	return youtubeKey{Network: cur.network, Profile: cur.profile.ID, Domain: youtubeSubgroup(q.Host), Port: q.Port, HintOnly: q.HintOnly}
}
func (r *youtubeRuntime) choose(k youtubeKey, now time.Time) (string, string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.cache[k].route(k.Network, now)
}

func (v youtubeLearn) route(network string, now time.Time) (string, string) {
	if network != "" && now.Before(v.Until) && (v.Stage == "LOCAL" || v.Stage == "DIRECT") {
		return v.Stage, v.Strategy
	}
	return "RELAY", ""
}
func (r *youtubeRuntime) failed(k youtubeKey, stage, strategy, reason string, now time.Time) {
	if k.Network == "" || stage == "RELAY" {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.room(k, now) {
		return
	}
	v := r.cache[k]
	if stage == "LOCAL" {
		if v.Reason == cdnPeerProvisionalReason {
			r.selection.PeerProvisionalFailures++
		}
		r.peerFlowFailedLocked(k, strategy, reason, now)
		r.score(k, strategy, false, now)
		for i, id := range r.order {
			if id == strategy {
				v.Next = (i + 1) % len(r.order)
				v.Tried |= 1 << uint(i)
			}
		}
		v.Failures++
	}
	v.Stage = "RELAY"
	v.Strategy = ""
	v.Qualified = ""
	v.Streak = 0
	v.alternateTrialStreak = cdnTrialStreak{}
	v.NeutralShortStreak = 0
	v.Confirmed = false
	v.Retry = now.Add(youtubeBackoff(v.Failures))
	if youtubeCDN(k) {
		v.TrialAfter = now.Add(youtubeTrialCooldown)
		if v.Retry.Before(v.TrialAfter) {
			v.Retry = v.TrialAfter
		}
	}
	v.Until = now.Add(youtubeLearnTTL)
	v.Reason = reason
	r.cache[k] = v
	r.shared.reject(k, strategy)
}
func (r *youtubeRuntime) confirmed(k youtubeKey, stage, strategy string, now time.Time) {
	if k.Network == "" {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.room(k, now) {
		return
	}
	if stage == "LOCAL" {
		r.score(k, strategy, true, now)
		r.renewPeerProofLocked(k, strategy, now)
	}
	streak := uint32(0)
	if old := r.cache[k]; old.Confirmed && old.Stage == stage && old.Strategy == strategy && now.Before(old.Until) {
		streak = old.Streak
	}
	old := r.cache[k]
	v := youtubeLearn{Stage: stage, Strategy: strategy, Until: now.Add(youtubeLearnTTL), Retry: now.Add(youtubeRetryAfter), Confirmed: true, Streak: streak, TrialChecks: old.TrialChecks, TrialDenials: old.TrialDenials, LastTrialCheck: old.LastTrialCheck, TrialAdmission: old.TrialAdmission, Sibling: old.Sibling, SiblingWaits: old.SiblingWaits}
	if stage == "LOCAL" && youtubeCDN(k) {
		// A regular LOCAL flow can confirm while another endpoint's trial
		// for this subgroup is cooling down. Keep the trial state independent.
		v.Qualified = old.Qualified
		v.TrialAfter = old.TrialAfter
		if v.Retry.Before(v.TrialAfter) {
			v.Retry = v.TrialAfter
		}
		v.Tried = old.Tried
		v.Next = old.Next
		v.cdnTrialSlot = old.cdnTrialSlot
		v.NeutralShortStreak = old.NeutralShortStreak
	}
	r.cache[k] = v
}
func (r *youtubeRuntime) snapshot() youtubeSnapshot {
	r.mu.Lock()
	defer r.mu.Unlock()
	s := youtubeSnapshot{RecordsOmitted: r.seq - uint64(len(r.records)), CacheEntries: len(r.cache), Cache: []youtubeCacheView{}, Stages: []youtubeStage{}, Records: []youtubeRecord{}, Shared: r.shared.snapshot(), Selection: r.selection, Replays: "complete ClientHello only before ANY origin byte; established TLS pinned; transport health is not HTTP/playback PASS"}
	for _, until := range r.peerProofs {
		if time.Now().Before(until) {
			s.Selection.PeerProofs++
		}
	}
	if r.trialActive {
		s.Selection.ActiveTrialID = r.trialID
		s.Selection.ActiveRecordID = r.trialRecord
		s.Selection.ActiveHost = r.trialEndpoint.Host
		s.Selection.ActiveDestination = r.trialEndpoint.Address
		s.Selection.ActiveStartedAt = r.trialStarted
		s.Selection.ActiveDomain = r.trialKey.Domain
		s.Selection.ActiveAgeMS = time.Since(r.trialStarted).Milliseconds()
		s.Selection.ActiveLastRXAgeMS = -1
		s.Selection.ActiveState = "OPENING_TRIAL"
		if v, ok := r.records[r.trialRecord]; ok {
			s.Selection.ActiveRecordMatches = v.TrialID == r.trialID
			s.Selection.ActiveRecordResult = v.TrialResult
			s.Selection.ActiveState = "SHORT_REPLY_WAITING_TERMINAL"
			if v.TX == 0 {
				s.Selection.ActiveState = "PRECONNECT_NO_CLIENT_BYTES"
			} else if v.RX == 0 {
				s.Selection.ActiveState = "WAITING_ORIGIN_REPLY"
			}
			if v.Reason == "SUSTAINED_TLS_TRANSPORT_NOT_PLAYBACK_PROOF" {
				s.Selection.ActiveState = "SUSTAINED_WAITING_TERMINAL"
			}
			if !v.LastRX.IsZero() {
				s.Selection.ActiveLastRXAgeMS = time.Since(v.LastRX).Milliseconds()
			}
		}
	}
	for k, v := range r.cache {
		if len(s.Cache) < 24 {
			admission := v.TrialAdmission
			if v.LastTrialCheck.IsZero() {
				admission = "NO_ELIGIBLE_NEW_FLOW_CHECK"
			}
			s.Cache = append(s.Cache, youtubeCacheView{v.cdnTrialSlot, v.NeutralShortStreak, max(int64(0), time.Until(v.TrialAfter).Milliseconds()), k.HintOnly, k.Network, k.Profile, k.Domain, v.Stage, v.Strategy, v.Reason, k.Port, v.Until, v.Retry, v.Tried, v.Streak, v.Qualified, admission, v.TrialChecks, v.TrialDenials, v.LastTrialCheck, v.TrialAfter, v.Sibling, v.SiblingWaits})
		}
	}
	for _, v := range r.stats {
		s.Stages = append(s.Stages, v)
	}
	sort.Slice(s.Stages, func(i, j int) bool {
		return s.Stages[i].Stage+s.Stages[i].Strategy < s.Stages[j].Stage+s.Stages[j].Strategy
	})
	for _, v := range r.records {
		s.Records = append(s.Records, v)
	}
	sort.Slice(s.Records, func(i, j int) bool {
		if s.Records[i].Active != s.Records[j].Active {
			return s.Records[i].Active
		}
		return s.Records[i].Updated.After(s.Records[j].Updated)
	})
	s.CacheOmitted = len(r.cache) - len(s.Cache)
	if len(s.Records) > 24 {
		s.RecordsOmitted += uint64(len(s.Records) - 24)
		s.Records = s.Records[:24]
	}
	return s
}
func (c *Controller) youtubeEngine(cur profilesResult, q browserproxy.Request, p browserproxy.Plan, candidate string) (string, *localstrategy.LocalStrategyEngine) {
	if !c.youtubeLocalAllowed(cur.network) {
		return "", nil
	}
	if candidate == "baseline" {
		return c.browserScopedLocal(cur.profile, q.Host, cur.network, q.Port)
	}
	var actions []localstrategy.Action
	preset := "youtube"
	c.browser.youtube.mu.Lock()
	cp, catalog := c.browser.youtube.plans[candidate]
	c.browser.youtube.mu.Unlock()
	if catalog {
		actions = append(actions, cp.Actions...)
		preset = "browser-catalog"
	}
	for _, v := range localstrategy.BrowserYouTubeCandidates() {
		if v.ID == candidate {
			actions = append([]localstrategy.Action(nil), v.Actions...)
		}
	}

	if len(actions) == 0 {
		return "", nil
	}
	// A DNS association is not authenticated SNI. Bind exactly this destination,
	// never claim TrustedOrigin, and use absolute segmentation for hidden SNI.
	domains := []string{q.Host}
	var ips []string
	if q.HintOnly {
		domains = nil
		ips = []string{p.Destination.Addr().String() + "/32"}
		for i := range actions {
			if actions[i].Kind == "tcp-multisplit" {
				actions[i].Anchor = ""
				actions[i].Markers = nil
				actions[i].Positions = []uint16{1, 5}
			}
		}
	}
	raw := cur.network + cur.profile.ID + q.Owner.Exe + q.Host + p.Destination.String() + candidate
	if q.HintOnly {
		raw += "|EXACT_IP_HINT_ABSOLUTE_SPLIT"
	} else {
		raw += "|OBSERVED_OR_CONNECT_NAME"
	}
	sum := sha256.Sum256([]byte(raw))
	id := "yt-" + hex.EncodeToString(sum[:12])
	r := c.browser.youtube
	r.mu.Lock()
	defer r.mu.Unlock()
	now := time.Now()
	for key, v := range r.engines {
		if now.After(v.Until) {
			delete(r.engines, key)
		}
	}
	if v, ok := r.engines[id]; ok {
		return id, v.Engine
	}
	if len(r.engines) >= 256 {
		return "", nil
	}
	engine := localstrategy.New()
	profile := localstrategy.Profile{ID: id, Name: "Browser LOCAL / " + candidate, Version: 1, Application: q.Owner.Exe, Protocol: "tcp", Ports: []uint16{443}, Domains: domains, IPs: ips, Strategy: "chain", Actions: actions, Preset: preset, PresetVersion: localstrategy.PresetVersion, Cutoff: 1, Enabled: true}
	if engine.Reload(localstrategy.Config{Version: 1, Enabled: true, User: []localstrategy.Profile{profile}}) != nil {
		return "", nil
	}
	engine.Guard = func(m localstrategy.Metadata) bool { return c.youtubeLocalAllowed(cur.network) }
	r.engines[id] = youtubeEngine{engine, now.Add(youtubeLearnTTL)}
	return id, engine
}
func (r *youtubeRuntime) engine(id string) *localstrategy.LocalStrategyEngine {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.engines[id].Engine
}

type youtubePlanRef struct {
	mu     sync.Mutex
	plan   browserproxy.Plan
	origin browserproxy.OriginReporter
}

func (r *youtubePlanRef) set(p browserproxy.Plan, conn net.Conn) {
	r.mu.Lock()
	r.plan = p
	r.origin, _ = conn.(browserproxy.OriginReporter)
	r.mu.Unlock()
}

type youtubePlanConn struct {
	net.Conn
	ref *youtubePlanRef
}

func (c *youtubePlanConn) CurrentPlan() browserproxy.Plan {
	c.ref.mu.Lock()
	p, origin := c.ref.plan, c.ref.origin
	c.ref.mu.Unlock()
	if origin != nil {
		report := origin.OriginAttempts()
		if addr, e := netip.ParseAddrPort(report.Selected); e == nil {
			p = browserproxy.RetargetOrigin(p, addr)
		}
	}
	return p
}
func (c *youtubePlanConn) OriginAttempts() browserproxy.OriginReport {
	c.ref.mu.Lock()
	p, origin := c.ref.plan, c.ref.origin
	c.ref.mu.Unlock()
	if origin != nil {
		return origin.OriginAttempts()
	}
	return browserproxy.OriginReport{Selected: p.Destination.String(), State: "YOUTUBE_LOCAL_LADDER_NO_RELAY_IP_RECOVERY"}
}

func (c *youtubePlanConn) CurrentTCPPolicy() (flowpolicy.Result, bool) {
	return c.CurrentPlan().Policy, true
}
func (c *youtubePlanConn) CloseWrite() error {
	if v, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return v.CloseWrite()
	}
	return nil
}

// Caller holds r.mu. Keep the currently admitted trial available to its meter.
func (r *youtubeRuntime) addYoutubeRecordLocked(record youtubeRecord) uint64 {
	r.seq++
	record.ID = r.seq
	if len(r.records) >= 96 {
		old := record.ID
		for id := range r.records {
			if id < old && id != r.trialRecord {
				old = id
			}
		}
		delete(r.records, old)
	}
	r.records[record.ID] = record
	return record.ID
}

func (c *Controller) openYoutubeLadder(ctx context.Context, cur profilesResult, q browserproxy.Request, p browserproxy.Plan, open func(context.Context, browserproxy.Request, browserproxy.Plan) (net.Conn, error)) (net.Conn, browserproxy.Plan, error) {
	cur = c.captureAutomaticScope(cur)
	if !c.automaticScopeCurrent(cur) {
		return nil, p, errAutomaticScopeChanged
	}
	open = c.automaticScopedOpen(cur, open)
	r := c.browser.youtube
	if c.catalog != nil {
		r.setPlans(c.catalog.snapshot().Plans)
	}
	ref := &youtubePlanRef{}
	service := c.browserOriginPolicy(q.Host).Group
	if riotAuto(cur.profile) && riotHost(q.Host) {
		service = "riot-client"
	}
	if service == "" {
		service = "ordinary"
	}
	key := youtubeScope(cur, q)
	r.register(key, cur, q, p, time.Now())
	r.shared.notify()
	endpoint := cdnEndpoint{q.Host, p.Destination.String()}
	stage, strategy, decisionReason, selection := r.chooseEndpointWithReason(key, endpoint, time.Now())
	if stage == "RELAY" && p.Policy.Source == "configured_baseline" && p.Policy.Action == flowpolicy.DirectPlus {
		stage = "LOCAL"
		strategy = "baseline"
		decisionReason = "CONFIGURED_BASELINE"
	}
	c.youtubeBackgroundRecheck(cur, q, p, key)
	trial := false
	trialID := uint64(0)
	admission := "NOT_NEEDED"
	trialPeer := relaySiblingEvidence{AgeMS: -1, Reason: "NOT_A_CDN_TRIAL"}
	if stage == "RELAY" {
		peer := c.relayUsage().mediaTrialSibling(cur.profile.ID, cur.network, q.Host, time.Now())
		candidate, token, reason, evidence := r.decideEndpointTrial(key, time.Now(), peer, endpoint)
		admission = reason
		selection.Trial = &evidence
		if token != 0 {
			trialID = token
			trialPeer = peer
			stage = "LOCAL"
			strategy = candidate
			trial = true
		}
	}
	decision := r.startCDNDecision(q, cdnDecisionEvent{
		Destination: endpoint.Address, Stage: stage, Strategy: strategy, Reason: decisionReason, Admission: admission, TrialID: trialID,
		Selection: &selection,
	})
	var step func(context.Context, string, string, int, string) (net.Conn, browserproxy.Plan, error)
	step = func(work context.Context, stage, strategy string, depth int, fallbackReason string) (net.Conn, browserproxy.Plan, error) {
		if !c.automaticScopeCurrent(cur) {
			if trial {
				r.finishTrialOutcomeFor(trialID, key, strategy, "INCONCLUSIVE", false, time.Now(), 0)
			}
			return nil, p, errAutomaticScopeChanged
		}
		actual := p
		actual.FirstFlightManaged = true
		actual.DirectCandidates = nil
		actual.DirectDeadline = time.Time{}
		actual.Probe = "YOUTUBE_LOCAL_LADDER"
		actual.Policy = flowpolicy.Result{Action: flowpolicy.Direct, Fallback: flowpolicy.FailBlock, Source: youtubeLadderSource, Reason: "Unproven subgroup uses authenticated RELAY; LOCAL only after bounded verified selection; no replay after origin bytes"}
		if stage == "LOCAL" {
			id, _ := c.youtubeEngine(cur, q, actual, strategy)
			if id == "" {
				if !c.automaticScopeCurrent(cur) {
					if trial {
						r.finishTrialOutcomeFor(trialID, key, strategy, "INCONCLUSIVE", false, time.Now(), 0)
					}
					return nil, actual, errAutomaticScopeChanged
				}
				r.failed(key, "LOCAL", strategy, "LOCAL_GUARD_OR_CAPACITY", time.Now())
				if trial {
					r.finishTrialOutcomeFor(trialID, key, strategy, "FAILED", false, time.Now(), 0)
					trial = false
				}
				r.mu.Lock()
				v, exists := r.cache[key]
				if exists {
					v.Retry = time.Now().Add(5 * time.Second)
					v.Tried = 0
					r.cache[key] = v
				}
				r.mu.Unlock()
				return step(work, "RELAY", "", depth+1, "LOCAL_GUARD_OR_CAPACITY")
			}
			actual.Policy.Action = flowpolicy.DirectPlus
			actual.Policy.Strategy = id
		}
		if stage == "RELAY" {
			actual = stallRetryPlan(cur, actual)
			actual.Policy.Source = youtubeLadderSource
			actual.FirstFlightManaged = true
			actual.Probe = "YOUTUBE_LOCAL_LADDER"
			if fallbackReason == "" {
				actual.Policy.Reason = "RELAY selected (" + decisionReason + ", local_admission=" + admission + ")"
			} else {
				actual.Policy.Reason = "RELAY fallback (" + fallbackReason + ")"
			}
		}
		budget := 650 * time.Millisecond
		if stage == "RELAY" {
			budget = 5 * time.Second
		}
		openStarted := time.Now()
		attempt, cancel := context.WithTimeout(work, budget)
		var conn net.Conn
		var err error
		if stage == "RELAY" {
			reason := actual.Policy.Reason
			conn, actual, err = c.openKnownBrowserGroup(attempt, cur, q, actual, open)
			actual.Policy.Reason = reason
			actual.FirstFlightManaged = true
		} else {
			conn, err = open(attempt, q, actual)
		}
		cancel()
		if !c.automaticScopeCurrent(cur) {
			if conn != nil {
				_ = conn.Close()
			}
			if trial {
				r.finishTrialOutcomeFor(trialID, key, strategy, "INCONCLUSIVE", false, time.Now(), 0)
			}
			return nil, actual, errAutomaticScopeChanged
		}
		r.mu.Lock()
		record := r.addYoutubeRecordLocked(youtubeRecord{cdnTrialSlot: cdnTrialSlot{TrialID: trialID, NeutralShortAttempt: r.cache[key].NeutralShortStreak + 1}, OpenMS: milliseconds(time.Since(openStarted)), Service: service, Active: err == nil, Profile: cur.profile.ID, Domain: q.Host, Destination: actual.Destination.String(), Stage: stage, Strategy: strategy, Reason: "OPEN", Trial: trial && stage == "LOCAL", Updated: time.Now()})
		if trial && stage == "LOCAL" {
			r.trialRecord = record
		}
		if decision.ConnectionID != 0 {
			openEvent := decision
			openEvent.Selection = nil
			openEvent.RecordID = record
			openEvent.Stage = stage
			openEvent.Strategy = strategy
			openEvent.Destination = actual.Destination.String()
			openEvent.Reason = fallbackReason
			openEvent.Phase = "OPENED"
			if err != nil {
				openEvent.Phase = "OPEN_FAILED"
			}
			r.addCDNDecisionLocked(openEvent)
		}
		label := service + ":" + stage + ":" + strategy
		if _, exists := r.stats[label]; !exists && len(r.stats) >= 128 {
			label = "other:" + stage + ":CATALOG_OVERFLOW"
			service = "other"
		}
		stats := r.stats[label]
		stats.Service = service
		stats.Stage = stage
		stats.Strategy = strategy
		stats.Connections++
		if err != nil {
			stats.Failures++
			v := r.records[record]
			v.Reason = "OPEN_FAILED"
			r.records[record] = v
		}
		r.stats[label] = stats
		r.mu.Unlock()
		next := func(nextCtx context.Context, reason string) (net.Conn, error) {
			if stage == "RELAY" || depth >= 2 {
				return nil, errors.New("YOUTUBE_LADDER_EXHAUSTED")
			}
			nextStage, nextStrategy := "RELAY", ""
			n, _, e := step(nextCtx, nextStage, nextStrategy, depth+1, reason)
			return n, e
		}
		if err != nil {
			if trial && stage == "LOCAL" && work.Err() != nil {
				r.finishTrialOutcomeFor(trialID, key, strategy, "FAILED", false, time.Now(), 0)
			}
			if work.Err() != nil {
				return nil, actual, work.Err()
			}
			if stage != "LOCAL" || !r.endpointFailed(key, strategy, cdnEndpoint{q.Host, actual.Destination.String()}, "OPEN_FAILED", time.Now()) {
				r.failed(key, stage, strategy, "OPEN_FAILED", time.Now())
			}
			if trial && stage == "LOCAL" {
				r.finishTrialOutcomeFor(trialID, key, strategy, "FAILED", false, time.Now(), 0)
			}
			if stage == "RELAY" {
				return nil, actual, err
			}
			conn, err = next(work, "OPEN_FAILED")
			if err == nil {
				ref.mu.Lock()
				actual = ref.plan
				ref.mu.Unlock()
			}
			return conn, actual, err
		}
		ref.set(actual, conn)
		observer := &youtubeMeter{trialID: trialID, trial: trial && stage == "LOCAL", Conn: conn, r: r, id: record, label: label, key: key, stage: stage, strategy: strategy, started: time.Now(), host: q.Host, destination: actual.Destination.String(), sibling: trialPeer, inspection: func() *localstrategy.Inspection { return c.localPacketInspection(q, actual) }, transform: func() bool { return c.browserTransform(q, actual) }}
		if automaticApplication(cur.profile) {
			observer.recoveryCurrent = func() bool { return c.automaticScopeCurrent(cur) }
		}
		observer.slot.NeutralShortAttempt = r.cacheAttempt(key)
		observer.slot.TrialID = trialID
		observer.recordTrialEvidence(true)
		if stage == "RELAY" {
			return observer, actual, nil
		}
		monitored := browserproxy.WatchMidstream(observer, 6*time.Second, func() { observer.failure("MIDSTREAM_STALL_NEW_CONNECTION_REQUIRED") })
		timeout := 400 * time.Millisecond
		if stage == "LOCAL" {
			timeout = 900 * time.Millisecond
		}
		conn = browserproxy.WatchRelayOrigin(monitored, browserproxy.OriginConfig{
			Context: c.ctx, Health: browserproxy.NewOriginHealth(), Silence: timeout,
			NextFlow: next, OnFailure: observer.failure,
		})
		return conn, actual, nil
	}
	conn, actual, err := step(ctx, stage, strategy, 0, "")
	if err != nil {
		return nil, actual, err
	}
	return &youtubePlanConn{Conn: conn, ref: ref}, actual, nil
}

type youtubeMeter struct {
	trialID            uint64
	recoveryCurrent    func() bool
	rememberLocalProof bool
	releaseProbe       func()
	releaseProbeOnce   sync.Once
	net.Conn
	r                               *youtubeRuntime
	id                              uint64
	label                           string
	key                             youtubeKey
	stage, strategy                 string
	started                         time.Time
	inspection                      func() *localstrategy.Inspection
	closing                         bool
	neutral                         bool
	neutralCounted                  bool
	halfClosed                      bool
	firstClientWrite, serverHelloAt time.Time
	lastClientWrite                 time.Time
	rxAtLastWrite                   uint64
	transform                       func() bool
	mu                              sync.Mutex
	wire                            browserproxy.TLSWireObserver
	tx, rx                          uint64
	healthy                         bool
	postHelloWrite                  bool
	applied, witnessChecked         bool
	lastReply                       time.Time
	trial                           bool
	promoted                        bool
	firstApplicationRX              time.Time
	dataObserved                    bool
	host, destination               string
	failureReason                   string
	trialFinalized                  bool
	sibling                         relaySiblingEvidence
	smallEOF                        bool
	slot                            cdnTrialSlot
	trialDone                       sync.Once
	failed                          bool
	gap                             sync.Once
	bad                             sync.Once
}

func (m *youtubeMeter) recoveryScopeCurrent() bool {
	return m.recoveryCurrent == nil || m.recoveryCurrent()
}

func (m *youtubeMeter) failure(reason string) {
	if m.releaseProbe != nil {
		m.releaseProbeOnce.Do(m.releaseProbe)
	}
	if !m.recoveryScopeCurrent() {
		// An obsolete automatic flow is not a LOCAL failure verdict. Keep the
		// stream's counters, but never demote the old scope or launch a new route.
		m.r.mu.Lock()
		if record, ok := m.r.records[m.id]; ok {
			record.Reason = "AUTOMATIC_SCOPE_CHANGED"
			m.r.records[m.id] = record
		}
		m.r.mu.Unlock()
		if m.trial {
			m.trialDone.Do(func() {
				m.mu.Lock()
				defer m.mu.Unlock()
				m.finishTrialLocked("INCONCLUSIVE", time.Now())
			})
		}
		return
	}
	if strings.Contains(reason, "EOF") && (m.noteClientClose() || m.noteSmallEOF()) {
		// The first-flight wrapper may report EOF without another meter.Read.
		// Finalize here, not only on Read/Close, or max1 remains held indefinitely.
		m.finishObservation()
		m.updateCloseRecord()
		return
	}
	m.bad.Do(func() {
		m.mu.Lock()
		if m.stage == "LOCAL" && !m.witnessChecked && m.tx > 0 && m.transform != nil {
			m.witnessChecked = true
			m.applied = m.transform()
		}
		m.failed = true
		m.failureReason = reason
		applied, known := m.applied, m.witnessChecked
		promoted := m.promoted
		finalized := m.trialFinalized
		failure := m.failureEvidenceLocked(reason, time.Now())
		m.mu.Unlock()
		if m.stage != "LOCAL" || !m.r.endpointFailed(m.key, m.strategy, cdnEndpoint{m.host, m.destination}, reason, time.Now()) {
			m.r.failed(m.key, m.stage, m.strategy, reason, time.Now())
		}
		m.r.mu.Lock()
		defer m.r.mu.Unlock()
		if m.stage == "LOCAL" {
			m.r.failures = append(m.r.failures, failure)
			if len(m.r.failures) > 32 {
				m.r.failures = append([]localFailureEvidence(nil), m.r.failures[len(m.r.failures)-32:]...)
			}
		}
		if m.trial && finalized && !promoted {
			m.r.selection.PostTrialFailures++
			if failure.RX > 0 {
				m.r.selection.FailedAfterReply++
			}
		}
		if promoted {
			m.r.selection.PostPromotionFailures++
			m.r.selection.FailedAfterReply++
		}
		s := m.r.stats[m.label]
		s.Failures++
		m.r.stats[m.label] = s
		if v, ok := m.r.records[m.id]; ok {
			if m.inspection != nil {
				v.Inspection = m.inspection()
			}
			v.Reason = reason
			v.Failure = &failure
			if promoted {
				v.TrialResult = "SUCCESS_REVOKED_AFTER_FAILURE"
			}
			if strings.Contains(reason, "STALL") || strings.Contains(reason, "TIMEOUT") || strings.Contains(reason, "SILENT") || strings.Contains(reason, "BUDGET") {
				v.IOFailure = "TIMEOUT"
			}
			v.Transform = applied
			v.TransformKnown = known
			v.Updated = time.Now()
			m.r.records[m.id] = v
		}
	})
	if m.trial {
		m.finishObservation()
	}
	m.recordTrialEvidence(true)
}
func (m *youtubeMeter) Write(p []byte) (int, error) {
	m.mu.Lock()
	if len(p) > 0 && m.firstClientWrite.IsZero() {
		m.firstClientWrite = time.Now()
	}
	m.mu.Unlock()
	afterHello := m.wire.Snapshot().Origin.ServerHelloComplete
	n, e := m.Conn.Write(p)
	if n > 0 {
		m.mu.Lock()
		m.lastClientWrite = time.Now()
		m.rxAtLastWrite = m.rx
		m.postHelloWrite = m.postHelloWrite || afterHello
		m.mu.Unlock()
	}
	m.wire.ObserveClient(p[:n])
	m.account(uint64(n), 0)
	return n, e
}
func (m *youtubeMeter) Read(p []byte) (int, error) {
	n, e := m.Conn.Read(p)
	m.wire.ObserveOrigin(p[:n])
	m.account(0, uint64(n))
	if n == 0 && isYoutubeTimeout(e) {
		now := time.Now()
		m.progressGap(now)
		m.maybePromoteTrial(now)
		m.releaseIdleShortTrial(now)
	}
	v := m.wire.Snapshot().Origin
	if v.AlertLevel != 0 || v.State == "NON_TLS_OR_INVALID_HEADER" {
		m.failure("EARLY_TLS_ALERT_OR_INVALID_HEADER_NO_REPLAY")
	}
	if e != nil && !errors.Is(e, net.ErrClosed) {
		m.mu.Lock()
		spoken := m.tx > 0 && !m.closing
		healthy := m.healthy
		failedAlready := m.failed
		m.mu.Unlock()
		if spoken && !healthy && errors.Is(e, io.EOF) && v.ServerHelloComplete && !m.trial {
			m.r.mu.Lock()
			control := m.r.cache[m.key]
			if control.Confirmed && control.Stage == "LOCAL" && control.Strategy == m.strategy && time.Now().Before(control.Until) && strings.HasPrefix(control.Reason, "BACKGROUND_PUBLIC_") && strings.HasSuffix(control.Reason, "_NOT_BULK_PROOF") {
				if record, ok := m.r.records[m.id]; ok {
					record.Reason = "SHORT_TLS_CLOSE_WITH_PUBLIC_CONTROL_PROOF"
					m.r.records[m.id] = record
				}
				m.r.mu.Unlock()
				return n, e
			}
			m.r.mu.Unlock()
		}
		if spoken && (!healthy && errors.Is(e, io.EOF) || !errors.Is(e, io.EOF) && !isYoutubeTimeout(e)) {
			code := "READ_IO_ERROR"
			if errors.Is(e, io.EOF) {
				code = "REMOTE_EOF"
			} else if errors.Is(e, syscall.ECONNRESET) || errors.Is(e, syscall.Errno(10054)) {
				code = "REMOTE_RESET"
			}
			m.r.mu.Lock()
			if record, ok := m.r.records[m.id]; ok && !failedAlready {
				record.IOFailure = code
				m.r.records[m.id] = record
			}
			m.r.mu.Unlock()
			if errors.Is(e, io.EOF) && (m.noteClientClose() || m.noteSmallEOF()) { /* neither negative proof nor sustained success */
			} else {
				reason := "REMOTE_IO_ERROR"
				if code == "REMOTE_RESET" {
					reason = "REMOTE_RST"
				} else if errors.Is(e, io.EOF) {
					reason = "REMOTE_EOF_AFTER_REPLY"
					m.mu.Lock()
					if m.rx == 0 {
						reason = "REMOTE_EOF_BEFORE_REPLY"
					}
					m.mu.Unlock()
				}
				m.failure(reason)
			}
		}
	}
	if isTCPReset(e) {
		m.mu.Lock()
		closing := m.closing
		m.mu.Unlock()
		if !closing {
			m.failure("REMOTE_RST")
		}
	}
	if n > 0 && (e == nil || errors.Is(e, io.EOF)) {
		m.maybePromoteTrial(time.Now())
	}
	if e != nil && !isYoutubeTimeout(e) {
		trace := m.currentInspection()
		if isTCPReset(e) || errors.Is(e, io.EOF) && m.trial || trace != nil && trace.TCPPackets.ClientFIN > 0 && trace.TCPPackets.RemoteFIN > 0 {
			m.finishObservation()
			m.updateCloseRecord()
		}
	}
	return n, e
}
func isYoutubeTimeout(e error) bool { var n net.Error; return errors.As(e, &n) && n.Timeout() }
func (m *youtubeMeter) account(tx, rx uint64) {
	scopeCurrent := m.recoveryScopeCurrent()
	m.mu.Lock()
	m.tx += tx
	m.rx += rx
	if rx > 0 {
		m.lastReply = time.Now()
	}
	snapshot := m.wire.Snapshot()
	hello := snapshot.Origin.ServerHelloComplete
	firstHello := hello && m.serverHelloAt.IsZero()
	if firstHello {
		m.serverHelloAt = time.Now()
	}
	if rx > 0 && snapshot.Origin.ApplicationBytes > 0 && m.firstApplicationRX.IsZero() {
		m.firstApplicationRX = time.Now()
	}
	timing := m.timingLocked(nil, time.Time{})
	lastRX := m.lastReply
	dataObserved := m.dataObserved
	if m.stage == "LOCAL" && !m.witnessChecked && m.tx > 0 && rx > 0 {
		m.witnessChecked = true
		m.applied = m.transform()
	}
	transformed := m.stage != "LOCAL" || m.applied

	dataStarted := scopeCurrent && m.trial && !m.trialFinalized && !m.dataObserved && !m.failed && m.applied && m.postHelloWrite && hello && snapshot.Origin.ApplicationBytes >= cdnDataTrialBytes
	if dataStarted {
		m.dataObserved = true
	}
	confirmed := scopeCurrent && !m.failed && !m.healthy && hello && m.rx > 64*1024 && m.tx > 0 && m.postHelloWrite && transformed
	if confirmed {
		m.healthy = true
	}
	m.mu.Unlock()
	if firstHello && m.releaseProbe != nil {
		m.releaseProbeOnce.Do(m.releaseProbe)
	}
	if confirmed && m.stage != "RELAY" && !m.trial && m.recoveryScopeCurrent() {
		now := time.Now()
		m.r.confirmed(m.key, m.stage, m.strategy, now)
		m.mu.Lock()
		verified := m.rx
		m.mu.Unlock()
		m.r.recordVerification(m.key, verified)
		if m.rememberLocalProof {
			m.r.mu.Lock()
			if !m.r.endpointBlockedLocked(m.key, m.strategy, cdnEndpoint{m.host, m.destination}, now) {
				m.r.notePeerProofLocked(m.key, m.strategy, now)
			}
			m.r.mu.Unlock()
		}
	}
	m.r.mu.Lock()
	s := m.r.stats[m.label]
	if dataStarted {
		m.r.selection.DataTrials++
	}
	if firstHello && timing.ClientHelloToServerHelloMS >= 0 {
		v := uint64(timing.ClientHelloToServerHelloMS)
		s.HelloSamples++
		s.HelloSumMS += v
		if v > s.HelloMaxMS {
			s.HelloMaxMS = v
		}
	}
	s.TX += tx
	s.RX += rx
	if confirmed {
		s.Confirmed++
	}
	m.r.stats[m.label] = s
	if v, ok := m.r.records[m.id]; ok {
		v.Timing = timing
		v.LastRX = lastRX
		v.TX += tx
		v.RX += rx
		v.ServerHello = hello
		v.DataTrial = dataObserved
		if dataStarted {
			v.TrialResult = "DATA_OBSERVED_WAITING_SUSTAINED"
		}
		v.Transform = m.stage == "LOCAL" && transformed
		v.TransformKnown = m.stage != "LOCAL" || m.witnessChecked
		if confirmed {
			v.Reason = "SUSTAINED_TLS_TRANSPORT_NOT_PLAYBACK_PROOF"
		}
		v.Updated = time.Now()
		m.r.records[m.id] = v
	}
	m.r.mu.Unlock()
}
func (m *youtubeMeter) CloseWrite() error {
	m.mu.Lock()
	m.halfClosed = true
	m.mu.Unlock()
	if c, ok := m.Conn.(interface{ CloseWrite() error }); ok {
		return c.CloseWrite()
	}
	return nil
}

// A quiet encrypted response cannot be distinguished from a completed HTTP/2
// response without MITM. This is a short-lived hint for NEW connections only:
// do not close, move or replay the current TLS session on this observation.
func (m *youtubeMeter) progressGap(now time.Time) {
	if m.stage == "RELAY" || !m.recoveryScopeCurrent() {
		return
	}
	m.mu.Lock()
	gap := !m.healthy && m.tx > 0 && m.rx >= 8*1024 && m.rx < 64*1024 && !m.lastReply.IsZero() && now.Sub(m.lastReply) >= 4*time.Second
	m.mu.Unlock()
	if !gap {
		return
	}
	m.r.mu.Lock()
	positive := m.r.cache[m.key]
	m.r.mu.Unlock()
	if positive.Confirmed && positive.Stage == m.stage && positive.Strategy == m.strategy {
		return
	}
	m.gap.Do(func() {
		m.r.mu.Lock()
		v := m.r.cache[m.key]
		if v.Stage == "" {
			v.Stage = "RELAY"
			v.Until = now.Add(youtubeLearnTTL)
		}
		v.Reason = "EARLY_PROGRESS_GAP_HINT_NOT_HTTP_FAILURE"
		if m.r.room(m.key, now) {
			m.r.cache[m.key] = v
		}
		m.r.mu.Unlock()
		m.r.mu.Lock()
		if v, ok := m.r.records[m.id]; ok {
			v.Reason = "EARLY_PROGRESS_GAP_HINT_NEXT_CONNECTION_ONLY"
			m.r.records[m.id] = v
		}
		m.r.mu.Unlock()
	})
}

func (m *youtubeMeter) Close() error {
	if m.releaseProbe != nil {
		m.releaseProbeOnce.Do(m.releaseProbe)
	}
	// Inspect before our own Close emits FIN, so that we cannot fabricate neutral proof.
	if trace := m.currentInspection(); trace != nil && trace.TCPPackets.RemoteRST > 0 {
		m.failure("REMOTE_RST")
	}
	m.noteClientClose()
	m.mu.Lock()
	m.closing = true
	m.mu.Unlock()
	err := m.Conn.Close()
	m.finishObservation()
	m.updateCloseRecord()
	return err
}
