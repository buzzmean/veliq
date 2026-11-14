// Package optimizer scores fresh route observations and selects routes for new flows.
package optimizer

import (
	"errors"
	"math"
	"net/netip"
	"sort"
	"sync"
	"time"
)

const Direct = "DIRECT"

type RelayCandidate struct {
	ID      string  `json:"id"`
	Address string  `json:"address,omitempty"`
	Region  string  `json:"region,omitempty"`
	City    string  `json:"city,omitempty"`
	Load    float64 `json:"load,omitempty"`
}
type RouteMeasurement struct {
	Target              netip.AddrPort `json:"-"`
	RouteAddress        string         `json:"-"`
	Network             string         `json:"-"`
	AuthenticatedTarget bool           `json:"-"`
	RouteID             string         `json:"route_id"`
	RTT                 time.Duration  `json:"rtt"`
	Jitter              time.Duration  `json:"jitter"`
	Loss                float64        `json:"loss"`
	FailureRate         float64        `json:"failure_rate"`
	Load                float64        `json:"load"`
	Stability           float64        `json:"stability"`
	Available           bool           `json:"available"`
	ObservedAt          time.Time      `json:"observed_at"`
	Samples             int            `json:"samples"`
	Probes              []ProbeSample  `json:"-"`
	ConsecutiveLoss     int            `json:"consecutive_loss,omitempty"`
	MaxLossBurst        int            `json:"max_loss_burst,omitempty"`
	TransportError      string         `json:"transport_error,omitempty"`
}
type RouteScore struct {
	ID          string           `json:"id"`
	Score       float64          `json:"score"`
	Measurement RouteMeasurement `json:"measurement"`
}
type RouteHistory struct {
	Measurements []RouteMeasurement `json:"measurements"`
	Changes      []Change           `json:"changes"`
}
type Change struct {
	From, To string
	At       time.Time
}
type Parameters struct {
	MinimumImprovement float64       `json:"minimum_improvement"`
	MinimumLifetime    time.Duration `json:"minimum_lifetime"`
	ConfirmationPeriod time.Duration `json:"confirmation_period"`
	MaxAge             time.Duration `json:"max_age"`
}

func DefaultParameters() Parameters {
	return Parameters{5, 30 * time.Second, 10 * time.Second, 90 * time.Second}
}
func validFraction(x float64) bool { return !math.IsNaN(x) && !math.IsInf(x, 0) && x >= 0 && x <= 1 }

// Score is in equivalent milliseconds. Loss/failure penalties dominate small RTT gains.
func Score(m RouteMeasurement) float64 {
	if !m.Available || m.Samples < 1 || m.RTT < 0 || m.Jitter < 0 || !validFraction(m.Loss) || !validFraction(m.FailureRate) || !validFraction(m.Load) || !validFraction(m.Stability) {
		return math.Inf(1)
	}
	return float64(m.RTT)/float64(time.Millisecond) + 2*float64(m.Jitter)/float64(time.Millisecond) + 4000*m.Loss + 2000*m.FailureRate + 15*m.Load + 20*(1-m.Stability)
}

type Selection struct {
	Primary   string       `json:"primary"`
	Secondary string       `json:"secondary"`
	Tertiary  string       `json:"tertiary"`
	Ranked    []RouteScore `json:"ranked"`
	Changed   bool         `json:"changed"`
	// Held names the reason the selector stayed on a faulted route instead of
	// moving to another route that is not healthy either.
	Held string `json:"held,omitempty"`
}
type RouteSelector struct {
	mu                                   sync.Mutex
	p                                    Parameters
	measurements                         map[string]RouteMeasurement
	quality                              map[string]*qualityState
	pendingRounds                        int
	pendingCandidateAt, pendingCurrentAt time.Time
	history                              RouteHistory
	current, pending                     string
	since, pendingSince                  time.Time
	guard                                FlapGuard
}

// FlapGuard is client-side switching damping. It is deliberately not part of the
// signed Parameters document: older clients parse that document strictly, and the
// damping must hold whatever the server publishes. The zero value disables it.
type FlapGuard struct {
	// RelativeImprovement: a voluntary switch must beat the current score by this
	// fraction of it (scores are in the thousands under loss; 5 units is noise).
	RelativeImprovement float64
	// After MaxChanges route changes within Window, a voluntary switch needs Dwell on
	// the current route. Faults still fail over immediately.
	Window     time.Duration
	MaxChanges int
	Dwell      time.Duration
	// HoldWithoutHealthyAlternative: when the current route is faulted and the only
	// candidate is measured unhealthy too, stay put instead of swapping faults.
	HoldWithoutHealthyAlternative bool
}

func DefaultFlapGuard() FlapGuard {
	return FlapGuard{RelativeImprovement: 0.2, Window: 30 * time.Minute, MaxChanges: 3, Dwell: 10 * time.Minute, HoldWithoutHealthyAlternative: true}
}
func (s *RouteSelector) SetFlapGuard(g FlapGuard) {
	s.mu.Lock()
	s.guard = g
	s.mu.Unlock()
}

// dwellLocked is the time a route must have been current before a voluntary switch.
func (s *RouteSelector) dwellLocked(now time.Time) time.Duration {
	dwell := s.p.MinimumLifetime
	if s.guard.MaxChanges > 0 && s.guard.Window > 0 {
		recent := 0
		for _, c := range s.history.Changes {
			if now.Sub(c.At) <= s.guard.Window {
				recent++
			}
		}
		if recent >= s.guard.MaxChanges && s.guard.Dwell > dwell {
			dwell = s.guard.Dwell
		}
	}
	return dwell
}

func New(p Parameters) *RouteSelector {
	if p.MinimumImprovement <= 0 {
		p.MinimumImprovement = 5
	}
	if p.MinimumLifetime < 0 {
		p.MinimumLifetime = 0
	}
	if p.ConfirmationPeriod < 0 {
		p.ConfirmationPeriod = 0
	}
	if p.MaxAge <= 0 {
		p.MaxAge = 90 * time.Second
	}
	return &RouteSelector{p: p, measurements: make(map[string]RouteMeasurement), quality: make(map[string]*qualityState), current: Direct}
}
func (s *RouteSelector) Observe(m RouteMeasurement) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if m.RouteID == "" || m.ObservedAt.IsZero() {
		return
	}
	old, ok := s.measurements[m.RouteID]
	if ok && !m.ObservedAt.After(old.ObservedAt) {
		return
	}
	if !ok && len(s.measurements) >= 64 {
		return
	}
	if !validFraction(m.Loss) || !validFraction(m.FailureRate) || !validFraction(m.Load) || m.Samples < 0 || m.RTT < 0 || m.Jitter < 0 {
		return
	}
	state := s.quality[m.RouteID]
	if state == nil {
		state = &qualityState{}
		s.quality[m.RouteID] = state
	}
	m.Probes = append([]ProbeSample(nil), m.Probes...)
	state.rounds = append(state.rounds, m)
	cutoff := m.ObservedAt.Add(-QualityWindow)
	for len(state.rounds) > 0 && state.rounds[0].ObservedAt.Before(cutoff) {
		state.rounds = state.rounds[1:]
	}
	if len(state.rounds) > 128 {
		state.rounds = state.rounds[len(state.rounds)-128:]
	}
	incomingBurst := 0
	for _, p := range m.Probes {
		if !state.lastPacketAt.IsZero() && p.At.Before(state.lastPacketAt) {
			continue
		}
		if p.At.Sub(state.lastPacketAt) > QualityWindow {
			state.trailingLoss = 0
		}
		if p.Outcome == Timeout {
			state.trailingLoss++
		} else {
			state.trailingLoss = 0
		}
		incomingBurst = max(incomingBurst, state.trailingLoss)
		state.lastPacketAt = p.At
	}
	q := aggregate(state.rounds, m.ObservedAt)
	badRounds := 0
	for _, round := range state.rounds {
		if round.Loss >= .1-1e-9 {
			badRounds++
		}
	}
	hard := m.TransportError != "" || (!m.Available && m.Samples > 0) || m.ConsecutiveLoss >= 3 || m.MaxLossBurst >= 5 || incomingBurst >= 5 || (q.Samples >= 40 && q.Loss >= .1 && badRounds >= 2 && m.Loss >= .1-1e-9)
	if hard {
		state.fault = true
		state.reason = "probe_failure"
		if m.TransportError != "" {
			state.reason = m.TransportError
		}
		state.goodSince = time.Time{}
		state.goodRounds = 0
	}
	if state.fault && !hard && m.Available && m.Loss <= .02 && m.MaxLossBurst <= 1 {
		if state.goodSince.IsZero() {
			state.goodSince = m.ObservedAt
		}
		state.goodRounds++
		if state.goodRounds >= 3 && m.ObservedAt.Sub(state.goodSince) >= RecoveryConfirmation {
			state.fault = false
			state.reason = ""
		}
	} else if state.fault && !hard {
		state.goodSince = time.Time{}
		state.goodRounds = 0
	}
	s.measurements[m.RouteID] = m
	summary := m
	summary.Probes = nil
	s.history.Measurements = append(s.history.Measurements, summary)
	if len(s.history.Measurements) > 256 {
		s.history.Measurements = s.history.Measurements[len(s.history.Measurements)-256:]
	}
}
func (s *RouteSelector) Select(now time.Time) Selection {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.since.IsZero() {
		s.since = now
	}
	ranked := make([]RouteScore, 0, len(s.measurements))
	for id, m := range s.measurements {
		if now.Sub(m.ObservedAt) > min(s.p.MaxAge, QualityWindow) || m.ObservedAt.After(now) {
			continue
		}
		q := s.qualityLocked(id, now)
		v := QualityScore(q, m.Load)
		if !math.IsInf(v, 1) {
			ranked = append(ranked, RouteScore{id, v, m})
		}
	}
	sort.Slice(ranked, func(i, j int) bool {
		if ranked[i].Score == ranked[j].Score {
			return ranked[i].ID < ranked[j].ID
		}
		return ranked[i].Score < ranked[j].Score
	})
	out := Selection{Primary: s.current, Ranked: ranked}
	currentScore := math.Inf(1)
	for _, r := range ranked {
		if r.ID == s.current {
			currentScore = r.Score
		}
	}
	best := Direct
	if len(ranked) > 0 {
		best = ranked[0].ID
	}
	// Unknown DIRECT observations do not establish a relay improvement.
	directMeasurement, known := s.measurements[Direct]
	directFresh := known && !directMeasurement.ObservedAt.After(now) && now.Sub(directMeasurement.ObservedAt) <= s.p.MaxAge
	if !directFresh && s.current == Direct {
		best = Direct
	}
	unhealthy := math.IsInf(currentScore, 1) && s.current != Direct
	// Swapping one fault for another only churns connections: when the candidate is
	// measured unhealthy as well, keep the current route and report why.
	hold := false
	if unhealthy && s.guard.HoldWithoutHealthyAlternative && math.IsInf(lookup(ranked, best), 1) {
		// best has no finite score only when nothing healthy is ranked, so best is the
		// DIRECT fallback: hold if DIRECT was measured fresh (hence unhealthy); if it
		// was never measured or is stale, failing over to it stays the safe default.
		if best == Direct && directFresh {
			hold = true
			out.Held = "no_healthy_alternative"
		}
	}
	needed := s.p.MinimumImprovement
	if s.guard.RelativeImprovement > 0 && !math.IsInf(currentScore, 1) {
		needed = math.Max(needed, s.guard.RelativeImprovement*currentScore)
	}
	if !hold && best != s.current && (unhealthy || currentScore-lookup(ranked, best) >= needed) {
		if unhealthy {
			out.Changed = true
		} else {
			if s.pending != best {
				s.pending = best
				s.pendingSince = now
				s.pendingRounds = 1
				s.pendingCandidateAt = s.measurements[best].ObservedAt
				s.pendingCurrentAt = s.measurements[s.current].ObservedAt
			}
			candidateAt, currentAt := s.measurements[best].ObservedAt, s.measurements[s.current].ObservedAt
			if candidateAt.After(s.pendingCandidateAt) && currentAt.After(s.pendingCurrentAt) {
				s.pendingRounds++
				s.pendingCandidateAt = candidateAt
				s.pendingCurrentAt = currentAt
			}
			// A lone lossy round is visible in statistics, but is not sustained evidence.
			currentQuality, candidateQuality := s.qualityLocked(s.current, now), s.qualityLocked(best, now)
			sustainedLossEvidence := currentQuality.Loss <= candidateQuality.Loss || currentQuality.LossRounds >= 2
			if now.Sub(s.since) >= s.dwellLocked(now) && now.Sub(s.pendingSince) >= s.p.ConfirmationPeriod && s.pendingRounds >= 3 && sustainedLossEvidence {
				out.Changed = true
			}
		}
		if out.Changed {
			from := s.current
			s.current = best
			s.since = now
			s.pending = ""
			s.history.Changes = append(s.history.Changes, Change{from, best, now})
			if len(s.history.Changes) > 128 {
				s.history.Changes = s.history.Changes[1:]
			}
		}
	} else {
		s.pending = ""
	}
	out.Primary = s.current
	backups := []string{}
	for _, r := range ranked {
		if r.ID != out.Primary {
			backups = append(backups, r.ID)
		}
	}
	if len(backups) > 0 {
		out.Secondary = backups[0]
	}
	if len(backups) > 1 {
		out.Tertiary = backups[1]
	}
	return out
}
func lookup(r []RouteScore, id string) float64 {
	for _, v := range r {
		if v.ID == id {
			return v.Score
		}
	}
	return math.Inf(1)
}
func (s *RouteSelector) History() RouteHistory {
	s.mu.Lock()
	defer s.mu.Unlock()
	return RouteHistory{append([]RouteMeasurement(nil), s.history.Measurements...), append([]Change(nil), s.history.Changes...)}
}

func ValidateParameters(p Parameters) error {
	if math.IsNaN(p.MinimumImprovement) || math.IsInf(p.MinimumImprovement, 0) || p.MinimumImprovement <= 0 || p.MinimumImprovement > 10000 || p.MinimumLifetime < 0 || p.MinimumLifetime > time.Hour || p.ConfirmationPeriod < 0 || p.ConfirmationPeriod > time.Hour || p.MaxAge < time.Second || p.MaxAge > time.Hour {
		return errors.New("invalid routing parameters")
	}
	return nil
}
func (s *RouteSelector) Configure(p Parameters) error {
	if e := ValidateParameters(p); e != nil {
		return e
	}
	s.mu.Lock()
	s.p = p
	s.pending = ""
	s.mu.Unlock()
	return nil
}
