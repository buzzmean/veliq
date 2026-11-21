package optimizer

import (
	"math"
	"sort"
	"time"
)

// Outcomes distinguish unanswered sent probes from failures before network send.
// A timeout is end-to-end probe loss, not proof that a particular network hop lost it.
type ProbeSample struct {
	At      time.Time
	RTT     time.Duration
	Outcome string
}

const (
	Reply            = "reply"
	Timeout          = "timeout"
	LocalFailure     = "local_failure"
	TransportFailure = "transport_failure"
)
const (
	QualityWindow         = 60 * time.Second
	MinimumQualitySamples = 20
	MinimumQualityRounds  = 3
	RecoveryConfirmation  = 10 * time.Second
	EWMAAlpha             = .25
)

type Quality struct {
	NetworkSamples       int           `json:"network_sample_count"`
	WindowSeconds        int           `json:"window_seconds"`
	LatestRTT            time.Duration `json:"latest_rtt"`
	MedianRTT            time.Duration `json:"median_rtt"`
	P95RTT               time.Duration `json:"p95_rtt"`
	Jitter               time.Duration `json:"jitter"`
	Loss                 float64       `json:"probe_loss"`
	EWMARTT              time.Duration `json:"ewma_rtt"`
	EWMAJitter           time.Duration `json:"ewma_jitter"`
	EWMALoss             float64       `json:"ewma_loss"`
	ConsecutiveLoss      int           `json:"consecutive_loss"`
	MaxLossBurst         int           `json:"max_loss_burst"`
	FailureRate          float64       `json:"failure_rate"`
	LocalFailureRate     float64       `json:"local_failure_rate"`
	Stability            float64       `json:"stability"`
	Samples              int           `json:"sample_count"`
	Rounds               int           `json:"round_count"`
	LossRounds           int           `json:"loss_rounds"`
	ReplyCount           int           `json:"reply_count"`
	PercentilesAvailable bool          `json:"percentiles_available"`
	Health               string        `json:"health"`
	Reason               string        `json:"reason,omitempty"`
	ObservedAt           time.Time     `json:"observed_at"`
}

type qualityState struct {
	rounds       []RouteMeasurement
	fault        bool
	reason       string
	goodSince    time.Time
	goodRounds   int
	generation   uint64
	trailingLoss int
	lastPacketAt time.Time
}

func aggregate(rounds []RouteMeasurement, now time.Time) Quality {
	q := Quality{WindowSeconds: 60, Stability: 1}
	var packets []ProbeSample
	var losses, networkSamples, failures, localFailures float64
	var ewmaRTT, ewmaJitter float64
	legacyRTTs := []time.Duration{}
	var initialized bool
	for _, m := range rounds {
		if m.ObservedAt.After(now) || now.Sub(m.ObservedAt) > QualityWindow {
			continue
		}
		if len(m.Probes) > 0 {
			retained := make([]ProbeSample, 0, len(m.Probes))
			var total, variation, previous time.Duration
			replies, sent, lost, failed := 0, 0, 0, 0
			for _, p := range m.Probes {
				if p.At.After(now) || now.Sub(p.At) > QualityWindow {
					continue
				}
				retained = append(retained, p)
				switch p.Outcome {
				case Reply:
					sent++
					total += p.RTT
					if replies > 0 {
						delta := p.RTT - previous
						if delta < 0 {
							delta = -delta
						}
						variation += delta
					}
					previous = p.RTT
					replies++
				case Timeout:
					sent++
					lost++
				case LocalFailure, TransportFailure:
					failed++
				}
			}
			if len(retained) == 0 {
				continue
			}
			m.Probes = retained
			m.Samples = len(retained)
			m.Available = replies > 0
			m.RTT = 0
			m.Jitter = 0
			m.Loss = 0
			if replies > 0 {
				m.RTT = total / time.Duration(replies)
			}
			if replies > 1 {
				m.Jitter = variation / time.Duration(replies-1)
			}
			if sent > 0 {
				m.Loss = float64(lost) / float64(sent)
			}
			m.FailureRate = float64(failed) / float64(m.Samples)
		}
		q.Rounds++
		q.Samples += m.Samples
		q.ObservedAt = m.ObservedAt
		failures += m.FailureRate * float64(max(1, m.Samples))
		if m.Loss > 0 {
			q.LossRounds++
		}
		if m.Available {
			q.LatestRTT = m.RTT
			legacyRTTs = append(legacyRTTs, m.RTT)
			if !initialized {
				ewmaRTT = float64(m.RTT)
				ewmaJitter = float64(m.Jitter)
				initialized = true
			} else {
				ewmaRTT += (float64(m.RTT) - ewmaRTT) * EWMAAlpha
				ewmaJitter += (float64(m.Jitter) - ewmaJitter) * EWMAAlpha
			}
		}
		lossForEWMA := m.Loss
		if len(m.Probes) > 0 {
			sent, lost := 0, 0
			for _, p := range m.Probes {
				if p.Outcome == Reply || p.Outcome == Timeout {
					sent++
				}
				if p.Outcome == Timeout {
					lost++
				}
			}
			if sent > 0 {
				lossForEWMA = float64(lost) / float64(sent)
			} else {
				lossForEWMA = 0
			}
		}
		if q.Rounds == 1 {
			q.EWMALoss = lossForEWMA
		} else {
			q.EWMALoss += (lossForEWMA - q.EWMALoss) * EWMAAlpha
		}
		if len(m.Probes) > 0 {
			packets = append(packets, m.Probes...)
		} else {
			// Legacy aggregate observations cannot establish per-packet percentiles/bursts.
			networkSamples += float64(m.Samples)
			losses += m.Loss * float64(m.Samples)
		}
	}
	sort.SliceStable(packets, func(i, j int) bool { return packets[i].At.Before(packets[j].At) })
	rtts := []time.Duration{}
	var previous time.Duration
	var havePrevious bool
	var jitter time.Duration
	var jitterSamples int
	for _, p := range packets {
		if p.At.After(now) || now.Sub(p.At) > QualityWindow {
			continue
		}
		switch p.Outcome {
		case Reply:
			networkSamples++
			q.ReplyCount++
			q.LatestRTT = p.RTT
			q.ConsecutiveLoss = 0
			rtts = append(rtts, p.RTT)
			if havePrevious {
				difference := p.RTT - previous
				if difference < 0 {
					difference = -difference
				}
				jitter += difference
				jitterSamples++
			}
			previous = p.RTT
			havePrevious = true
		case Timeout:
			networkSamples++
			losses++
			q.ConsecutiveLoss++
			q.MaxLossBurst = max(q.MaxLossBurst, q.ConsecutiveLoss)
		case LocalFailure:
			localFailures++
			q.ConsecutiveLoss = 0
		case TransportFailure:
			q.ConsecutiveLoss = 0
		}
	}
	q.NetworkSamples = int(networkSamples)
	if networkSamples > 0 {
		q.Loss = losses / networkSamples
	}
	if q.Samples > 0 {
		q.FailureRate = math.Min(1, failures/float64(q.Samples))
		q.LocalFailureRate = localFailures / float64(q.Samples)
	} else if q.Rounds > 0 {
		q.FailureRate = math.Min(1, failures/float64(q.Rounds))
	}
	if jitterSamples > 0 {
		q.Jitter = jitter / time.Duration(jitterSamples)
	} else {
		q.Jitter = time.Duration(ewmaJitter)
	}
	if len(rtts) > 0 {
		q.PercentilesAvailable = true
		sort.Slice(rtts, func(i, j int) bool { return rtts[i] < rtts[j] })
		q.MedianRTT = rtts[(len(rtts)-1)/2]
		q.P95RTT = rtts[int(math.Ceil(.95*float64(len(rtts))))-1]
	} else {
		if len(legacyRTTs) > 0 {
			sort.Slice(legacyRTTs, func(i, j int) bool { return legacyRTTs[i] < legacyRTTs[j] })
			q.MedianRTT = legacyRTTs[(len(legacyRTTs)-1)/2]
		}
		q.P95RTT = q.MedianRTT
	}
	q.EWMARTT = time.Duration(ewmaRTT)
	q.EWMAJitter = time.Duration(ewmaJitter)
	// Bounded consistency index, not an invented availability probability.
	q.Stability = 1 / (1 + 10*q.Loss + float64(q.Jitter)/float64(50*time.Millisecond) + float64(max(0, q.MaxLossBurst-1))*.1)
	return q
}

// QualityScore units are equivalent milliseconds: each sustained percentage point
// of unanswered probes costs 40ms; every extra packet in a burst costs 25ms.
// Median guards one RTT outlier; p95 exposes persistent tails. No RTT is fabricated.
func QualityScore(q Quality, load float64) float64 {
	if q.Health != "healthy" || q.NetworkSamples < MinimumQualitySamples || !validFraction(q.Loss) || !validFraction(q.FailureRate) || !validFraction(load) {
		return math.Inf(1)
	}
	latency := .9*float64(q.MedianRTT) + .1*float64(q.EWMARTT)
	tail := math.Max(0, float64(q.P95RTT-q.MedianRTT))
	return latency/float64(time.Millisecond) + .5*tail/float64(time.Millisecond) + 2*float64(q.Jitter)/float64(time.Millisecond) + 4000*q.Loss + 2000*q.FailureRate + 25*float64(max(0, q.MaxLossBurst-1)) + 15*load + 20*(1-q.Stability)
}
func (s *RouteSelector) qualityLocked(id string, now time.Time) Quality {
	state := s.quality[id]
	if state == nil {
		return Quality{Health: "unavailable", Reason: "no_observations"}
	}
	q := aggregate(state.rounds, now)
	switch {
	case state.fault:
		q.Health = "unhealthy"
		q.Reason = state.reason
		if state.goodRounds > 0 {
			q.Health = "recovering"
		}
	case q.Rounds == 0:
		q.Health = "stale"
		q.Reason = "window_expired"
	case q.NetworkSamples < MinimumQualitySamples || q.Rounds < MinimumQualityRounds:
		q.Health = "warming_up"
		q.Reason = "insufficient_history"
	default:
		q.Health = "healthy"
	}
	return q
}
func (s *RouteSelector) Qualities(now time.Time) map[string]Quality {
	s.mu.Lock()
	defer s.mu.Unlock()
	result := map[string]Quality{}
	for id := range s.quality {
		result[id] = s.qualityLocked(id, now)
	}
	return result
}
func (s *RouteSelector) RegisterTransport(id string) uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	state := s.quality[id]
	if state == nil {
		if len(s.quality) >= 64 {
			return 0
		}
		state = &qualityState{}
		s.quality[id] = state
	}
	state.generation++
	return state.generation
}
func (s *RouteSelector) ReportTransportFailure(id string, generation uint64, reason string, at time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	state := s.quality[id]
	if state == nil || state.generation != generation {
		return
	}
	state.fault = true
	state.reason = reason
	state.goodSince = time.Time{}
	state.goodRounds = 0
	s.pending = ""
}

// Probe failures have no session generation; they report current path evidence.
func (s *RouteSelector) ReportProbeFailure(id, reason string, at time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	state := s.quality[id]
	if state == nil {
		if len(s.quality) >= 64 {
			return
		}
		state = &qualityState{}
		s.quality[id] = state
	}
	state.fault = true
	state.reason = reason
	state.goodSince = time.Time{}
	state.goodRounds = 0
	s.pending = ""
}
