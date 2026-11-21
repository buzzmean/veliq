package optimizer

import (
	"math"
	"testing"
	"time"
)

func packets(id string, at time.Time, rtt time.Duration, lost map[int]bool, tail map[int]time.Duration) RouteMeasurement {
	m := RouteMeasurement{RouteID: id, RTT: rtt, Available: true, ObservedAt: at, Samples: 100, Stability: 1}
	success := 0
	var total time.Duration
	for i := 0; i < 100; i++ {
		p := ProbeSample{At: at, RTT: rtt, Outcome: Reply}
		if lost[i] {
			p.Outcome = Timeout
			p.RTT = 0
			m.ConsecutiveLoss++
			m.MaxLossBurst = max(m.MaxLossBurst, m.ConsecutiveLoss)
		} else {
			m.ConsecutiveLoss = 0
			if duration, ok := tail[i]; ok {
				p.RTT = duration
			}
			total += p.RTT
			success++
		}
		m.Probes = append(m.Probes, p)
	}
	m.Loss = 1 - float64(success)/100
	m.Available = success > 0
	if success > 0 {
		m.RTT = total / time.Duration(success)
	}
	return m
}
func qualityFor(m RouteMeasurement) Quality {
	rounds := []RouteMeasurement{}
	for i := 0; i < 3; i++ {
		copy := m
		copy.Probes = append([]ProbeSample(nil), m.Probes...)
		copy.ObservedAt = m.ObservedAt.Add(time.Duration(i) * time.Second)
		for j := range copy.Probes {
			copy.Probes[j].At = copy.ObservedAt
		}
		rounds = append(rounds, copy)
	}
	q := aggregate(rounds, rounds[2].ObservedAt)
	q.Health = "healthy"
	return q
}
func TestLossDistributionAndTailScoring(t *testing.T) {
	at := time.Unix(1000, 0)
	stable := qualityFor(packets(Direct, at, 50*time.Millisecond, nil, nil))
	if stable.Loss != 0 || stable.Jitter != 0 || stable.Samples != 300 || stable.MedianRTT != 50*time.Millisecond || stable.P95RTT != 50*time.Millisecond || stable.Stability != 1 {
		t.Fatal(stable)
	}
	previous := QualityScore(stable, 0)
	for _, percent := range []int{1, 3, 5} {
		lost := map[int]bool{}
		for i := 0; i < percent; i++ {
			lost[i*20+10] = true
		}
		q := qualityFor(packets("relay", at, 50*time.Millisecond, lost, nil))
		if math.Abs(q.Loss-float64(percent)/100) > 1e-8 || q.MaxLossBurst != 1 {
			t.Fatal(q)
		}
		if score := QualityScore(q, 0); score <= previous {
			t.Fatal("loss not penalized", score)
		} else {
			previous = score
		}
	}
	isolated := qualityFor(packets("relay", at, 50*time.Millisecond, map[int]bool{10: true, 30: true, 50: true, 70: true, 90: true}, nil))
	burst := qualityFor(packets("relay", at, 50*time.Millisecond, map[int]bool{10: true, 11: true, 12: true, 13: true, 14: true}, nil))
	if burst.MaxLossBurst != 5 || QualityScore(burst, 0) <= QualityScore(isolated, 0) {
		t.Fatal("burst ignored")
	}
	tail := map[int]time.Duration{}
	for i := 0; i < 10; i++ {
		tail[i*10] = 250 * time.Millisecond
	}
	q := qualityFor(packets("relay", at, 50*time.Millisecond, nil, tail))
	if q.MedianRTT != 50*time.Millisecond || q.P95RTT != 250*time.Millisecond || q.Jitter <= 0 || QualityScore(q, 0) <= QualityScore(stable, 0) {
		t.Fatal("tail/jitter ignored", q)
	}
}
func TestRollingExpiryAndEWMA(t *testing.T) {
	at := time.Unix(1000, 0)
	rounds := []RouteMeasurement{sample(Direct, 10, 0, at), sample(Direct, 50, .04, at.Add(time.Second))}
	q := aggregate(rounds, at.Add(time.Second))
	if q.EWMARTT != 20*time.Millisecond || math.Abs(q.EWMALoss-.01) > 1e-8 {
		t.Fatal(q)
	}
	q = aggregate(rounds, at.Add(62*time.Second))
	if q.Samples != 0 || q.Rounds != 0 {
		t.Fatal("expired history", q)
	}
}
func TestBurstSpansRounds(t *testing.T) {
	at := time.Unix(1000, 0)
	a := packets("R", at, 20*time.Millisecond, map[int]bool{98: true, 99: true}, nil)
	b := packets("R", at.Add(time.Second), 20*time.Millisecond, map[int]bool{0: true, 1: true, 2: true}, nil)
	q := aggregate([]RouteMeasurement{a, b}, at.Add(time.Second))
	if q.MaxLossBurst != 5 {
		t.Fatal(q)
	}
}
func TestLocalFailureIsNotNetworkLoss(t *testing.T) {
	at := time.Unix(1000, 0)
	m := packets("R", at, 20*time.Millisecond, nil, nil)
	m.Probes[0].Outcome = LocalFailure
	m.Loss = .01
	m.FailureRate = .01
	q := aggregate([]RouteMeasurement{m}, at)
	if q.Loss != 0 || q.EWMALoss != 0 || q.LocalFailureRate != .01 {
		t.Fatal(q)
	}
}
func TestWarmupNeedsMultipleRounds(t *testing.T) {
	at := time.Unix(1000, 0)
	s := New(DefaultParameters())
	s.Observe(sample("R", 10, 0, at))
	if s.Qualities(at)["R"].Health != "warming_up" {
		t.Fatal("one round is sufficient")
	}
}
func TestRecoveryRequiresFreshConfirmedObservations(t *testing.T) {
	at := time.Unix(1000, 0)
	s := New(DefaultParameters())
	for i := 0; i < 3; i++ {
		s.Observe(sample("R", 10, 0, at.Add(time.Duration(i)*time.Second)))
	}
	generation := s.RegisterTransport("R")
	s.ReportTransportFailure("R", generation, "closed", at.Add(3*time.Second))
	for i := 0; i < 2; i++ {
		s.Observe(sample("R", 10, 0, at.Add(time.Duration(4+i*5)*time.Second)))
	}
	if s.Qualities(at.Add(9 * time.Second))["R"].Health != "recovering" {
		t.Fatal("early recovery")
	}
	s.Observe(sample("R", 10, 0, at.Add(14*time.Second)))
	if s.Qualities(at.Add(14 * time.Second))["R"].Health != "healthy" {
		t.Fatal("recovery missing")
	}
	newGeneration := s.RegisterTransport("R")
	if newGeneration == generation {
		t.Fatal("generation not advanced")
	}
	s.ReportTransportFailure("R", generation, "old_session", at.Add(15*time.Second))
	if s.Qualities(at.Add(15 * time.Second))["R"].Health != "healthy" {
		t.Fatal("retired session poisoned replacement")
	}
}
func TestSeriousBurstAndSustainedLossUnhealthy(t *testing.T) {
	at := time.Unix(1000, 0)
	for _, loss := range []map[int]bool{{95: true, 96: true, 97: true, 98: true, 99: true}, {1: true, 11: true, 21: true, 31: true, 41: true, 51: true, 61: true, 71: true, 81: true, 91: true}} {
		s := New(DefaultParameters())
		for i := 0; i < 3; i++ {
			s.Observe(packets("R", at.Add(time.Duration(i)*time.Second), 20*time.Millisecond, loss, nil))
		}
		if s.Qualities(at.Add(2 * time.Second))["R"].Health != "unhealthy" {
			t.Fatal("serious loss considered healthy")
		}
	}
}
func TestTransientAndAlternatingRoutesDoNotFlap(t *testing.T) {
	at := time.Unix(1000, 0)
	for _, kind := range []string{"rtt", "loss", "alternating"} {
		s := New(DefaultParameters())
		for i := 0; i < 14; i++ {
			now := at.Add(time.Duration(i) * 5 * time.Second)
			d, r := 50., 60.
			dl := 0.
			if i == 5 {
				if kind == "rtt" {
					d = 500
				} else if kind == "loss" {
					dl = .2
				}
			}
			if kind == "alternating" && i%2 == 1 {
				d = 80
				r = 20
			}
			observePair(s, now, d, r, dl, 0)
			if selected := s.Select(now); selected.Primary != Direct {
				t.Fatalf("%s switched on transient evidence at %d: %+v", kind, i, selected)
			}
		}
	}
}
func TestSustainedDegradationAndMinimumLifetime(t *testing.T) {
	at := time.Unix(1000, 0)
	s := New(DefaultParameters())
	for i := 0; i < 15; i++ {
		now := at.Add(time.Duration(i) * 5 * time.Second)
		dl := 0.
		if i >= 4 {
			dl = .03
		}
		observePair(s, now, 50, 55, dl, 0)
		s.Select(now)
	}
	if s.Select(at.Add(70*time.Second)).Primary != "FRA-01" {
		t.Fatal("sustained degradation ignored")
	}
}
func TestHealthDetectsNewBurstAcrossRoundBoundary(t *testing.T) {
	at := time.Unix(1000, 0)
	s := New(DefaultParameters())
	s.Observe(packets("R", at, 20*time.Millisecond, map[int]bool{98: true, 99: true}, nil))
	s.Observe(packets("R", at.Add(time.Second), 20*time.Millisecond, map[int]bool{0: true, 1: true, 2: true}, nil))
	if s.Qualities(at.Add(time.Second))["R"].Health != "unhealthy" {
		t.Fatal("cross-round burst did not change health")
	}
}

func TestPartialRoundExpiryDoesNotRetainExpiredLoss(t *testing.T) {
	now := time.Unix(2000, 0)
	m := RouteMeasurement{RouteID: "R", ObservedAt: now, Samples: 3, Available: true, Loss: 2.0 / 3, FailureRate: 1.0 / 3, RTT: 500 * time.Millisecond,
		Probes: []ProbeSample{{At: now.Add(-61 * time.Second), Outcome: Timeout}, {At: now.Add(-61 * time.Second), Outcome: LocalFailure}, {At: now, Outcome: Reply, RTT: 20 * time.Millisecond}}}
	q := aggregate([]RouteMeasurement{m}, now)
	if q.Samples != 1 || q.NetworkSamples != 1 || q.Loss != 0 || q.EWMALoss != 0 || q.FailureRate != 0 || q.LocalFailureRate != 0 || q.EWMARTT != 20*time.Millisecond {
		t.Fatal(q)
	}
}
func TestRequiredLossAndJitterTradeoffs(t *testing.T) {
	quality := func(rtt, jitter float64, loss float64) Quality {
		return Quality{Health: "healthy", Samples: 100, NetworkSamples: 100, MedianRTT: time.Duration(rtt * float64(time.Millisecond)), P95RTT: time.Duration(rtt * float64(time.Millisecond)), EWMARTT: time.Duration(rtt * float64(time.Millisecond)), Jitter: time.Duration(jitter * float64(time.Millisecond)), Loss: loss, Stability: 1}
	}
	if QualityScore(quality(55, 2, 0), 0) >= QualityScore(quality(48, 7, .02), 0) {
		t.Fatal("7ms RTT gain outweighed loss/jitter")
	}
	if QualityScore(quality(80, 12, .015), 0) <= QualityScore(quality(58, 3, .001), 0) {
		t.Fatal("better relay did not win")
	}
}
