package optimizer

import (
	"math"
	"testing"
	"time"
)

func sample(id string, rtt, loss float64, at time.Time) RouteMeasurement {
	return RouteMeasurement{RouteID: id, RTT: time.Duration(rtt * float64(time.Millisecond)), Loss: loss, Stability: 1, Available: true, ObservedAt: at, Samples: 100}
}
func observePair(s *RouteSelector, at time.Time, direct, relay, loss, relayLoss float64) {
	s.Observe(sample(Direct, direct, loss, at))
	s.Observe(sample("FRA-01", relay, relayLoss, at))
}
func TestScoringHysteresis(t *testing.T) {
	for _, tc := range []struct {
		direct, relay, loss, relayLoss float64
		want                           string
	}{{24, 28, 0, 0, Direct}, {55, 37, .025, .001, "FRA-01"}, {30, 29, 0, 0, Direct}, {55, 48, 0, .02, Direct}, {80, 58, .015, .001, "FRA-01"}} {
		n := time.Unix(1000, 0)
		s := New(Parameters{5, 20 * time.Second, 10 * time.Second, time.Minute})
		for i := 0; i < 9; i++ {
			at := n.Add(time.Duration(i) * 5 * time.Second)
			observePair(s, at, tc.direct, tc.relay, tc.loss, tc.relayLoss)
			got := s.Select(at)
			if i < 4 && got.Primary != Direct {
				t.Fatal("early switch", got)
			}
		}
		if got := s.Select(n.Add(40 * time.Second)).Primary; got != tc.want {
			t.Fatalf("case %+v got %s", tc, got)
		}
	}
}
func TestConfirmationResetAndFailover(t *testing.T) {
	n := time.Unix(1000, 0)
	s := New(Parameters{5, 0, 10 * time.Second, time.Minute})
	for i := 0; i < 6; i++ {
		at := n.Add(time.Duration(i) * 5 * time.Second)
		observePair(s, at, 80, 20, 0, 0)
		s.Observe(sample("WAW", 35, 0, at))
		s.Select(at)
	}
	got := s.Select(n.Add(25 * time.Second))
	if got.Primary != "FRA-01" || got.Secondary != "WAW" || got.Tertiary != Direct {
		t.Fatal(got)
	}
	generation := s.RegisterTransport("FRA-01")
	s.ReportTransportFailure("FRA-01", generation, "closed", n.Add(26*time.Second))
	if got := s.Select(n.Add(26 * time.Second)); got.Primary != "WAW" {
		t.Fatal("no immediate failure", got)
	}
	if got := s.Select(n.Add(2 * time.Minute)); got.Primary != Direct {
		t.Fatal("stale route", got)
	}
}
func TestInvalidAndUnknown(t *testing.T) {
	n := time.Unix(1000, 0)
	s := New(DefaultParameters())
	for i := 0; i < 8; i++ {
		at := n.Add(time.Duration(i) * 5 * time.Second)
		s.Observe(sample("FRA", 1, 0, at))
		if s.Select(at).Primary != Direct {
			t.Fatal("unknown direct optimized")
		}
	}
	m := sample(Direct, 1, math.NaN(), n)
	if !math.IsInf(Score(m), 1) {
		t.Fatal("NaN accepted")
	}
}
func TestPollingCannotReplaceConfirmationEvidence(t *testing.T) {
	n := time.Unix(1000, 0)
	s := New(DefaultParameters())
	for i := 0; i < 3; i++ {
		observePair(s, n.Add(time.Duration(i)*time.Second), 80, 20, 0, 0)
	}
	s.Select(n.Add(2 * time.Second))
	if s.Select(n.Add(40*time.Second)).Primary != Direct {
		t.Fatal("switched without new observations")
	}
}
