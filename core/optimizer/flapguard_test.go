package optimizer

import (
	"testing"
	"time"
)

// burst loses 5 consecutive probes: a serious burst makes the route unhealthy.
var burst = map[int]bool{95: true, 96: true, 97: true, 98: true, 99: true}

// relayPreferred drives the selector until it has moved to FRA-01.
func relayPreferred(t *testing.T, s *RouteSelector, n time.Time) time.Time {
	t.Helper()
	at := n
	for i := 0; i < 8; i++ {
		at = n.Add(time.Duration(i) * 5 * time.Second)
		observePair(s, at, 80, 20, 0, 0)
		s.Select(at)
	}
	if got := s.Select(at); got.Primary != "FRA-01" {
		t.Fatalf("setup: relay not selected: %+v", got)
	}
	return at
}

func bothUnhealthy(s *RouteSelector, from time.Time) Selection {
	var last Selection
	for i := 1; i <= 4; i++ {
		at := from.Add(time.Duration(i) * 5 * time.Second)
		s.Observe(packets(Direct, at, 80*time.Millisecond, burst, nil))
		s.Observe(packets("FRA-01", at, 20*time.Millisecond, burst, nil))
		last = s.Select(at)
	}
	return last
}

func TestBothRoutesUnhealthyKeepsCurrentRouteInsteadOfFlapping(t *testing.T) {
	n := time.Unix(1000, 0)
	control := New(Parameters{5, 0, 10 * time.Second, time.Minute})
	guarded := New(Parameters{5, 0, 10 * time.Second, time.Minute})
	guarded.SetFlapGuard(DefaultFlapGuard())
	end := relayPreferred(t, control, n)
	relayPreferred(t, guarded, n)

	// Without the guard the faulted relay hands traffic to an equally faulted DIRECT.
	if got := bothUnhealthy(control, end); got.Primary != Direct {
		t.Fatalf("control run no longer shows the flap this guard prevents: %+v", got)
	}
	got := bothUnhealthy(guarded, end)
	if got.Primary != "FRA-01" || got.Held != "no_healthy_alternative" {
		t.Fatalf("switched to an unhealthy route: %+v", got)
	}
	if n := len(guarded.History().Changes); n != 1 {
		t.Fatalf("unexpected extra changes: %d", n)
	}
}

func TestFaultedRelayStillFallsBackToHealthyOrUnmeasuredDirect(t *testing.T) {
	n := time.Unix(1000, 0)
	s := New(Parameters{5, 0, 10 * time.Second, time.Minute})
	s.SetFlapGuard(DefaultFlapGuard())
	end := relayPreferred(t, s, n)
	// DIRECT stays healthy, the relay develops a serious burst: immediate fallback.
	var got Selection
	for i := 1; i <= 4; i++ {
		at := end.Add(time.Duration(i) * 5 * time.Second)
		s.Observe(sample(Direct, 80, 0, at))
		s.Observe(packets("FRA-01", at, 20*time.Millisecond, burst, nil))
		got = s.Select(at)
	}
	if got.Primary != Direct || got.Held != "" {
		t.Fatalf("failover to healthy DIRECT lost: %+v", got)
	}

	// Relay fault while DIRECT has never been measured: fail over (existing invariant).
	s2 := New(Parameters{5, 0, 10 * time.Second, time.Minute})
	s2.SetFlapGuard(DefaultFlapGuard())
	var cur Selection
	for i := 0; i < 8; i++ {
		at := n.Add(time.Duration(i) * 5 * time.Second)
		s2.Observe(sample(Direct, 80, 0, at))
		s2.Observe(sample("FRA-01", 20, 0, at))
		cur = s2.Select(at)
	}
	if cur.Primary != "FRA-01" {
		t.Fatalf("setup: %+v", cur)
	}
	at := n.Add(10 * time.Minute) // every older measurement is stale now
	s2.Observe(packets("FRA-01", at, 20*time.Millisecond, burst, nil))
	s2.Observe(packets("FRA-01", at.Add(time.Second), 20*time.Millisecond, burst, nil))
	if got := s2.Select(at.Add(2 * time.Second)); got.Primary != Direct {
		t.Fatalf("no failover to unmeasured DIRECT: %+v", got)
	}
}

func TestRelativeImprovementIgnoresNoiseAtHighScores(t *testing.T) {
	n := time.Unix(1000, 0)
	run := func(guard bool) string {
		s := New(Parameters{5, 0, 10 * time.Second, time.Minute})
		if guard {
			s.SetFlapGuard(DefaultFlapGuard())
		}
		// Both routes are poor (2% loss ~ hundreds of score units); the relay is only
		// ~8% better, which is well above the absolute margin of 5 but is just noise.
		for i := 0; i < 12; i++ {
			at := n.Add(time.Duration(i) * 5 * time.Second)
			observePair(s, at, 300, 276, 0.02, 0.02)
			s.Select(at)
		}
		return s.Select(n.Add(60 * time.Second)).Primary
	}
	if got := run(false); got != "FRA-01" {
		t.Fatalf("control run does not show the noise switch: %s", got)
	}
	if got := run(true); got != Direct {
		t.Fatalf("switched on an 8%% improvement: %s", got)
	}
}

func TestFrequentChangesRequireLongDwellBeforeVoluntarySwitch(t *testing.T) {
	n := time.Unix(1000, 0)
	s := New(Parameters{5, 0, 10 * time.Second, time.Minute})
	s.SetFlapGuard(DefaultFlapGuard())
	now := n.Add(time.Hour)
	// Three changes in the last half hour, the last one 2 minutes ago.
	s.history.Changes = []Change{{Direct, "FRA-01", now.Add(-20 * time.Minute)}, {"FRA-01", Direct, now.Add(-11 * time.Minute)}, {Direct, "FRA-01", now.Add(-2 * time.Minute)}}
	s.current, s.since = "FRA-01", now.Add(-2*time.Minute)
	drive := func(from time.Time, rounds int) Selection {
		var got Selection
		for i := 0; i < rounds; i++ {
			at := from.Add(time.Duration(i) * 5 * time.Second)
			observePair(s, at, 20, 120, 0, 0) // DIRECT is now far better than the relay
			got = s.Select(at)
		}
		return got
	}
	if got := drive(now, 10); got.Primary != "FRA-01" {
		t.Fatalf("voluntary switch only 2 minutes after the last change: %+v", got)
	}
	later := now.Add(9 * time.Minute) // 11 minutes since the last change
	if got := drive(later, 10); got.Primary != Direct {
		t.Fatalf("switch still blocked after the dwell elapsed: %+v", got)
	}
}
