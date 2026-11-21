package controlplane

import (
	"testing"
	"time"
)

func TestNoisySourceDoesNotStarveOthers(t *testing.T) {
	now := time.Now()
	l := newLimiter(now)
	for i := 0; i < 1000; i++ {
		l.allow(now, "198.51.100.9")
	}
	if l.allow(now, "198.51.100.9") {
		t.Fatal("noisy source not throttled")
	}
	if !l.allow(now, "203.0.113.5") {
		t.Fatal("quiet source starved by noisy one")
	}
	if !l.allow(now.Add(2*time.Second), "198.51.100.9") {
		t.Fatal("source not refilled")
	}
}

func TestLimiterBoundsTrackedSources(t *testing.T) {
	now := time.Now()
	l := newLimiter(now)
	l.maxIPs = 4
	for _, ip := range []string{"a", "b", "c", "d"} {
		l.allow(now, ip)
	}
	if l.allow(now, "e") {
		t.Fatal("unbounded source table")
	}
	if !l.allow(now.Add(2*time.Minute), "e") {
		t.Fatal("idle sources not evicted")
	}
}
