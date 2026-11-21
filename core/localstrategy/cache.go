package localstrategy

import (
	"errors"
	"github.com/buzzmean/neexitlag/core/optimizer"
	"math"
	"sync"
	"time"
)

// TargetKey never pools different applications, destinations, networks or versions.
type TargetKey struct {
	ConfigRevision                                      string
	Network, Application, Destination, Domain, Protocol string
	Version                                             int
}
type Working struct {
	Strategy                                           string
	LastSuccess, LastTested, Expires, QuarantinedUntil time.Time
	FailureCount                                       int
	Measurement                                        optimizer.RouteMeasurement
}
type Cache struct {
	mu    sync.Mutex
	items map[TargetKey]map[string]Working
	limit int
}

func NewCache(limit int) *Cache {
	if limit <= 0 {
		limit = 1024
	}
	return &Cache{items: map[TargetKey]map[string]Working{}, limit: limit}
}
func (c *Cache) Record(k TargetKey, strategy string, m optimizer.RouteMeasurement, success bool, now time.Time) error {
	if len(k.ConfigRevision) > 128 || len(m.RouteID) > 128 || len(m.TransportError) > 256 {
		return errors.New("oversized strategy evidence")
	}
	if k.Network == "" || k.Application == "" || k.Destination == "" || k.Version != Version || len(k.Network) > 128 || len(k.Application) > 2048 || len(k.Destination) > 512 || len(k.Domain) > 253 || len(strategy) > 64 || strategy == "" || m.ObservedAt.After(now.Add(time.Second)) || now.Sub(m.ObservedAt) > time.Minute {
		return errors.New("invalid strategy evidence scope/time")
	}
	if k.Protocol != "tcp" && k.Protocol != "udp" {
		return errors.New("invalid protocol")
	}
	if success && (math.IsInf(optimizer.Score(m), 1) || m.Loss > 0.05 || m.FailureRate > 0.05) {
		return errors.New("success needs usable measured quality")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.cleanup(now)
	all := c.items[k]
	if all == nil {
		if len(c.items) >= c.limit {
			return errors.New("strategy cache capacity")
		}
		all = map[string]Working{}
		c.items[k] = all
	}
	if len(all) >= 12 {
		if _, ok := all[strategy]; !ok {
			return errors.New("too many target strategies")
		}
	}
	v := all[strategy]
	v.Strategy = strategy
	v.LastTested = now
	v.Expires = now.Add(15 * time.Minute)
	v.Measurement = m
	v.Measurement.Probes = nil
	if success {
		if now.Before(v.QuarantinedUntil) {
			return errors.New("strategy quarantined; wait before retesting")
		}
		v.LastSuccess = now
		v.FailureCount = 0
	} else {
		v.FailureCount++
		if v.FailureCount >= 3 {
			v.QuarantinedUntil = now.Add(5 * time.Minute)
		}
	}
	all[strategy] = v
	return nil
}
func (c *Cache) cleanup(now time.Time) {
	for k, all := range c.items {
		for s, v := range all {
			if !now.Before(v.Expires) {
				delete(all, s)
			}
		}
		if len(all) == 0 {
			delete(c.items, k)
		}
	}
}
func (c *Cache) Cleanup(now time.Time) { c.mu.Lock(); defer c.mu.Unlock(); c.cleanup(now) }
func (c *Cache) Candidates(k TargetKey, now time.Time) []Working {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := []Working{}
	for _, v := range c.items[k] {
		if now.Before(v.Expires) && !now.Before(v.LastTested) && !now.Before(v.QuarantinedUntil) && v.FailureCount == 0 && !v.LastSuccess.IsZero() {
			out = append(out, v)
		}
	}
	return out
}

// Recommend uses the existing score to order usable measured local candidates.
// Prefer a working local route before paying relay traffic cost.
// Healthy DIRECT wins. Missing per-target direct evidence cannot enable DIRECT+.
func Recommend(direct optimizer.RouteMeasurement, working []Working, relay optimizer.RouteMeasurement, now time.Time) string {
	fresh := func(m optimizer.RouteMeasurement) bool {
		return !m.ObservedAt.After(now) && now.Sub(m.ObservedAt) < 15*time.Minute
	}
	if !fresh(direct) {
		return ""
	}
	ds := optimizer.Score(direct)
	if !math.IsInf(ds, 1) && direct.Loss <= .01 && direct.FailureRate == 0 {
		return "DIRECT"
	}
	best := ""
	score := math.Inf(1)

	for _, v := range working {
		if v.Strategy == "DIRECT" || v.Strategy == "RELAY" || v.FailureCount > 0 || now.Before(v.QuarantinedUntil) || !now.Before(v.Expires) || !fresh(v.Measurement) {
			continue
		}
		s := optimizer.Score(v.Measurement)
		if s < score && s <= ds {
			score = s
			best = v.Strategy
		}
	}
	if best != "" {
		return best
	}
	if fresh(relay) && !math.IsInf(optimizer.Score(relay), 1) {
		return "RELAY"
	}
	return ""
}

func (c *Cache) Evidence(k TargetKey, strategy string, now time.Time) (Working, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	v, ok := c.items[k][strategy]
	return v, ok && now.Before(v.Expires) && !now.Before(v.LastTested)
}

func (c *Cache) Quarantined(k TargetKey, strategy string, now time.Time) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	v, ok := c.items[k][strategy]
	return ok && now.Before(v.Expires) && now.Before(v.QuarantinedUntil)
}
