package controlplane

import (
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// bucket is a token bucket. Callers hold the owning limiter's mutex.
type bucket struct {
	tokens float64
	last   time.Time
}

func (b *bucket) take(now time.Time, rate, burst float64) bool {
	b.tokens += now.Sub(b.last).Seconds() * rate
	if b.tokens > burst {
		b.tokens = burst
	}
	b.last = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// limiter combines a global bucket that protects the database with a bucket per
// source address, so one noisy or hostile client cannot starve the others.
type limiter struct {
	mu                   sync.Mutex
	global               bucket
	perIP                map[string]*bucket
	globalRate, globalBr float64
	ipRate, ipBr         float64
	maxIPs               int
}

func newLimiter(now time.Time) *limiter {
	return &limiter{global: bucket{tokens: 400, last: now}, perIP: make(map[string]*bucket), globalRate: 100, globalBr: 400, ipRate: 30, ipBr: 100, maxIPs: 4096}
}

// sourceKey is the client address. Behind a local reverse proxy (the web
// cabinet) every request arrives from loopback, so only then X-Real-IP is
// trusted: a remote client can never present a loopback address itself.
func sourceKey(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
		if real := net.ParseIP(strings.TrimSpace(r.Header.Get("X-Real-IP"))); real != nil {
			return real.String()
		}
	}
	return host
}

// allow charges the source first, so a rejected source does not consume the
// global budget.
func (l *limiter) allow(now time.Time, source string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	b := l.perIP[source]
	if b == nil {
		if len(l.perIP) >= l.maxIPs {
			// Idle buckets are full and carry no information; drop them.
			for k, v := range l.perIP {
				if now.Sub(v.last) > time.Minute {
					delete(l.perIP, k)
				}
			}
			if len(l.perIP) >= l.maxIPs {
				return false
			}
		}
		b = &bucket{tokens: l.ipBr, last: now}
		l.perIP[source] = b
	}
	if !b.take(now, l.ipRate, l.ipBr) {
		return false
	}
	return l.global.take(now, l.globalRate, l.globalBr)
}

// Club cold boots share a NAT/code: allow the bounded startup burst, then a
// conservative sustained issuance rate. Keys here are IP or SHA256, never codes.
func newEnrollmentLimiter(now time.Time) *limiter {
	l := newLimiter(now)
	l.globalRate = 25
	l.globalBr = 100
	l.global = bucket{tokens: 100, last: now}
	l.ipRate = 5
	l.ipBr = 60
	return l
}

// Login codes go out by email: keep both the per-address and the global rate low.
func newLoginLimiter(now time.Time) *limiter {
	l := newLimiter(now)
	l.globalRate = 5
	l.globalBr = 50
	l.global = bucket{tokens: 50, last: now}
	l.ipRate = 0.2
	l.ipBr = 10
	return l
}
