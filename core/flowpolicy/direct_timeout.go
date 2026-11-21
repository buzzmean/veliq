package flowpolicy

import (
	"sort"
	"sync"
	"time"
)

// DirectTimeoutCache remembers origins whose DIRECT connection attempts hit a
// connect timeout (SYN without answer) so later flows go straight to the relay
// instead of paying the timeout again. It only ever moves traffic TOWARDS the relay:
// it never authorizes DIRECT, and a cached origin is re-checked by one background
// DIRECT probe per TTL so traffic returns to DIRECT when the path recovers.
//
// Address-aware callers record a failed destination immediately; only TWO DISTINCT
// failed IPs within TimeoutWindow promote the domain. Legacy callers without an
// address retain their two-event contract. Cancellation/HTTP errors do not create
// verdicts. Only verified end-to-end success clears them.
type DirectTimeoutCache struct {
	mu      sync.Mutex
	entries map[DirectTimeoutKey]*directTimeoutEntry
	// Cumulative counters, visible in diagnostics to judge the load on the relay.
	hits, created, revalidations, recovered  uint64
	stalls, stallRetries, stallRetryFailures uint64
}

type DirectTimeoutKey struct {
	Network     string
	Application string
	Host        string
	Port        uint16
	Address     string // Empty is a domain verdict; nonempty is a specific destination IP.
}

const (
	TimeoutWindow     = 60 * time.Second
	DirectTimeoutTTL  = 10 * time.Minute
	directTimeoutCap  = 256
	probeRetryOnError = time.Minute
)

type directTimeoutEntry struct {
	addresses    map[string]bool // Bounded at two distinct failed addresses, never packet bursts.
	reason       string
	probeHost    string
	firstFailure time.Time
	failures     int
	active       bool
	since        time.Time
	nextProbe    time.Time
	probing      bool
	hits         uint64
	lastHit      time.Time
}

func NewDirectTimeoutCache() *DirectTimeoutCache {
	return &DirectTimeoutCache{entries: make(map[DirectTimeoutKey]*directTimeoutEntry)}
}

// RecordTimeout notes one DIRECT connect timeout. It returns true when this call
// made (or renewed) the origin active.
func (c *DirectTimeoutCache) RecordTimeout(k DirectTimeoutKey, now time.Time) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if k.Address != "" {
		// Keep an address verdict immediately, but a whole-domain verdict needs two
		// DIFFERENT failed IPs. Repeating a timeout on one server never poisons its peers.
		domain := k
		domain.Address = ""
		e := c.entries[domain]
		if e == nil {
			c.makeRoom(now)
			e = &directTimeoutEntry{}
			c.entries[domain] = e
		}
		if e.addresses == nil || (!e.active && now.Sub(e.firstFailure) > TimeoutWindow) {
			e.addresses = map[string]bool{}
			e.firstFailure = now
		}
		if len(e.addresses) < 2 {
			e.addresses[k.Address] = true
		}
		e.failures = len(e.addresses)
		if e.failures >= 2 {
			if !e.active {
				c.created++
				e.since = now
			}
			e.active = true
			e.nextProbe = now.Add(DirectTimeoutTTL)
			e.reason = "TWO_DISTINCT_DIRECT_ADDRESSES_FAILED"
		}
		addr := c.entries[k]
		if addr == nil {
			c.makeRoom(now)
			addr = &directTimeoutEntry{firstFailure: now, since: now}
			c.entries[k] = addr
		}
		addr.active = true
		addr.nextProbe = now.Add(DirectTimeoutTTL)
		addr.reason = "DIRECT_ADDRESS_FAILED"
		return e.active
	}
	e := c.entries[k]
	if e == nil {
		c.makeRoom(now)
		e = &directTimeoutEntry{}
		c.entries[k] = e
	}
	if e.active {
		// A fresh timeout while cached confirms the path is still dead: renew.
		e.nextProbe = now.Add(DirectTimeoutTTL)
		return true
	}
	if e.failures == 0 || now.Sub(e.firstFailure) > TimeoutWindow {
		e.failures, e.firstFailure = 1, now
		return false
	}
	e.failures++
	e.active, e.since, e.nextProbe = true, now, now.Add(DirectTimeoutTTL)
	c.created++
	return true
}

// RecordStall notes a DIRECT tunnel that got no answer after the ClientHello. It is the
// same class of failure as a connect timeout and follows the same rules.
func (c *DirectTimeoutCache) RecordStall(k DirectTimeoutKey, now time.Time) bool {
	c.mu.Lock()
	c.stalls++
	c.mu.Unlock()
	return c.RecordTimeout(k, now)
}

// RecordOriginStall promotes a domain after an actual silent ClientHello, when
// the caller has evidence that address rotation cannot bypass that domain's SNI
// filtering. It never authorizes DIRECT and retains the normal TTL/recheck.
func (c *DirectTimeoutCache) RecordOriginStall(k DirectTimeoutKey, now time.Time) {
	c.RecordStall(k, now)
	k.Address = ""
	c.mu.Lock()
	defer c.mu.Unlock()
	e := c.entries[k]
	if e == nil {
		c.makeRoom(now)
		e = &directTimeoutEntry{}
		c.entries[k] = e
	}
	if !e.active {
		c.created++
		e.since = now
	}
	e.active = true
	e.nextProbe = now.Add(DirectTimeoutTTL)
	e.reason = "DIRECT_ORIGIN_CLIENTHELLO_STALL"
}

// NoteRetry counts the outcome of a transparent retry through the relay.
func (c *DirectTimeoutCache) NoteRetry(ok bool) {
	c.mu.Lock()
	if ok {
		c.stallRetries++
	} else {
		c.stallRetryFailures++
	}
	c.mu.Unlock()
}

// RecordSuccess clears a verdict only after caller-verified application success.
func (c *DirectTimeoutCache) RecordSuccess(k DirectTimeoutKey) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if k.Address != "" {
		domain := k
		domain.Address = ""
		if e := c.entries[domain]; e != nil {
			if e.active {
				c.recovered++
			}
			delete(c.entries, domain)
		}
	}
	if e := c.entries[k]; e != nil {
		if e.active && k.Address == "" {
			c.recovered++
		}
		delete(c.entries, k)
	}
}

// Lookup reports whether flows to k must go straight to the relay. due is true
// when the TTL elapsed and the caller should start one background DIRECT probe
// (claimed atomically: only one caller gets due=true until ProbeDone).
func (c *DirectTimeoutCache) Lookup(k DirectTimeoutKey, now time.Time) (active, due bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e := c.entries[k]
	if e == nil || !e.active {
		return false, false
	}
	e.hits++
	e.lastHit = now
	c.hits++
	if !e.probing && !now.Before(e.nextProbe) {
		e.probing = true
		c.revalidations++
		return true, true
	}
	return true, false
}

// ProbeDone ends a background probe. Success/failure of the probe itself is fed
// through RecordSuccess/RecordTimeout; an inconclusive probe (the owner exited, a
// reset...) is retried soon instead of waiting a whole TTL.
func (c *DirectTimeoutCache) ProbeDone(k DirectTimeoutKey, now time.Time, conclusive bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e := c.entries[k]
	if e == nil {
		return
	}
	e.probing = false
	if !conclusive {
		e.nextProbe = now.Add(probeRetryOnError)
	}
}

func (c *DirectTimeoutCache) makeRoom(now time.Time) {
	for k, e := range c.entries {
		if !e.active && now.Sub(e.firstFailure) > TimeoutWindow {
			delete(c.entries, k)
		}
	}
	if len(c.entries) < directTimeoutCap {
		return
	}
	var oldest DirectTimeoutKey
	var at time.Time
	first := true
	for k, e := range c.entries {
		t := e.firstFailure
		if e.active {
			t = e.since
		}
		if first || t.Before(at) {
			oldest, at, first = k, t, false
		}
	}
	delete(c.entries, oldest)
}

// AddressFailed is only a bounded skip hint, never authorization to use DIRECT.
func (c *DirectTimeoutCache) AddressFailed(k DirectTimeoutKey, now time.Time) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	e := c.entries[k]
	return k.Address != "" && e != nil && e.active && now.Before(e.nextProbe)
}

type DirectTimeoutOrigin struct {
	Group           string    `json:"group,omitempty"`
	ProbeHost       string    `json:"probe_host,omitempty"`
	Network         string    `json:"network"`
	Application     string    `json:"profile_id"`
	Address         string    `json:"address,omitempty"`
	Reason          string    `json:"reason"`
	FailedAddresses int       `json:"distinct_failed_addresses"`
	RemainingMS     int64     `json:"ttl_remaining_ms"`
	Probing         bool      `json:"recheck_in_progress"`
	Host            string    `json:"host"`
	Port            uint16    `json:"port"`
	Hits            uint64    `json:"relay_steered_flows"`
	Since           time.Time `json:"since"`
	NextProbe       time.Time `json:"next_direct_probe"`
}

type DirectTimeoutStats struct {
	ActiveAddresses int                   `json:"active_addresses"`
	ActiveOrigins   int                   `json:"active_origins"`
	Hits            uint64                `json:"relay_steered_flows"`
	Created         uint64                `json:"origins_cached_total"`
	Revalidations   uint64                `json:"background_direct_probes"`
	RecoveredDirect uint64                `json:"recovered_to_direct"`
	Stalls          uint64                `json:"direct_stalls_total"`
	StallRetries    uint64                `json:"stall_retries_via_relay"`
	StallRetryFails uint64                `json:"stall_retries_failed"`
	Top             []DirectTimeoutOrigin `json:"top_origins"`
}

// Stats returns counters and the busiest origins (at most 20) for diagnostics.
func (c *DirectTimeoutCache) Stats() DirectTimeoutStats {
	c.mu.Lock()
	defer c.mu.Unlock()
	s := DirectTimeoutStats{Hits: c.hits, Created: c.created, Revalidations: c.revalidations, RecoveredDirect: c.recovered,
		Stalls: c.stalls, StallRetries: c.stallRetries, StallRetryFails: c.stallRetryFailures}
	for k, e := range c.entries {
		if !e.active {
			continue
		}
		if k.Address == "" {
			s.ActiveOrigins++
		} else {
			s.ActiveAddresses++
		}
		remaining := time.Until(e.nextProbe).Milliseconds()
		if remaining < 0 {
			remaining = 0
		}
		s.Top = append(s.Top, DirectTimeoutOrigin{Group: BrowserRelayGroup(k.Host), ProbeHost: e.probeHost, Network: k.Network, Application: k.Application, Address: k.Address, Reason: e.reason, FailedAddresses: len(e.addresses), RemainingMS: remaining, Probing: e.probing, Host: k.Host, Port: k.Port, Hits: e.hits, Since: e.since, NextProbe: e.nextProbe})
	}
	sort.Slice(s.Top, func(i, j int) bool {
		if s.Top[i].Hits != s.Top[j].Hits {
			return s.Top[i].Hits > s.Top[j].Hits
		}
		return s.Top[i].Host < s.Top[j].Host
	})
	if len(s.Top) > 20 {
		s.Top = s.Top[:20]
	}
	return s
}
