package browserproxy

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"github.com/buzzmean/neexitlag/core/flowpolicy"
	"net"
	"net/netip"
	"sync"
	"time"
)

type DNSRecoveryResult struct {
	Destination     netip.AddrPort `json:"destination"`
	Source          string         `json:"source"`
	Expires         time.Time      `json:"expires"`
	Verified        bool           `json:"verified"`
	AddressVerified bool           `json:"address_verified,omitempty"`
	Failure         string         `json:"failure,omitempty"`
	Probe           ProbeResult    `json:"origin"`
	Trials          []Trial        `json:"trials"`
}
type dnsRecoveryEntry struct {
	result DNSRecoveryResult
	until  time.Time
	done   chan struct{}
}

// DNSRecovery caches authenticated origin address evidence until DNS TTL (max 5min).
// CDN root rejection is address evidence only, never a successful page probe.
// Negative cooldown, singleflight, entry/admission limits bound failure load.
type DNSRecovery struct {
	mu      sync.Mutex
	entries map[string]*dnsRecoveryEntry
	slots   chan struct{}
}

func NewDNSRecovery() *DNSRecovery {
	return &DNSRecovery{entries: map[string]*dnsRecoveryEntry{}, slots: make(chan struct{}, 2)}
}
func DNSCacheKey(k flowpolicy.LearnKey) string { b, _ := json.Marshal(k); return string(b) }
func (r *DNSRecovery) Lookup(key string, now time.Time) (DNSRecoveryResult, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	v := r.entries[key]
	if v == nil || v.done != nil || !now.Before(v.until) {
		return DNSRecoveryResult{}, false
	}
	return v.result, true
}
func (r *DNSRecovery) Recover(ctx context.Context, key, host string, port uint16, roots *x509.CertPool, lookup DNSLookup, open DNSOpen) DNSRecoveryResult {
	return r.RecoverScoped(ctx, key, host, port, roots, lookup, open, nil)
}

// RecoverScoped additionally rejects obsolete automatic-flow evidence. A nil
// guard preserves ordinary browser recovery and its existing cache contract.
func (r *DNSRecovery) RecoverScoped(ctx context.Context, key, host string, port uint16, roots *x509.CertPool, lookup DNSLookup, open DNSOpen, scopeCurrent func() bool) (result DNSRecoveryResult) {
	current := func() bool { return scopeCurrent == nil || scopeCurrent() }
	cancelled := func() DNSRecoveryResult { return DNSRecoveryResult{Failure: "DNS_RECOVERY_SCOPE_CHANGED"} }
	if !current() {
		return cancelled()
	}
	r.mu.Lock()
	now := time.Now()
	for k, v := range r.entries {
		if v.done == nil && !now.Before(v.until) {
			delete(r.entries, k)
		}
	}
	if old := r.entries[key]; old != nil {
		done := old.done
		result := old.result
		r.mu.Unlock()
		if done != nil {
			select {
			case <-done:
				if !current() {
					return cancelled()
				}
				// Read this singleflight's result, never a newer same-key entry.
				r.mu.Lock()
				result, until := old.result, old.until
				r.mu.Unlock()
				if result.Failure == "DNS_RECOVERY_SCOPE_CHANGED" || time.Now().Before(until) {
					return result
				}
			case <-ctx.Done():
			}
			return DNSRecoveryResult{Failure: "DNS_RECOVERY_PENDING"}
		}
		if !current() {
			return cancelled()
		}
		return result
	}
	if len(r.entries) >= 512 {
		r.mu.Unlock()
		return DNSRecoveryResult{Failure: "DNS_RECOVERY_CAPACITY"}
	}
	entry := &dnsRecoveryEntry{done: make(chan struct{})}
	r.entries[key] = entry
	r.mu.Unlock()
	result = DNSRecoveryResult{Failure: "DNS_RECOVERY_UNAVAILABLE"}
	defer func() {
		if !current() {
			result = cancelled()
		}
		r.mu.Lock()
		defer r.mu.Unlock()
		entry.result = result
		if result.Failure == "DNS_RECOVERY_SCOPE_CHANGED" {
			delete(r.entries, key)
		} else {
			entry.until = time.Now().Add(30 * time.Second)
			if result.Usable() {
				entry.until = result.Expires
			}
		}
		close(entry.done)
		entry.done = nil
	}()
	select {
	case r.slots <- struct{}{}:
		defer func() { <-r.slots }()
	case <-ctx.Done():
		return result
	default:
		result.Failure = "DNS_RECOVERY_CAPACITY"
		return result
	}
	// Keep room for the actual NEW Chrome tunnel within the existing proxy budget.
	budget := 2 * time.Second
	if d, ok := ctx.Deadline(); ok {
		if left := time.Until(d) - 750*time.Millisecond; left < budget {
			budget = left
		}
	}
	if budget <= 0 {
		result.Failure = "DNS_RECOVERY_DEADLINE"
		return result
	}
	bounded, stop := context.WithTimeout(ctx, budget)
	defer stop()
	if !current() {
		return cancelled()
	}
	query, queryStop := context.WithTimeout(bounded, 900*time.Millisecond)
	answer, err := lookup(query, host, open)
	queryStop()
	if !current() {
		return cancelled()
	}
	if err != nil {
		result.Failure = "DNS_ALTERNATIVE_FAILED"
		return result
	}
	result.Source = answer.Source
	if answer.ObtainedAt.IsZero() {
		answer.ObtainedAt = time.Now()
	}
	if answer.TTL > 5*time.Minute {
		answer.TTL = 5 * time.Minute
	}
	for i, ip := range answer.Addresses {
		if !current() {
			return cancelled()
		}
		if i >= 2 {
			break
		}
		destination := netip.AddrPortFrom(ip, port)
		started := time.Now()
		probeBudget := time.Second
		count := len(answer.Addresses)
		if count > 2 {
			count = 2
		}
		if deadline, ok := bounded.Deadline(); ok {
			if share := time.Until(deadline) / time.Duration(count-i); share < probeBudget {
				probeBudget = share
			}
		}
		probe, probeStop := context.WithTimeout(bounded, probeBudget)
		checked := ProbeOriginDetailed(probe, host, port, true, roots, func(ctx context.Context) (net.Conn, error) { return open(ctx, destination) })
		probeStop()
		if !current() {
			return cancelled()
		}
		result.Probe = checked
		outcome := checked.Failure
		if outcome == "" {
			outcome = "ORIGIN_RESPONSE"
		}
		result.Trials = append(result.Trials, Trial{Route: "RELAY_REQUIRED", Destination: destination.String(), Phase: checked.Phase, Detail: checked.Detail, Outcome: outcome, HTTPStatus: checked.Status, ALPN: checked.ALPN, TLSVersion: checked.TLSVersion, DurationMS: time.Since(started).Milliseconds()})
		complete := checked.Failure == "" && checked.Phase == "ORIGIN_RESPONSE" && checked.TLSVersion != 0 && checked.Bytes > 0
		httpOK := complete && checked.Status >= 200 && checked.Status < 400
		// googlevideo's / is not a signed media request. An authenticated
		// 403/404 proves the DNS address, not playback or full-site success.
		cdnRoot := complete && flowpolicy.DomainMatches(host, "googlevideo.com") && (checked.Status == 403 || checked.Status == 404)
		if httpOK || cdnRoot {
			result.Verified = httpOK
			result.AddressVerified = true
			result.Failure = ""
			result.Destination = destination
			result.Expires = answer.ObtainedAt.Add(answer.TTL)
			return result
		}
		if bounded.Err() != nil {
			break
		}
	}
	result.Failure = "DNS_ALTERNATIVE_ORIGIN_UNVERIFIED"
	return result
}

// Usable is deliberately separate from Verified (successful HTTP origin probe).
func (r DNSRecoveryResult) Usable() bool { return r.Verified || r.AddressVerified }
func (r DNSRecoveryResult) ProbeName() string {
	if r.Verified {
		return "DNS_RELAY_HTTP_VERIFIED"
	}
	if r.AddressVerified {
		return "DNS_RELAY_ADDRESS_VERIFIED"
	}
	return "DNS_RECOVERY_FAILED"
}
