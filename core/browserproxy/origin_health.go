package browserproxy

import (
	"context"
	"errors"
	"net/netip"
	"sync"
	"time"
)

const OriginNegativeTTL = time.Minute

type originBadKey struct {
	scope string
	ip    netip.AddrPort
}
type originDNS struct {
	err    error
	answer DNSAnswer
	until  time.Time
	done   chan struct{}
}

// OriginHealth is process-local, bounded and network/profile/domain/relay scoped.
// No permanent successful-IP pin: negative TTL expiry permits a fresh real trial.
type OriginHealth struct {
	mu    sync.Mutex
	bad   map[originBadKey]time.Time
	dns   map[string]*originDNS
	slots chan struct{}
}

func NewOriginHealth() *OriginHealth {
	return &OriginHealth{bad: map[originBadKey]time.Time{}, dns: map[string]*originDNS{}, slots: make(chan struct{}, 2)}
}
func (h *OriginHealth) Failed(scope string, ip netip.AddrPort, now time.Time) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for k, v := range h.bad {
		if !now.Before(v) {
			delete(h.bad, k)
		}
	}
	if len(h.bad) < 1024 || !h.bad[originBadKey{scope, ip}].IsZero() {
		h.bad[originBadKey{scope, ip}] = now.Add(OriginNegativeTTL)
	}
}
func (h *OriginHealth) Pick(scope string, candidates []netip.AddrPort, tried map[netip.AddrPort]bool, now time.Time) (netip.AddrPort, int) {
	h.mu.Lock()
	defer h.mu.Unlock()
	skipped := 0
	seen := map[netip.AddrPort]bool{}
	for _, ip := range candidates {
		if seen[ip] {
			continue
		}
		seen[ip] = true
		if !ip.IsValid() || tried[ip] {
			continue
		}
		k := originBadKey{scope, ip}
		if until := h.bad[k]; now.Before(until) {
			skipped++
			continue
		}
		delete(h.bad, k)
		return ip, skipped
	}
	return netip.AddrPort{}, skipped
}

// Resolve caches TTL-bound, verified-HTTPS DoH ANSWERS, not origin health/PASS.
// One query per scope; max two concurrent resolutions, 256 entries, 64 addresses.
func (h *OriginHealth) Resolve(ctx context.Context, scope string, lookup func(context.Context) (DNSAnswer, error)) (DNSAnswer, error) {
	now := time.Now()
	h.mu.Lock()
	for k, v := range h.dns {
		if v.done == nil && !now.Before(v.until) {
			delete(h.dns, k)
		}
	}
	if v := h.dns[scope]; v != nil {
		done := v.done
		if done == nil {
			a := v.answer
			a.Addresses = append([]netip.Addr(nil), a.Addresses...)
			h.mu.Unlock()
			return a, v.err
		}
		h.mu.Unlock()
		select {
		case <-done:
			h.mu.Lock()
			a := v.answer
			a.Addresses = append([]netip.Addr(nil), a.Addresses...)
			err := v.err
			h.mu.Unlock()
			return a, err
		case <-ctx.Done():
			return DNSAnswer{}, ctx.Err()
		}
	}
	if len(h.dns) >= 256 {
		h.mu.Unlock()
		return DNSAnswer{}, errors.New("ORIGIN_DNS_CAPACITY")
	}
	v := &originDNS{done: make(chan struct{})}
	h.dns[scope] = v
	h.mu.Unlock()
	select {
	case h.slots <- struct{}{}:
		defer func() { <-h.slots }()
	default:
		h.mu.Lock()
		v.err = errors.New("ORIGIN_DNS_CAPACITY")
		v.until = time.Now().Add(time.Second)
		close(v.done)
		v.done = nil
		h.mu.Unlock()
		return DNSAnswer{}, errors.New("ORIGIN_DNS_CAPACITY")
	}
	a, err := lookup(ctx)
	// A cancelled policy/owner scope is not DNS evidence. Release all existing
	// waiters with the same error, but allow the next current flow a fresh query.
	if errors.Is(err, ErrOriginScopeChanged) {
		h.mu.Lock()
		v.err = err
		delete(h.dns, scope)
		close(v.done)
		v.done = nil
		h.mu.Unlock()
		return DNSAnswer{}, err
	}
	if len(a.Addresses) > 64 {
		a.Addresses = a.Addresses[:64]
	}
	a.Addresses = append([]netip.Addr(nil), a.Addresses...)
	until := time.Now().Add(time.Second)
	if err == nil && len(a.Addresses) > 0 {
		obtained := a.ObtainedAt
		if obtained.IsZero() {
			obtained = time.Now()
		}
		ttl := a.TTL
		if ttl > 5*time.Minute {
			ttl = 5 * time.Minute
		}
		if ttl < 0 {
			ttl = 0
		}
		until = obtained.Add(ttl)
	}
	h.mu.Lock()
	v.answer = a
	v.err = err
	v.until = until
	close(v.done)
	v.done = nil
	h.mu.Unlock()
	return a, err
}

// Unknown network fingerprints must never share cached DNS/negative evidence,
// but still share the same global two-worker admission bound.
func (h *OriginHealth) Uncached(ctx context.Context, lookup func(context.Context) (DNSAnswer, error)) (DNSAnswer, error) {
	select {
	case h.slots <- struct{}{}:
		defer func() { <-h.slots }()
	case <-ctx.Done():
		return DNSAnswer{}, ctx.Err()
	default:
		return DNSAnswer{}, errors.New("ORIGIN_DNS_CAPACITY")
	}
	return lookup(ctx)
}
