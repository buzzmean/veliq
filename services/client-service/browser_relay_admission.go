package clientservice

import (
	"context"
	"sync"
	"time"
)

type relayAdmissionPool struct {
	active, waiting                              int
	hits, failures, canceled, waited, idleClosed uint64
	waitTotal, waitMax                           time.Duration
	changed                                      chan struct{}
}

func (u *browserRelayUsage) admissionPool(opaque bool) *relayAdmissionPool {
	if opaque {
		return &u.opaqueAdmission
	}
	return &u.videoAdmission
}
func admissionLimits(opaque bool) (int, int, time.Duration) {
	if opaque {
		return opaqueGoogleRelayLimit, opaqueGoogleWaitLimit, time.Second
	}
	return videoRelayLimit, videoRelayWaitLimit, videoRelayWait
}
func (u *browserRelayUsage) permitLocked(opaque bool) func() {
	p := u.admissionPool(opaque)
	p.active++
	var once sync.Once
	return func() {
		once.Do(func() {
			u.mu.Lock()
			defer u.mu.Unlock()
			p := u.admissionPool(opaque)
			p.active--
			if p.changed != nil {
				close(p.changed)
				p.changed = nil
			}
		})
	}
}
func (u *browserRelayUsage) acquireVideo() (func(), bool) { return u.tryAcquireVideo(true) }
func (u *browserRelayUsage) tryAcquireVideo(count bool, opaque ...bool) (func(), bool) {
	other := len(opaque) > 0 && opaque[0]
	limit, _, _ := admissionLimits(other)
	u.mu.Lock()
	defer u.mu.Unlock()
	p := u.admissionPool(other)
	if p.active >= limit || p.waiting > 0 {
		if count {
			p.hits++
		}
		return nil, false
	}
	return u.permitLocked(other), true
}

// Existing bounded open workers wait here; no extra goroutine or unbounded queue.
// Cancellation is distinct from capacity failure (tab navigation is not VPS failure).
func (u *browserRelayUsage) acquireVideoContext(ctx context.Context, opaque ...bool) (func(), bool) {
	other := len(opaque) > 0 && opaque[0]
	limit, maxWait, budget := admissionLimits(other)
	u.mu.Lock()
	p := u.admissionPool(other)
	if ctx.Err() != nil {
		p.canceled++
		u.mu.Unlock()
		return nil, false
	}
	if p.active < limit && p.waiting == 0 {
		release := u.permitLocked(other)
		u.mu.Unlock()
		return release, true
	}
	p.hits++
	if p.waiting >= maxWait {
		p.failures++
		u.mu.Unlock()
		return nil, false
	}
	p.waiting++
	p.waited++
	u.mu.Unlock()
	start := time.Now()
	defer func() {
		u.mu.Lock()
		p := u.admissionPool(other)
		p.waiting--
		elapsed := time.Since(start)
		p.waitTotal += elapsed
		if elapsed > p.waitMax {
			p.waitMax = elapsed
		}
		u.mu.Unlock()
	}()
	timer := time.NewTimer(budget)
	defer timer.Stop()
	for {
		u.mu.Lock()
		p = u.admissionPool(other)
		if ctx.Err() != nil {
			p.canceled++
			u.mu.Unlock()
			return nil, false
		}
		if p.active < limit {
			release := u.permitLocked(other)
			u.mu.Unlock()
			return release, true
		}
		if p.changed == nil {
			p.changed = make(chan struct{})
		}
		changed := p.changed
		u.mu.Unlock()
		select {
		case <-changed:
		case <-ctx.Done():
			u.mu.Lock()
			u.admissionPool(other).canceled++
			u.mu.Unlock()
			return nil, false
		case <-timer.C:
			u.mu.Lock()
			u.admissionPool(other).failures++
			u.mu.Unlock()
			return nil, false
		}
	}
}
