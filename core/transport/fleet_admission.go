package transport

import (
	"context"
	"sync"
	"time"
)

// FleetAdmission reserves no additional permit. It transfers admission only
// after one redundant legacy session has no remaining leases.
type FleetAdmission struct {
	mu      sync.Mutex
	once    sync.Once
	target  *Pool
	donors  []*Pool
	budget  *FleetBudget
	token   uint64
	until   time.Time
	valid   func() bool
	victim  *Pool
	session uint64
	state   string
	stopped bool
	wake    chan struct{}
	stop    chan struct{}
	done    chan struct{}
}

type FleetAdmissionSnapshot struct {
	State          string  `json:"state"`
	VictimSession  uint64  `json:"victim_session,omitempty"`
	ExistingLeases int     `json:"existing_leases"`
	SessionAgeMS   float64 `json:"session_age_ms"`
	Priority       bool    `json:"slot_priority"`
	VictimFenced   bool    `json:"victim_fenced"`
}

func NewFleetAdmission(target *Pool, donors []*Pool, until time.Time, valid func() bool) *FleetAdmission {
	a := &FleetAdmission{target: target, donors: append([]*Pool(nil), donors...), until: until, valid: valid,
		state: "WAITING_LEGACY_ALTERNATIVE", wake: make(chan struct{}, 1), stop: make(chan struct{}), done: make(chan struct{})}
	a.budget = target.cfg.FleetBudget
	if a.budget == nil {
		a.stopped = true
		a.state = "UNAVAILABLE"
		close(a.done)
		return a
	}
	a.token = a.budget.admissionToken()
	target.mu.Lock()
	if target.admissionToken != 0 {
		a.budget.cancelPriority(target.admissionToken)
	}
	target.admissionToken, target.admissionGuard = a.token, a.allowed
	ready := false
	for _, s := range target.sessions {
		if !target.closed && !target.draining && !s.draining && alive(s.client) && s.client.conn.Context().Err() == nil && !target.fencedLocked(s) {
			ready = true
			break
		}
	}
	if !ready && !target.closed && !target.draining && target.ctx.Err() == nil {
		a.budget.prioritize(target, a.token, until, false)
	}
	target.mu.Unlock()
	go a.run()
	return a
}

func (a *FleetAdmission) Done() <-chan struct{} { return a.done }

func (a *FleetAdmission) allowed() bool {
	a.mu.Lock()
	active, until := !a.stopped, a.until
	a.mu.Unlock()
	a.target.mu.Lock()
	owns := a.target.admissionToken == a.token
	a.target.mu.Unlock()
	return active && owns && time.Now().Before(until) && a.target.ctx.Err() == nil && a.budget.Enabled() && (a.valid == nil || a.valid())
}

// Refresh keeps the victim stable while the same fresh policy is renewed.
func (a *FleetAdmission) Refresh(until time.Time) bool {
	a.mu.Lock()
	if a.stopped || !time.Now().Before(a.until) {
		a.mu.Unlock()
		return false
	}
	if a.until.Equal(until) {
		a.mu.Unlock()
		return true
	}
	a.until = until
	if a.budget.priorityValid(a.token) {
		a.budget.prioritize(a.target, a.token, until, false)
	}
	a.mu.Unlock()
	select {
	case a.wake <- struct{}{}:
	default:
	}
	return true
}

func (a *FleetAdmission) Cancel() {
	if a.budget == nil {
		return
	}
	a.once.Do(func() {
		a.mu.Lock()
		a.stopped = true
		if a.state != "READY" {
			a.state = "CANCELLED"
		}
		victim := a.victim
		a.mu.Unlock()
		if a.budget != nil {
			a.budget.cancelPriority(a.token)
		}
		if victim != nil {
			victim.mu.Lock()
			for _, s := range victim.sessions {
				if s.fence == a.token {
					s.fence = 0
				}
			}
			victim.signalLocked()
			victim.mu.Unlock()
		}
		a.target.mu.Lock()
		if a.target.admissionToken == a.token {
			a.target.admissionToken = 0
			a.target.admissionGuard = nil
		}
		if a.target.creatingToken == a.token && a.target.createCancel != nil {
			a.target.createCancel()
		}
		a.target.signalLocked()
		a.target.mu.Unlock()
		close(a.stop)
	})
}

func (a *FleetAdmission) Snapshot() FleetAdmissionSnapshot {
	a.mu.Lock()
	out := FleetAdmissionSnapshot{State: a.state, VictimSession: a.session}
	victim := a.victim
	a.mu.Unlock()
	out.Priority = a.budget != nil && a.budget.priorityValid(a.token)
	if victim != nil {
		if out.State == "WAITING_EXISTING_LEASES" {
			out.State = "WAITING_SESSION_SETUP"
		}
		victim.mu.Lock()
		for _, s := range victim.sessions {
			if s.id == out.VictimSession {
				out.ExistingLeases = s.active
				out.VictimFenced = victim.fencedLocked(s)
				out.SessionAgeMS = float64(min(7*24*time.Hour, max(time.Duration(0), time.Since(s.born)))) / float64(time.Millisecond)
				if out.VictimFenced && s.active > 0 && out.State == "WAITING_SESSION_SETUP" {
					out.State = "WAITING_EXISTING_LEASES"
				}
			}
		}
		victim.mu.Unlock()
	}
	return out
}

func (p *Pool) HasAdmittingSession() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed || p.draining {
		return false
	}
	for _, s := range p.sessions {
		if !s.draining && !p.fencedLocked(s) && alive(s.client) && s.client.conn.Context().Err() == nil {
			return true
		}
	}
	return false
}

func (p *Pool) fenceForAdmission(a *FleetAdmission, until time.Time) uint64 {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p == a.target || p.closed || p.draining || p.cfg.FleetBudget != a.budget {
		return 0
	}
	var best *poolSession
	for _, s := range p.sessions {
		if s.draining || p.fencedLocked(s) || !alive(s.client) || s.client.conn.Context().Err() != nil {
			continue
		}
		alternative := false
		for _, other := range p.sessions {
			if other != s && !other.draining && !p.fencedLocked(other) && alive(other.client) && other.client.conn.Context().Err() == nil && other.active < p.cfg.SessionFlows-p.cfg.ProbeReserve && !time.Now().Before(other.blockedUntil) {
				alternative = true
				break
			}
		}
		if alternative && (best == nil || s.active < best.active || s.active == best.active && s.id < best.id) {
			best = s
		}
	}
	if best == nil || !a.budget.prioritize(a.target, a.token, until, false) {
		return 0
	}
	best.fence = a.token
	p.reapLocked(time.Now())
	p.signalLocked()
	return best.id
}

func (a *FleetAdmission) run() {
	defer close(a.done)
	defer a.Cancel()
	for {
		if !a.allowed() {
			return
		}
		if a.target.HasAdmittingSession() {
			a.mu.Lock()
			if a.stopped {
				a.mu.Unlock()
				return
			}
			a.state = "READY"
			a.mu.Unlock()
			return
		}
		ch := a.budget.changes()
		a.mu.Lock()
		if a.stopped {
			a.mu.Unlock()
			return
		}
		until, victim := a.until, a.victim
		if !a.budget.priorityValid(a.token) {
			a.budget.prioritize(a.target, a.token, until, false)
		}
		if a.budget.priorityValid(a.token) && a.budget.Snapshot().Sessions >= FleetSessionLimit && victim == nil {
			for _, p := range a.donors {
				if id := p.fenceForAdmission(a, until); id != 0 {
					a.victim, a.session = p, id
					break
				}
			}
		}
		a.mu.Unlock()
		if a.budget.priorityValid(a.token) {
			a.mu.Lock()
			if a.stopped {
				a.mu.Unlock()
				return
			}
			if a.victim != nil {
				a.state = "WAITING_EXISTING_LEASES"
			} else {
				a.state = "WAITING_SESSION_SETUP"
				if a.budget.Snapshot().Sessions >= FleetSessionLimit {
					a.state = "WAITING_NATURAL_SESSION_RELEASE"
				}
			}
			a.mu.Unlock()
			ctx, cancel := context.WithDeadline(a.target.ctx, minTime(until, time.Now().Add(100*time.Millisecond)))
			s, err := a.target.acquireToken(ctx, false, a.token)
			if err == nil {
				a.target.release(s)
			}
			cancel()
		}
		timer := time.NewTimer(min(100*time.Millisecond, max(time.Duration(0), time.Until(until))))
		select {
		case <-a.stop:
			timer.Stop()
			return
		case <-a.target.ctx.Done():
			timer.Stop()
			return
		case <-a.wake:
			timer.Stop()
		case <-ch:
			timer.Stop()
		case <-timer.C:
		}
	}
}

func (a *FleetAdmission) SetDonors(donors []*Pool) {
	a.mu.Lock()
	if !a.stopped && a.victim == nil {
		a.donors = append([]*Pool(nil), donors...)
	}
	a.mu.Unlock()
	select {
	case a.wake <- struct{}{}:
	default:
	}
}

func minTime(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}
