package transport

import "time"

type fleetSessionCreation struct {
	configured bool
	reuse      bool
	allow      bool
	allCreates bool
	until      time.Time
	epoch      uint64
}

// SetFleetAdmission separates permission to reuse a session from permission
// to create another one. Owned managed pools gate every creation; an exact legacy
// alias gates only explicitly tagged fleet operations, preserving manual routes.
// No callback runs under the pool lock. Existing stream/datagram leases survive.
func (p *Pool) SetFleetAdmission(reuse, allow bool, until time.Time, allCreates bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	old := p.fleetCreation
	changed := !old.configured || old.reuse != reuse || old.allow != allow || !old.allCreates && allCreates || until.Before(old.until) || !time.Now().Before(old.until)
	p.fleetCreation.configured, p.fleetCreation.allow, p.fleetCreation.reuse = true, allow, reuse
	p.fleetCreation.until, p.fleetCreation.allCreates = until, allCreates
	if changed {
		p.fleetCreation.epoch++
		if p.creating && (p.creatingFleet || old.allCreates || allCreates) && p.createCancel != nil {
			p.createCancel()
		}
		p.signalLocked()
	}
}

func (p *Pool) fleetReuseAllowedLocked(fleet bool) bool {
	g := p.fleetCreation
	return !g.configured || !fleet && !g.allCreates || g.reuse && time.Now().Before(g.until)
}

func (p *Pool) fleetCreationAllowedLocked(fleet bool) bool {
	g := p.fleetCreation
	return !g.configured || !fleet && !g.allCreates || g.reuse && g.allow && time.Now().Before(g.until)
}

func (p *Pool) fleetCreationCurrentLocked(fleet bool, epoch uint64) bool {
	return p.fleetCreationAllowedLocked(fleet) && (!(fleet || p.fleetCreation.allCreates) || epoch == p.fleetCreation.epoch)
}

// CanCreateFleetSession is a pure projection used before reserving client-side
// handoff priority. Acquire and factory publication independently check again.
func (p *Pool) CanCreateFleetSession() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return !p.closed && !p.draining && p.ctx.Err() == nil && p.fleetCreationAllowedLocked(true)
}

// CanReuseFleetSession reports authorization only, without changing pool state.
// Callers still acquire a live session atomically; this is not a reservation.
func (p *Pool) CanReuseFleetSession() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return !p.closed && !p.draining && p.ctx.Err() == nil && p.fleetReuseAllowedLocked(true)
}
