package transport

import (
	"sync"
	"time"
)

const (
	FleetSessionLimit     = 2
	FleetApplicationLimit = 47
	FleetProbeLimit       = 1
	FleetWaitingLimit     = 16
	FleetEchoLimit        = 10
	FleetEchoWindow       = 5 * time.Second
)

type fleetResource uint8

const (
	fleetSession fleetResource = iota
	fleetApplication
	fleetProbe
	fleetWaiter
	fleetResources
)

// FleetBudget is owned by the client, not by a particular relay or config.
// Pools debit it even when the feature is off, so a hot opt-in accounts for
// pre-existing work without revoking a permit that has already been issued.
type FleetBudget struct {
	mu            sync.Mutex
	enabled       bool
	used          [fleetResources]int
	echoes        [FleetEchoLimit]time.Time
	echoIndex     int
	changed       chan struct{}
	nextAdmission uint64
	priority      uint64
	priorityPool  *Pool
	priorityUntil time.Time
}

func (b *FleetBudget) signalLocked() {
	if b.changed != nil {
		close(b.changed)
	}
	b.changed = make(chan struct{})
}

func (b *FleetBudget) changes() <-chan struct{} {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.changed == nil {
		b.changed = make(chan struct{})
	}
	return b.changed
}

type FleetOccupancy struct {
	Enabled      bool `json:"enabled"`
	Sessions     int  `json:"sessions"`
	Applications int  `json:"application_flows"`
	Probes       int  `json:"probe_flows"`
	Waiting      int  `json:"waiting_opens"`
}

func (b *FleetBudget) SetEnabled(enabled bool) {
	b.mu.Lock()
	b.enabled = enabled
	if !enabled {
		b.priority, b.priorityPool = 0, nil
	}
	b.signalLocked()
	b.mu.Unlock()
}

func (b *FleetBudget) Snapshot() FleetOccupancy {
	if b == nil {
		return FleetOccupancy{}
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	return FleetOccupancy{
		Enabled:      b.enabled,
		Sessions:     b.used[fleetSession],
		Applications: b.used[fleetApplication],
		Probes:       b.used[fleetProbe],
		Waiting:      b.used[fleetWaiter],
	}
}

func (b *FleetBudget) Enabled() bool {
	if b == nil {
		return false
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.enabled
}

func (b *FleetBudget) overSessionLimit() bool {
	if b == nil {
		return false
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.enabled && b.used[fleetSession] > FleetSessionLimit
}

func (b *FleetBudget) reserve(resource fleetResource) (func(), bool) {
	return b.reserveOwned(resource, nil)
}

func (b *FleetBudget) reserveOwned(resource fleetResource, owner *Pool) (func(), bool) {
	if b == nil {
		return func() {}, true
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	limits := [...]int{FleetSessionLimit, FleetApplicationLimit, FleetProbeLimit, FleetWaitingLimit}
	if b.priority != 0 && !time.Now().Before(b.priorityUntil) {
		b.priority, b.priorityPool = 0, nil
		b.signalLocked()
	}
	if b.enabled {
		if resource == fleetSession && b.priority != 0 && owner != b.priorityPool && b.used[fleetSession] >= FleetSessionLimit-1 {
			return nil, false
		}
		if b.used[resource] >= limits[resource] {
			return nil, false
		}
		if (resource == fleetApplication || resource == fleetProbe) &&
			b.used[fleetApplication]+b.used[fleetProbe] >= FleetApplicationLimit+FleetProbeLimit {
			return nil, false
		}
	}
	b.used[resource]++
	var once sync.Once
	return func() {
		once.Do(func() {
			b.mu.Lock()
			b.used[resource]--
			if resource == fleetSession {
				b.signalLocked()
			}
			b.mu.Unlock()
		})
	}, true
}

func (b *FleetBudget) admissionToken() uint64 {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.nextAdmission++
	if b.nextAdmission == 0 {
		b.nextAdmission++
	}
	return b.nextAdmission
}

func (b *FleetBudget) prioritize(pool *Pool, token uint64, until time.Time, freeOnly bool) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	if !b.enabled || !time.Now().Before(until) {
		return false
	}
	if b.priority != 0 && !time.Now().Before(b.priorityUntil) {
		b.priority, b.priorityPool = 0, nil
	}
	if b.priority != 0 && b.priority != token || freeOnly && b.used[fleetSession] >= FleetSessionLimit {
		return false
	}
	b.priority, b.priorityPool, b.priorityUntil = token, pool, until
	b.signalLocked()
	return true
}

func (b *FleetBudget) priorityValid(token uint64) bool {
	if b == nil || token == 0 {
		return false
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.enabled && b.priority == token && time.Now().Before(b.priorityUntil)
}

func (b *FleetBudget) cancelPriority(token uint64) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.priority == token {
		b.priority, b.priorityPool = 0, nil
		b.signalLocked()
	}
}

func (b *FleetBudget) allowEcho(now time.Time) bool {
	if b == nil {
		return true
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if !b.enabled {
		// Preserve the last transmissions while off for a hot opt-in.
		b.echoes[b.echoIndex] = now
		b.echoIndex = (b.echoIndex + 1) % len(b.echoes)
		return true
	}
	oldest := b.echoes[b.echoIndex]
	if !oldest.IsZero() && now.Sub(oldest) < FleetEchoWindow {
		return false
	}
	b.echoes[b.echoIndex] = now
	b.echoIndex = (b.echoIndex + 1) % len(b.echoes)
	return true
}
