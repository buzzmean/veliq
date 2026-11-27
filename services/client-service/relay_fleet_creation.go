package clientservice

import (
	"time"

	"github.com/buzzmean/veliq/core/transport"
)

type fleetSessionCreation struct {
	id      string
	pool    *transport.Pool
	owned   bool
	reuse   bool
	allow   bool
	network string
	until   time.Time
}

// The list is bounded by the signed policy (at most four candidates). Its pool
// policies are scalar state: transport never calls back into client locks.
func (f *relayFleet) setSessionCreations(next []fleetSessionCreation) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, old := range f.sessionCreations {
		kept := false
		for _, entry := range next {
			kept = kept || entry.pool == old.pool
		}
		if !kept {
			old.pool.SetFleetAdmission(false, false, time.Time{}, old.owned)
		}
	}
	f.sessionCreations = append([]fleetSessionCreation(nil), next...)
	for _, entry := range f.sessionCreations {
		entry.pool.SetFleetAdmission(entry.reuse, entry.allow, entry.until, entry.owned)
	}
}

func (f *relayFleet) denySessionCreationsLocked() {
	for i := range f.sessionCreations {
		entry := &f.sessionCreations[i]
		entry.reuse, entry.allow = false, false
		entry.pool.SetFleetAdmission(false, false, time.Time{}, entry.owned)
	}
}

func (f *relayFleet) invalidateCreationNetworkLocked(network string) {
	for i := range f.sessionCreations {
		entry := &f.sessionCreations[i]
		if network == "" || entry.network != network {
			entry.reuse, entry.allow = false, false
			entry.pool.SetFleetAdmission(false, false, time.Time{}, entry.owned)
		}
	}
}

func (f *relayFleet) shareSessionCreationWithLegacy(pool *transport.Pool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for i := range f.sessionCreations {
		entry := &f.sessionCreations[i]
		if entry.pool == pool {
			entry.owned = false
			pool.SetFleetAdmission(entry.reuse, entry.allow, entry.until, false)
		}
	}
}

// An in-place legacy endpoint update must not inherit the old fleet scope,
// including after an ordinary manual open authenticates a session there.
func (f *relayFleet) denyPoolAdmission(pool *transport.Pool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for i := range f.sessionCreations {
		entry := &f.sessionCreations[i]
		if entry.pool == pool {
			entry.reuse, entry.allow = false, false
			pool.SetFleetAdmission(false, false, time.Time{}, entry.owned)
		}
	}
}
