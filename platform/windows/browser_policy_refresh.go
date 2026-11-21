package windowsplatform

import (
	"sync"
	"time"
)

// A request is not evidence that Chromium reloaded policy. No SID/PAC/secret
// values are exposed. One outstanding native operation bounds stalled GP RPC.
type BrowserPolicyRefreshView struct {
	State      string    `json:"state"`
	At         time.Time `json:"at"`
	Requests   uint64    `json:"requests"`
	LiveUptake string    `json:"live_uptake"`
}
type policyRefreshQueue struct {
	mu         sync.Mutex
	busy       bool
	dirty      bool
	pendingSID string
	view       BrowserPolicyRefreshView
}

var browserPolicyRefresh policyRefreshQueue

func BrowserPolicyRefreshStatus() BrowserPolicyRefreshView { return browserPolicyRefresh.snapshot() }
func (q *policyRefreshQueue) snapshot() BrowserPolicyRefreshView {
	q.mu.Lock()
	defer q.mu.Unlock()
	v := q.view
	v.LiveUptake = "NOT_OBSERVED"
	return v
}
func (q *policyRefreshQueue) request(sid string, refresh func(string) string) {
	q.mu.Lock()
	if q.busy {
		q.dirty = true
		q.pendingSID = sid
		q.mu.Unlock()
		return
	}
	q.busy = true
	q.view.Requests++
	q.view.State = "USER_POLICY_REFRESH_PENDING"
	q.view.At = time.Now()
	q.mu.Unlock()
	go func() {
		for {
			state := refresh(sid)
			q.mu.Lock()
			q.view.State = state
			q.view.At = time.Now()
			if !q.dirty {
				q.busy = false
				q.mu.Unlock()
				return
			}
			sid = q.pendingSID
			q.pendingSID = ""
			q.dirty = false
			q.view.Requests++
			q.view.State = "USER_POLICY_REFRESH_PENDING"
			q.mu.Unlock()
		}
	}()
}
