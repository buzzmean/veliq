package measurement

import (
	"sort"
	"sync"
	"time"
)

// Probe accounting separates LOSS from DELAY. Scoring is unchanged (an echo not
// answered within Settings.Timeout counts as lost for route selection), but the engine
// keeps listening for LateWindow after the last probe, so a reply that arrives later is
// recorded as late, with its real RTT, instead of vanishing as if the packet was lost.

const (
	accountRing   = 1024
	accountWindow = 5 * time.Minute
)

type sampleKind uint8

const (
	kindOnTime sampleKind = iota + 1
	kindNoReply
	kindLate
	kindSendError
)

type sampleRecord struct {
	id   uint64
	at   time.Time
	kind sampleKind
	rtt  time.Duration
}

type routeAccount struct {
	mu     sync.Mutex
	since  time.Time
	nextID uint64
	ring   []sampleRecord
}

func newRouteAccount(now time.Time) *routeAccount { return &routeAccount{since: now} }

func (a *routeAccount) add(at time.Time, kind sampleKind, rtt time.Duration) uint64 {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.nextID++
	if len(a.ring) >= accountRing {
		a.ring = a.ring[1:]
	}
	a.ring = append(a.ring, sampleRecord{id: a.nextID, at: at, kind: kind, rtt: rtt})
	return a.nextID
}

// late turns a no-reply sample into a late one. It reports false when the sample has
// already left the ring or was already resolved.
func (a *routeAccount) late(id uint64, rtt time.Duration) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	for i := len(a.ring) - 1; i >= 0; i-- {
		if a.ring[i].id == id {
			if a.ring[i].kind != kindNoReply {
				return false
			}
			a.ring[i].kind, a.ring[i].rtt = kindLate, rtt
			return true
		}
	}
	return false
}

// AccountWindow summarizes probes for one route over a period. Counts are probes
// that were actually handed to the transport (Sent); SendErrors never left the host.
type AccountWindow struct {
	Sent       uint64 `json:"sent"`
	OnTime     uint64 `json:"on_time"`
	Late       uint64 `json:"late"`
	NoReply    uint64 `json:"no_reply"`
	SendErrors uint64 `json:"send_errors"`
	// LossStrictPercent is what route scoring sees: not answered within the timeout.
	LossStrictPercent float64 `json:"loss_strict_percent"`
	// LossTruePercent is never answered, even inside the late window.
	LossTruePercent float64 `json:"loss_true_percent"`
	LatePercent     float64 `json:"late_percent"`
	OnTimeRTTAvgMs  float64 `json:"on_time_rtt_avg_ms"`
	LateRTTAvgMs    float64 `json:"late_rtt_avg_ms"`
	LateRTTMaxMs    float64 `json:"late_rtt_max_ms"`
}

type AccountView struct {
	RouteID  string        `json:"route_id"`
	Since    time.Time     `json:"since"`
	Scope    string        `json:"scope"`
	All      AccountWindow `json:"all_retained"`
	Last5Min AccountWindow `json:"last_5_min"`
}

func summarize(records []sampleRecord, from time.Time) AccountWindow {
	var w AccountWindow
	var onTime, late time.Duration
	for _, r := range records {
		if r.at.Before(from) {
			continue
		}
		switch r.kind {
		case kindOnTime:
			w.Sent++
			w.OnTime++
			onTime += r.rtt
		case kindLate:
			w.Sent++
			w.Late++
			late += r.rtt
			if ms := float64(r.rtt) / float64(time.Millisecond); ms > w.LateRTTMaxMs {
				w.LateRTTMaxMs = ms
			}
		case kindNoReply:
			w.Sent++
			w.NoReply++
		case kindSendError:
			w.SendErrors++
		}
	}
	if w.Sent > 0 {
		sent := float64(w.Sent)
		w.LossStrictPercent = round1(100 * float64(w.Late+w.NoReply) / sent)
		w.LossTruePercent = round1(100 * float64(w.NoReply) / sent)
		w.LatePercent = round1(100 * float64(w.Late) / sent)
	}
	if w.OnTime > 0 {
		w.OnTimeRTTAvgMs = round1(float64(onTime) / float64(w.OnTime) / float64(time.Millisecond))
	}
	if w.Late > 0 {
		w.LateRTTAvgMs = round1(float64(late) / float64(w.Late) / float64(time.Millisecond))
	}
	return w
}
func round1(v float64) float64 { return float64(int64(v*10+0.5)) / 10 }

func (a *routeAccount) view(id string, now time.Time) AccountView {
	a.mu.Lock()
	records := append([]sampleRecord(nil), a.ring...)
	since := a.since
	a.mu.Unlock()
	return AccountView{RouteID: id, Since: since, Scope: "last 1024 probes per route; late = reply after the timeout, with real RTT",
		All: summarize(records, time.Time{}), Last5Min: summarize(records, now.Add(-accountWindow))}
}

func (e *Engine) account(route string, now time.Time) *routeAccount {
	e.accountMu.Lock()
	defer e.accountMu.Unlock()
	if e.accounts == nil {
		e.accounts = make(map[string]*routeAccount)
	}
	a := e.accounts[route]
	if a == nil {
		if len(e.accounts) >= 64 {
			return newRouteAccount(now) // bounded: never retained, never grows memory
		}
		a = newRouteAccount(now)
		e.accounts[route] = a
	}
	return a
}

// Accounts returns per-route probe accounting, sorted by route ID.
func (e *Engine) Accounts(now time.Time) []AccountView {
	e.accountMu.Lock()
	ids := make([]string, 0, len(e.accounts))
	for id := range e.accounts {
		ids = append(ids, id)
	}
	e.accountMu.Unlock()
	sort.Strings(ids)
	out := make([]AccountView, 0, len(ids))
	for _, id := range ids {
		e.accountMu.Lock()
		a := e.accounts[id]
		e.accountMu.Unlock()
		if a != nil {
			out = append(out, a.view(id, now))
		}
	}
	return out
}
