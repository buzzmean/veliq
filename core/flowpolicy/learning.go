package flowpolicy

import (
	"errors"
	"sync"
	"time"
)

type LearnKey struct {
	Revision    string `json:"revision,omitempty"`
	Network     string `json:"network"`
	Application string `json:"application"`
	Protocol    string `json:"protocol"`
	Target      string `json:"target"`
	Port        uint16 `json:"port"`
}
type Learned struct {
	Score    float64   `json:"score"`
	Key      LearnKey  `json:"key"`
	Result   Result    `json:"result"`
	Success  bool      `json:"success"`
	Observed time.Time `json:"observed"`
	Expires  time.Time `json:"expires"`
}
type Learning struct {
	mu    sync.Mutex
	items map[LearnKey]map[string]Learned
}

func NewLearning() *Learning { return &Learning{items: map[LearnKey]map[string]Learned{}} }
func (l *Learning) Record(v Learned, now time.Time) error {
	if v.Key.Network == "" || len(v.Key.Network) > 128 || v.Key.Application == "" || len(v.Key.Application) > 2048 || v.Key.Target == "" || len(v.Key.Target) > 512 || v.Key.Port == 0 || v.Key.Protocol != "tcp" && v.Key.Protocol != "udp" || v.Observed.After(now.Add(time.Second)) || v.Expires.After(v.Observed.Add(24*time.Hour)) || !now.Before(v.Expires) {
		return errors.New("invalid scoped learning evidence")
	}
	r := Rule{ID: "learned", Action: v.Result.Action, Strategy: v.Result.Strategy, RelayID: v.Result.RelayID, Fallback: v.Result.Fallback}
	if err := r.Validate(); err != nil {
		return err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.cleanup(now)
	if len(l.items) >= 1024 && l.items[v.Key] == nil {
		return errors.New("learning capacity reached")
	}
	if l.items[v.Key] == nil {
		l.items[v.Key] = map[string]Learned{}
	}
	id := string(v.Result.Action) + ":" + v.Result.Strategy
	if len(l.items[v.Key]) >= 12 {
		if _, ok := l.items[v.Key][id]; !ok {
			return errors.New("candidate capacity reached")
		}
	}
	l.items[v.Key][id] = v
	return nil
}
func (l *Learning) cleanup(now time.Time) {
	for k, all := range l.items {
		for id, v := range all {
			if !now.Before(v.Expires) {
				delete(all, id)
			}
		}
		if len(all) == 0 {
			delete(l.items, k)
		}
	}
}
func (l *Learning) Lookup(k LearnKey, now time.Time) (Result, bool) {
	return l.LookupSince(k, time.Time{}, now)
}
func (l *Learning) LookupSince(k LearnKey, after, now time.Time) (Result, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.cleanup(now)
	var best Learned
	for _, v := range l.items[k] {
		if v.Success && !v.Observed.Before(after) && (best.Observed.IsZero() || learnedRank(v.Result.Action) < learnedRank(best.Result.Action) || learnedRank(v.Result.Action) == learnedRank(best.Result.Action) && (v.Score < best.Score || v.Score == best.Score && v.Observed.After(best.Observed))) {
			best = v
		}
	}
	if best.Observed.IsZero() {
		return Result{}, false
	}
	r := best.Result
	r.Source = "learned"
	r.Reason = "application-level proof on this network/target"
	return r, true
}
func (l *Learning) Quarantined(k LearnKey, strategy string, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, v := range l.items[k] {
		if !v.Success && v.Result.Strategy == strategy && now.Before(v.Expires) {
			return true
		}
	}
	return false
}
func (l *Learning) Snapshot(now time.Time) []Learned {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.cleanup(now)
	out := []Learned{}
	for _, all := range l.items {
		for _, v := range all {
			out = append(out, v)
		}
	}
	return out
}
func (l *Learning) HasApplication(network, app, protocol string, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.cleanup(now)
	for k := range l.items {
		if k.Network == network && k.Application == app && k.Protocol == protocol {
			return true
		}
	}
	return false
}

func learnedRank(a Action) int {
	switch a {
	case Direct:
		return 0
	case DirectPlus:
		return 1
	case Relay, RelayRequired:
		return 2
	}
	return 3
}
