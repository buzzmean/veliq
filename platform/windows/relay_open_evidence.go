package windowsplatform

import (
	"errors"
	"time"
)

type RelayOpenEvidence struct {
	DurationMS    float64 `json:"duration_ms"`
	FailureReason string  `json:"failure_reason,omitempty"`
}
type UDPQueueEvidence struct {
	Capacity        int     `json:"capacity"`
	HighWater       int     `json:"high_water"`
	DropsDuringOpen uint64  `json:"drops_during_open"`
	DropsAfterOpen  uint64  `json:"drops_after_open"`
	MaxWaitMS       float64 `json:"max_wait_ms"`
}

func (l *EvidenceLedger) RecordRelayOpen(id ProcessIdentity, t Tuple, start time.Time, err error) {
	reason := ""
	if err != nil {
		reason = "transport_open_failed"
		var classified interface{ FailureReason() string }
		if errors.As(err, &classified) {
			reason = classified.FailureReason()
		}
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	k := l.keyLocked(id, t)
	v, ok := l.lookupLocked(k)
	if !ok {
		return
	}
	if v.HotAttach != nil {
		h := *v.HotAttach
		h.State = "HOT_ATTACH_ROUTE_OPENED"
		if err != nil {
			h.State = "HOT_ATTACH_ROUTE_FAILED"
		}
		v.HotAttach = &h
	}
	v.RelayOpen = &RelayOpenEvidence{float64(time.Since(start)) / float64(time.Millisecond), reason}
	l.storeLocked(k, v)
}
func (l *EvidenceLedger) RecordUDPQueue(id ProcessIdentity, t Tuple, depth int, opening, dropped bool, wait time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	k := l.keyLocked(id, t)
	v, ok := l.lookupLocked(k)
	if !ok {
		return
	}
	q := UDPQueueEvidence{Capacity: 32}
	if v.UDPQueue != nil {
		q = *v.UDPQueue
	}
	changed := v.UDPQueue == nil
	if depth > q.HighWater {
		q.HighWater = depth
		changed = true
	}
	if dropped {
		if opening {
			q.DropsDuringOpen++
		} else {
			q.DropsAfterOpen++
		}
		changed = true
	}
	ms := float64(wait) / float64(time.Millisecond)
	if ms > q.MaxWaitMS {
		q.MaxWaitMS = ms
		changed = true
	}
	if changed {
		v.UDPQueue = &q
		l.storeLocked(k, v)
	}
}
