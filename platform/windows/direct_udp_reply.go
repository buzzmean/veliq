package windowsplatform

import (
	"github.com/buzzmean/veliq/core/flowpolicy"
	"sync"
	"time"
)

// DirectUDPReplyEvidence describes passive metadata, not game join or loss.
// A zero counter is meaningful only together with observer availability/scope.
type DirectUDPReplyEvidence struct {
	State           string    `json:"state"`
	Reason          string    `json:"reason"`
	IdentityBound   bool      `json:"identity_bound"`
	FilterCovered   bool      `json:"filter_covered"`
	FromFirstPacket bool      `json:"from_first_packet"`
	FirstReply      time.Time `json:"first_reply,omitzero"`
	LastReply       time.Time `json:"last_reply,omitzero"`
}

type UDPReplyObserverStatus struct {
	Available            bool      `json:"available"`
	Reason               string    `json:"reason"`
	StartedAt            time.Time `json:"started_at,omitzero"`
	NativeError          uint32    `json:"native_error,omitempty"`
	KernelQueueLossKnown bool      `json:"kernel_queue_loss_known"`
}

type udpReplyObserverState struct {
	mu sync.Mutex
	s  UDPReplyObserverStatus
}

func (s *udpReplyObserverState) set(available bool, reason string, nativeError uint32) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if available && !s.s.Available {
		s.s.StartedAt = time.Now()
	}
	s.s.Available, s.s.Reason, s.s.NativeError = available, reason, nativeError
}

func (s *udpReplyObserverState) snapshot() UDPReplyObserverStatus {
	s.mu.Lock()
	defer s.mu.Unlock()
	v := s.s
	if v.Reason == "" {
		v.Reason = "NOT_STARTED"
	}
	return v
}

// NoteDirectUDP never creates a ledger entry or changes a packet/policy.
func (l *EvidenceLedger) NoteDirectUDP(id ProcessIdentity, t Tuple, identityBound bool) uint64 {
	l.mu.Lock()
	defer l.mu.Unlock()
	k := l.keyLocked(id, t)
	v, ok := l.flows[k]
	if !ok || t.Protocol != "udp" || v.Policy.Action != flowpolicy.Direct {
		return 0
	}
	if v.DirectUDPReply.State == "" {
		covered := t.Source.Addr().Is4() && t.Destination.Addr().Is4() && !t.Source.Addr().IsLoopback() && !t.Destination.Addr().IsLoopback() && t.Destination.Port() >= 1024
		v.DirectUDPReply = DirectUDPReplyEvidence{State: "UNAVAILABLE", Reason: "OBSERVER_STATUS_REQUIRED", IdentityBound: identityBound, FilterCovered: covered, FromFirstPacket: identityBound && v.Counters.Captured <= 1}
		l.storeLocked(k, v)
	} else if identityBound && !v.DirectUDPReply.IdentityBound {
		v.DirectUDPReply.IdentityBound = true
		v.DirectUDPReply.FromFirstPacket = false
		l.storeLocked(k, v)
	}
	return v.FlowID
}

func (l *EvidenceLedger) invalidateDirectUDP(id ProcessIdentity, t Tuple, generation uint64, reason string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	k := l.keyLocked(id, t)
	if v, ok := l.flows[k]; ok && v.FlowID == generation && v.DirectUDPReply.State != "" {
		v.DirectUDPReply.IdentityBound = false
		v.DirectUDPReply.State, v.DirectUDPReply.Reason = "UNAVAILABLE", reason
		l.storeLocked(k, v)
	}
}

// RecordDirectUDPReply rejects stale flow generations, PID births and unbound
// tuples. It only touches existing evidence and never retains packet content.
func (l *EvidenceLedger) RecordDirectUDPReply(id ProcessIdentity, t Tuple, flowID uint64, bytes uint64, at time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	k := l.keyLocked(id, t)
	v, ok := l.flows[k]
	if !ok || v.FlowID != flowID || v.DirectUDPReply.State == "" || !v.DirectUDPReply.IdentityBound || !v.DirectUDPReply.FilterCovered ||
		v.Policy.Action != flowpolicy.Direct || (v.Route != "" && v.Route != "DIRECT") || t.Protocol != "udp" || id.PID == 0 || id.CreationTime == 0 ||
		at.Before(v.StartedAt) || bytes == 0 {
		return false
	}
	if v.DirectUDPReply.FirstReply.IsZero() {
		v.DirectUDPReply.FirstReply = at
	}
	if at.After(v.DirectUDPReply.LastReply) {
		v.DirectUDPReply.LastReply = at
	}
	if at.After(v.LastSeen) {
		v.LastSeen = at
	}
	increment(&l.totals, "direct_reply")
	incrementBytes(&l.totals, "direct_reply", bytes)
	increment(&v.Counters, "direct_reply")
	incrementBytes(&v.Counters, "direct_reply", bytes)
	l.storeLocked(k, v)
	return true
}

func decorateDirectUDPReplies(flows []FlowEvidence, observer UDPReplyObserverStatus) {
	for i := range flows {
		f := &flows[i]
		if f.Protocol != "udp" || f.Route != "DIRECT" || f.GameUDP != nil {
			continue
		}
		if f.DirectUDPReply.State == "" {
			f.DirectUDPReply = DirectUDPReplyEvidence{State: "UNAVAILABLE", Reason: "NOT_TRACKED_PASSIVE_DIRECT"}
			continue
		}
		x := &f.DirectUDPReply
		if !x.FilterCovered {
			x.State, x.Reason = "UNAVAILABLE", "OUTSIDE_EXISTING_SNIFF_FILTER"
			continue
		}
		x.State, x.Reason = "UNAVAILABLE", "NATIVE_ENDPOINT_NOT_BOUND"
		if !x.IdentityBound {
			continue
		}
		if !observer.Available {
			x.Reason = observer.Reason
			continue
		}
		if !x.FromFirstPacket {
			x.State, x.Reason = "PARTIAL", "IDENTITY_BOUND_AFTER_FIRST_PACKET"
			continue
		}
		if f.StartedAt.Before(observer.StartedAt) {
			x.State, x.Reason = "PARTIAL", "OBSERVER_STARTED_AFTER_FLOW"
			continue
		}
		x.State, x.Reason = "OBSERVING", "PASSIVE_DIRECT_NO_REPLY_OBSERVED"
		if !x.FirstReply.IsZero() {
			x.Reason = "PASSIVE_DIRECT_REPLY_OBSERVED"
		}
	}
}
