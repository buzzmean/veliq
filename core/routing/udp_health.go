package routing

import "time"

const (
	DirectProbation           = "DIRECT_PROBATION"
	DirectConfirmed           = "DIRECT_CONFIRMED"
	DirectInsufficientReplies = "DIRECT_INSUFFICIENT_REPLIES"
	DirectLivenessLost        = "DIRECT_LIVENESS_LOST"
	FlowRelayFallback         = "FLOW_RELAY_FALLBACK"
	udpHealthTick             = 250 * time.Millisecond
	udpConfirmWindow          = 1500 * time.Millisecond
	udpLiveWindow             = 2 * time.Second
	udpDegradationGrace       = 2 * time.Second
)

// UDPHealthEvidence is transport evidence, never an application/voice latency
// assertion. Probation counters freeze on confirmation/fallback; cadence counters
// describe occupied time bins, not datagrams in a burst. No payload is retained.
type UDPHealthEvidence struct {
	State               string `json:"state"`
	Reason              string `json:"reason,omitempty"`
	ProbationReplies    uint64 `json:"probation_replies"`
	ProbationReplyBytes uint64 `json:"probation_reply_bytes"`
	ProbationDurationMS int64  `json:"probation_duration_ms"`
	OutboundBins        int    `json:"outbound_bins"`
	ReplyBins           int    `json:"reply_bins"`
	DegradedDurationMS  int64  `json:"degraded_duration_ms"`
	FakePrelude         int    `json:"fake_prelude_datagrams,omitempty"`
}

type udpCadenceBin struct {
	epoch                            int64
	valid, tx, rx                    bool
	txFirst, txLast, rxFirst, rxLast time.Duration
}
type udpCadence struct {
	state, reason                        string
	started, finished, degraded, stopped time.Time
	replies, bytes                       uint64
	// lenientReplies>0 confirms at probation end with that many replies: Discord
	// voice after a fake prelude, where a quiet channel answers few datagrams.
	// Post-confirmation liveness (DIRECT_LIVENESS_LOST -> relay) is unchanged.
	lenientReplies uint64
	bins           [16]udpCadenceBin // four seconds, fixed memory for the entire flow lifetime
}
type udpCadenceStats struct {
	tx, rx                           int
	txFirst, txLast, rxFirst, rxLast time.Duration
}

func (h *udpCadence) stateName() string {
	if h.state == "" {
		return DirectProbation
	}
	return h.state
}
func (h *udpCadence) observe(now time.Time, inbound bool, size int) {
	if h.stateName() == FlowRelayFallback {
		return
	}
	if h.started.IsZero() {
		if inbound {
			return
		} // unsolicited receive cannot start/confirm a probe
		h.started = now
	}
	elapsed := now.Sub(h.started)
	epoch := int64(elapsed / udpHealthTick)
	b := &h.bins[epoch%int64(len(h.bins))]
	if !b.valid || b.epoch != epoch {
		*b = udpCadenceBin{epoch: epoch, valid: true}
	}
	if inbound {
		if !b.rx {
			b.rxFirst = elapsed
		}
		b.rx, b.rxLast = true, elapsed
		if h.stateName() == DirectProbation {
			h.replies++
			h.bytes += uint64(size)
		}
	} else {
		if !b.tx {
			b.txFirst = elapsed
		}
		b.tx, b.txLast = true, elapsed
	}
}
func (h *udpCadence) stats(now time.Time, window time.Duration) (s udpCadenceStats) {
	if h.started.IsZero() {
		return
	}
	elapsed := now.Sub(h.started)
	for _, b := range h.bins {
		if !b.valid || time.Duration(b.epoch+1)*udpHealthTick <= elapsed-window || time.Duration(b.epoch)*udpHealthTick > elapsed {
			continue
		}
		if b.tx {
			if s.tx == 0 || b.txFirst < s.txFirst {
				s.txFirst = b.txFirst
			}
			if s.tx == 0 || b.txLast > s.txLast {
				s.txLast = b.txLast
			}
			s.tx++
		}
		if b.rx {
			if s.rx == 0 || b.rxFirst < s.rxFirst {
				s.rxFirst = b.rxFirst
			}
			if s.rx == 0 || b.rxLast > s.rxLast {
				s.rxLast = b.rxLast
			}
			s.rx++
		}
	}
	return
}
func (h *udpCadence) busy(now time.Time, s udpCadenceStats) bool {
	return s.tx >= 4 && s.txLast-s.txFirst >= 750*time.Millisecond && now.Sub(h.started)-s.txLast <= 500*time.Millisecond
}

// check runs under AdaptiveUDP.mu. A single read timeout is never a signal.
// Only sustained cadence can clear degradation; isolated replies cannot reset it.
func (h *udpCadence) check(now time.Time, probation time.Duration) (confirmed bool, failure string) {
	if h.started.IsZero() || h.stateName() == FlowRelayFallback {
		return
	}
	if h.stateName() == DirectProbation {
		s := h.stats(now, udpConfirmWindow)
		if h.busy(now, s) && s.rx >= 4 && s.rxLast-s.rxFirst >= 750*time.Millisecond && s.txLast >= s.rxFirst {
			h.state, h.finished = DirectConfirmed, now
			return true, ""
		}
		if now.Sub(h.started) >= probation {
			if h.lenientReplies > 0 && h.replies >= h.lenientReplies {
				h.state, h.finished = DirectConfirmed, now
				return true, ""
			}
			return false, DirectInsufficientReplies
		}
		return
	}
	s := h.stats(now, udpLiveWindow)
	if !h.busy(now, s) {
		h.degraded = time.Time{}
		return
	}
	if s.rx >= 4 && s.rxLast-s.rxFirst >= 750*time.Millisecond {
		h.degraded = time.Time{}
		return
	}
	if h.degraded.IsZero() {
		h.degraded = now
	}
	if now.Sub(h.degraded) >= udpDegradationGrace {
		return false, DirectLivenessLost
	}
	return
}
func (h *udpCadence) fallback(now time.Time, reason string) {
	if h.finished.IsZero() {
		h.finished = now
	}
	h.state, h.reason, h.stopped = FlowRelayFallback, reason, now
}
func (h *udpCadence) snapshot(now time.Time) UDPHealthEvidence {
	if !h.stopped.IsZero() {
		now = h.stopped
	}
	s := h.stats(now, udpLiveWindow)
	e := UDPHealthEvidence{State: h.stateName(), Reason: h.reason, ProbationReplies: h.replies, ProbationReplyBytes: h.bytes, OutboundBins: s.tx, ReplyBins: s.rx}
	if !h.started.IsZero() {
		end := h.finished
		if end.IsZero() {
			end = now
		}
		e.ProbationDurationMS = end.Sub(h.started).Milliseconds()
	}
	if !h.degraded.IsZero() {
		e.DegradedDurationMS = now.Sub(h.degraded).Milliseconds()
	}
	return e
}
