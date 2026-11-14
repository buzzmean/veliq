package clientservice

import (
	"github.com/buzzmean/neexitlag/core/localstrategy"
	"time"
)

const cdnTrialEvidenceCapacity = 32

// Passive metadata only. Expected response size, HTTP redirects and media segment
// boundaries are encrypted: do not infer them from rrN or TLS record type23.
type cdnTrialEvidence struct {
	cdnTrialSlot
	SlotActive                                                                              bool `json:"slot_active"`
	ID                                                                                      uint64
	Profile, Network, Host, Subgroup, Strategy, TrialResult, Reason, IOFailure, Destination string
	TX, RX                                                                                  uint64
	DataTrial, Active                                                                       bool
	Updated                                                                                 time.Time
	Timing                                                                                  youtubeTimings
	Packets                                                                                 localstrategy.TCPTrace
	Sibling                                                                                 relaySiblingEvidence
}

func (m *youtubeMeter) recordTrialEvidence(active bool) {
	if !m.trial {
		return
	}
	inspection := m.currentInspection()
	m.mu.Lock()
	active = active && !m.closing
	result := "PROBE_WAITING_DATA"
	switch {
	case m.failed && m.promoted:
		result = "SUCCESS_REVOKED_AFTER_FAILURE"
	case m.failed:
		result = "FAILED"
	case m.promoted && active:
		result = "SUCCESS_RUNNING"
	case m.promoted:
		result = "SUCCESS_CLOSED"
	case m.smallEOF:
		result = "INCONCLUSIVE_SMALL_EOF"
	case m.neutral:
		result = "INCONCLUSIVE_CLIENT_CLOSE"
	case active && m.slot.SlotReleaseReason == cdnShortReplyIdle:
		result = "INCONCLUSIVE_SHORT_REPLY_IDLE"
	case !active && m.healthy && m.dataObserved:
		result = "SUCCESS_WEAK_CLOSED"
	case !active:
		result = "INCONCLUSIVE"
	case m.dataObserved:
		result = "DATA_OBSERVED_WAITING_SUSTAINED"
	}
	if !m.recoveryScopeCurrent() && !m.promoted && !m.failed {
		result = "INCONCLUSIVE_SCOPE_CHANGED"
	}
	closed := time.Time{}
	if !active {
		closed = time.Now()
	}
	failureReason := m.failureReason
	row := cdnTrialEvidence{cdnTrialSlot: m.slot, SlotActive: m.slot.SlotReleasedAt.IsZero(), ID: m.id, Profile: m.key.Profile, Network: m.key.Network, Host: m.host, Destination: m.destination, Subgroup: m.key.Domain, Strategy: m.strategy, TrialResult: result, TX: m.tx, RX: m.rx, DataTrial: m.dataObserved, Active: active, Updated: time.Now(), Timing: m.timingLocked(inspection, closed), Sibling: m.sibling}
	if inspection != nil {
		row.Packets = inspection.TCPPackets
	}
	m.mu.Unlock()
	m.r.mu.Lock()
	defer m.r.mu.Unlock()
	row.Reason = result
	if failureReason != "" {
		row.Reason = failureReason
	}
	if mSmall := result == "INCONCLUSIVE_SMALL_EOF"; mSmall {
		row.IOFailure = "REMOTE_EOF"
	}
	if v, ok := m.r.records[m.id]; ok {
		if !v.SlotReleasedAt.IsZero() {
			row.cdnTrialSlot = v.cdnTrialSlot
			row.SlotActive = false
		}
		row.Reason = v.Reason
		row.IOFailure = v.IOFailure
		v.TrialResult = result
		m.r.records[m.id] = v
	}
	for i := range m.r.trials {
		if m.r.trials[i].ID == row.ID {
			m.r.trials[i] = row
			return
		}
	}
	m.r.trials = append(m.r.trials, row)
	if len(m.r.trials) > cdnTrialEvidenceCapacity {
		m.r.trials = append([]cdnTrialEvidence(nil), m.r.trials[len(m.r.trials)-cdnTrialEvidenceCapacity:]...)
	}
}
