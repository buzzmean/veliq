package clientservice

import (
	"strings"
	"time"

	"github.com/buzzmean/neexitlag/core/localstrategy"
)

const cdnStrongBytes = 1024 * 1024
const cdnStrongRecords = 16
const cdnStrongSpan = 3 * time.Second

// Quiet must exceed the 6s midstream watch so an unanswered request is already
// a failure before a completed burst or an idle short reply can be classified.
const cdnBurstQuiet = 7 * time.Second

type localFailureEvidence struct {
	At                                                    time.Time
	Domain, Strategy, Reason                              string
	TX, RX                                                uint64
	SinceClientHelloMS, SinceServerHelloMS, SinceLastRXMS int64
	ReceivedAfterHello, ApplicationRecords                uint64
	Promoted, PostHelloWrite                              bool
}

func (m *youtubeMeter) failureEvidenceLocked(reason string, now time.Time) localFailureEvidence {
	v := localFailureEvidence{At: now, Domain: m.key.Domain, Strategy: m.strategy, Reason: reason, TX: m.tx, RX: m.rx, SinceClientHelloMS: -1, SinceServerHelloMS: -1, SinceLastRXMS: -1, Promoted: m.promoted, PostHelloWrite: m.postHelloWrite}
	if !m.firstClientWrite.IsZero() {
		v.SinceClientHelloMS = now.Sub(m.firstClientWrite).Milliseconds()
	}
	if !m.serverHelloAt.IsZero() {
		v.SinceServerHelloMS = now.Sub(m.serverHelloAt).Milliseconds()
	}
	if !m.lastReply.IsZero() {
		v.SinceLastRXMS = now.Sub(m.lastReply).Milliseconds()
	}
	wire := m.wire.Snapshot().Origin
	v.ApplicationRecords = wire.ApplicationRecords
	if wire.ServerHelloEndBytes > 0 && m.rx >= wire.ServerHelloEndBytes {
		v.ReceivedAfterHello = m.rx - wire.ServerHelloEndBytes
	}
	return v
}
func (m *youtubeMeter) strongEvidenceLocked(now time.Time) bool {
	wire := m.wire.Snapshot().Origin
	return m.trial && !m.failed && !m.closing && m.healthy && m.applied && m.postHelloWrite &&
		wire.ServerHelloComplete && wire.AlertLevel == 0 && wire.State != "NON_TLS_OR_INVALID_HEADER" && wire.ServerHelloEndBytes > 0 && m.rx >= wire.ServerHelloEndBytes+cdnStrongBytes &&
		wire.ApplicationRecords >= cdnStrongRecords && wire.ApplicationBytes >= cdnStrongBytes &&
		!m.firstApplicationRX.IsZero() && m.lastReply.Sub(m.firstApplicationRX) >= cdnStrongSpan && now.Sub(m.lastReply) <= 3*time.Second
}

// Completed burst: >=1MiB answered after the last client write (16 records overall), then
// cdnBurstQuiet without a write, alert, RST or failure on the same open TLS stream.
func (m *youtubeMeter) burstCompleteLocked(now time.Time, inspection *localstrategy.Inspection) bool {
	if inspection != nil && (inspection.TCPPackets.RemoteRST > 0 || inspection.TCPPackets.ClientRST > 0) {
		return false
	}
	wire := m.wire.Snapshot().Origin
	return m.trial && !m.failed && !m.closing && !m.halfClosed && m.healthy && m.applied && m.postHelloWrite &&
		wire.ServerHelloComplete && wire.AlertLevel == 0 && wire.State != "NON_TLS_OR_INVALID_HEADER" && wire.ServerHelloEndBytes > 0 && m.rx >= wire.ServerHelloEndBytes+cdnStrongBytes &&
		wire.ApplicationRecords >= cdnStrongRecords && wire.ApplicationBytes >= cdnStrongBytes &&
		!m.firstApplicationRX.IsZero() && !m.lastReply.IsZero() && !m.lastClientWrite.After(m.lastReply) && m.rx >= m.rxAtLastWrite+cdnStrongBytes && now.Sub(m.lastReply) >= cdnBurstQuiet
}
func (m *youtubeMeter) promotionEvidenceLocked(now time.Time, inspection *localstrategy.Inspection) (bool, string) {
	if m.strongEvidenceLocked(now) {
		return true, "SUSTAINED_CDN_RUNNING_PROMOTED"
	}
	if m.burstCompleteLocked(now, inspection) {
		return true, "SUSTAINED_CDN_BURST_COMPLETE_PROMOTED"
	}
	return false, ""
}
func (m *youtubeMeter) maybePromoteTrial(now time.Time) {
	if !m.recoveryScopeCurrent() {
		return
	}
	inspection := m.currentInspection()
	m.mu.Lock()
	eligible, _ := m.promotionEvidenceLocked(now, inspection)
	m.mu.Unlock()
	if !eligible {
		return
	}
	promotedNow := false
	// Same lock order as terminal finalization: once -> meter -> runtime.
	m.trialDone.Do(func() {
		m.mu.Lock()
		defer m.mu.Unlock()
		if m.trialFinalized {
			return
		}
		if ok, reason := m.promotionEvidenceLocked(now, inspection); ok && m.recoveryScopeCurrent() && m.r.promoteRunningFor(m.trialID, m.key, m.strategy, m.rx, now) {
			m.promoted = true
			promotedNow = true
			m.r.mu.Lock()
			m.slot = m.r.cache[m.key].cdnTrialSlot
			if reason != "SUSTAINED_CDN_RUNNING_PROMOTED" {
				m.r.selection.BurstPromotions++
				v := m.r.cache[m.key]
				v.Reason = reason
				m.r.cache[m.key] = v
			}
			if v, ok := m.r.records[m.id]; ok {
				v.TrialResult = "SUCCESS_RUNNING"
				v.Reason = reason
				m.r.records[m.id] = v
			}
			m.r.mu.Unlock()
			return
		}
		verdict := "INCONCLUSIVE"
		if m.failed {
			verdict = "FAILED"
		}
		m.finishTrialLocked(verdict, now)
	})
	if promotedNow {
		m.recordTrialEvidence(true)
	}
}
func (r *youtubeRuntime) promoteRunning(k youtubeKey, id string, received uint64, now time.Time) bool {
	return r.promoteRunningFor(0, k, id, received, now)
}
func (r *youtubeRuntime) promoteRunningFor(token uint64, k youtubeKey, id string, received uint64, now time.Time) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	v := r.cache[k]
	if !r.trialActive || token != 0 && token != r.trialID || r.trialKey != k || r.trialStrategy != id || v.Qualified == "" || !r.room(k, now) {
		return false
	}
	// This flow's current sustained proof supersedes its old public prerequisite;
	// it never grants another device/session authorization or another subgroup LOCAL.
	r.selection.TrialSuccesses++
	r.selection.StrongPromotions++
	r.score(k, id, true, now)
	v.Stage = "LOCAL"
	v.Strategy = id
	v.Confirmed = true
	if v.Qualified != id {
		v.Qualified = id
		v.Streak = 0
	}
	v.Streak++
	v.alternateTrialStreak = cdnTrialStreak{}
	v.VerifiedBytes = received
	v.Until = now.Add(youtubeLearnTTL)
	v.TrialAfter = now.Add(youtubeTrialCooldown)
	v.Retry = v.TrialAfter
	v.Reason = "SUSTAINED_CDN_RUNNING_PROMOTED"
	attempt := v.NeutralShortStreak + 1
	v.NeutralShortStreak = 0
	v.cdnTrialSlot = cdnTrialSlot{TrialID: r.trialID, SlotReleasedAt: now, SlotReleaseReason: "SUCCESS_RUNNING", CooldownUntil: v.TrialAfter, NeutralShortAttempt: attempt}
	r.releaseTrialSlotLocked(v.cdnTrialSlot)
	r.cache[k] = v
	r.notePeerProofLocked(k, id, now)
	return true
}
func (m *youtubeMeter) noteSmallEOF() bool {
	if m.stage != "LOCAL" {
		return false
	}
	inspection := m.currentInspection()
	// Sequence overlap may also be reordering. Retransmit counters alone
	// never prove a TLS or application failure. Known reset/alert/timeout wins.
	retransmitted := inspection != nil && (inspection.TCPPackets.ClientRetransmits > 0 || inspection.TCPPackets.RemoteRetransmits > 0)
	if inspection != nil {
		t := inspection.TCPPackets
		if t.RemoteRST > 0 || t.ClientRST > 0 {
			return false
		}
	}
	m.mu.Lock()
	wire := m.wire.Snapshot().Origin
	if m.failed || m.rx == 0 || m.rx >= cdnDataTrialBytes || wire.AlertLevel != 0 || strings.Contains(wire.State, "INVALID") || !wire.ServerHelloComplete {
		m.mu.Unlock()
		return false
	}
	m.neutral = true
	m.smallEOF = true
	count := !m.neutralCounted
	m.neutralCounted = true
	m.mu.Unlock()
	m.r.mu.Lock()
	defer m.r.mu.Unlock()
	if count {
		s := m.r.stats[m.label]
		s.Inconclusive++
		m.r.stats[m.label] = s
	}
	if v, ok := m.r.records[m.id]; ok {
		v.Reason = "REMOTE_SMALL_EOF_INCONCLUSIVE"
		if retransmitted {
			v.Reason = "REMOTE_SMALL_EOF_INCONCLUSIVE_TCP_RETRANSMITS_INFORMATIONAL"
		}
		v.IOFailure = "REMOTE_EOF"
		v.TrialResult = "INCONCLUSIVE_SMALL_EOF"
		m.r.records[m.id] = v
	}
	return true
}
