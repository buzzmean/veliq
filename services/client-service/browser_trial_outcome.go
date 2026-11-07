package clientservice

import (
	"errors"
	"syscall"
	"time"

	"github.com/buzzmean/neexitlag/core/localstrategy"
)

// Times are passive observations, never decoded HTTP/2 frames or application
// contents. TLS1.3 type23 may contain handshake/alerts as well as HTTP data.
type youtubeTimings struct {
	ClientHelloToServerHelloMS                       int64 `json:"hello_to_server_hello_ms"`
	ClientHelloToCloseMS                             int64 `json:"hello_to_close_ms"`
	LastRXToCloseMS                                  int64 `json:"last_rx_to_close_ms"`
	ApplicationRecords, ApplicationBytes             uint64
	ApplicationSpanMS                                int64
	ReceivedAfterServerHello                         uint64 `json:"rx_after_server_hello_observed"`
	ClientApplicationRecord, OriginApplicationRecord bool
	ApplicationEvidenceBounded                       bool
	HalfCloseRequested                               bool
	RXAfterFirstClose                                bool
}

func (m *youtubeMeter) currentInspection() *localstrategy.Inspection {
	if m.stage != "LOCAL" {
		return nil
	}
	if m.inspection != nil {
		return m.inspection()
	}
	return nil
}
func (m *youtubeMeter) timingLocked(inspection *localstrategy.Inspection, closed time.Time) youtubeTimings {
	t := youtubeTimings{ClientHelloToServerHelloMS: -1, ClientHelloToCloseMS: -1, LastRXToCloseMS: -1, HalfCloseRequested: m.halfClosed}
	if !m.firstClientWrite.IsZero() && !m.serverHelloAt.IsZero() {
		t.ClientHelloToServerHelloMS = m.serverHelloAt.Sub(m.firstClientWrite).Milliseconds()
	}
	wire := m.wire.Snapshot()
	t.ApplicationRecords = wire.Origin.ApplicationRecords
	t.ApplicationBytes = wire.Origin.ApplicationBytes
	if !m.firstApplicationRX.IsZero() {
		t.ApplicationSpanMS = m.lastReply.Sub(m.firstApplicationRX).Milliseconds()
	}
	if wire.Origin.ServerHelloEndBytes > 0 && m.rx >= wire.Origin.ServerHelloEndBytes {
		t.ReceivedAfterServerHello = m.rx - wire.Origin.ServerHelloEndBytes
	}
	last := m.lastReply
	if inspection != nil && !inspection.TCPPackets.FirstCloseAt.IsZero() {
		closed = inspection.TCPPackets.FirstCloseAt
		if !inspection.TCPPackets.LastRemoteBeforeCloseAt.IsZero() {
			last = inspection.TCPPackets.LastRemoteBeforeCloseAt
		}
	}
	if !closed.IsZero() {
		if !m.firstClientWrite.IsZero() {
			t.ClientHelloToCloseMS = closed.Sub(m.firstClientWrite).Milliseconds()
		}
		if !last.IsZero() {
			t.LastRXToCloseMS = closed.Sub(last).Milliseconds()
			if t.LastRXToCloseMS < 0 {
				t.RXAfterFirstClose = true
				t.LastRXToCloseMS = 0
			}
		}
	}
	t.ClientApplicationRecord = wire.Client.ApplicationRecords > 0
	t.OriginApplicationRecord = wire.Origin.ApplicationRecords > 0
	for _, r := range wire.Client.Records {
		t.ClientApplicationRecord = t.ClientApplicationRecord || r.Type == 23
	}
	for _, r := range wire.Origin.Records {
		t.OriginApplicationRecord = t.OriginApplicationRecord || r.Type == 23
	}
	t.ApplicationEvidenceBounded = wire.Client.Bounded || wire.Origin.Bounded
	return t
}
func isTCPReset(e error) bool {
	return errors.Is(e, syscall.ECONNRESET) || errors.Is(e, syscall.Errno(10054))
}
func (m *youtubeMeter) noteClientClose() bool {
	inspection := m.currentInspection()
	if inspection == nil {
		return false
	}
	t := inspection.TCPPackets
	clean := t.FirstClose == "CLIENT_PACKET" && t.FirstCloseFlags&1 != 0 && t.ClientRST == 0 && t.RemoteRST == 0
	m.mu.Lock()
	if !clean || m.rx == 0 || m.failed {
		m.mu.Unlock()
		return false
	}
	m.neutral = true
	m.smallEOF = false
	count := !m.healthy && !m.neutralCounted
	m.neutralCounted = true
	timing := m.timingLocked(inspection, time.Time{})
	m.mu.Unlock()
	m.r.mu.Lock()
	defer m.r.mu.Unlock()
	if count {
		s := m.r.stats[m.label]
		s.Inconclusive++
		m.r.stats[m.label] = s
	}
	if v, ok := m.r.records[m.id]; ok {
		v.Inspection = inspection
		v.Timing = timing
		v.Reason = "CLIENT_INITIATED_CLOSE"
		v.IOFailure = ""
		v.Updated = time.Now()
		m.r.records[m.id] = v
	}
	return true
}
func (m *youtubeMeter) finishObservation() {
	if !m.trial {
		return
	}
	m.trialDone.Do(func() {
		m.mu.Lock()
		verdict := "INCONCLUSIVE"
		if m.failed {
			verdict = "FAILED"
		} else if m.healthy && m.dataObserved {
			verdict = "SUCCESS"
		} else if m.smallEOF {
			verdict = "REMOTE_SMALL_EOF"
		} else if m.neutral {
			verdict = "CLIENT_INITIATED_CLOSE"
		}
		if !m.recoveryScopeCurrent() {
			verdict = "INCONCLUSIVE"
		}
		rx := m.rx
		// Finalize under the meter lock: a late hard error must be counted
		// either in this outcome or explicitly after it, never lost/doubled.
		m.slot = m.r.finishTrialOutcomeFor(m.trialID, m.key, m.strategy, verdict, rx > 0, time.Now(), rx)
		m.trialFinalized = true
		m.mu.Unlock()
	})
	m.recordTrialEvidence(false)
}
func (m *youtubeMeter) updateCloseRecord() {
	inspection := m.currentInspection()
	m.mu.Lock()
	timing := m.timingLocked(inspection, time.Now())
	failed, healthy, neutral, promoted := m.failed, m.healthy, m.neutral, m.promoted
	m.mu.Unlock()
	m.r.mu.Lock()
	defer m.r.mu.Unlock()
	if v, ok := m.r.records[m.id]; ok {
		v.Active = false
		if promoted && !failed {
			v.TrialResult = "SUCCESS_CLOSED"
		}
		v.Inspection = inspection
		v.Timing = timing
		v.Updated = time.Now()
		if !failed && !healthy && !neutral && v.Reason == "OPEN" {
			v.Reason = "LOCAL_CLOSE_INCONCLUSIVE"
		}
		m.r.records[m.id] = v
	}
}
