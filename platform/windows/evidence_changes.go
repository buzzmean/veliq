package windowsplatform

import (
	"encoding/json"
	"errors"
	"github.com/buzzmean/veliq/core/localstrategy"
	"sort"
	"time"
)

// ChangeCursor tracks updates, not just flow births. Advancing a birth marker
// would silently miss later DIRECT bytes on an already existing protected flow.
type ChangeCursor struct {
	LedgerID    string `json:"ledger_id"`
	AfterUpdate uint64 `json:"after_update"`
}
type ChangeQuery struct {
	Cursor ChangeCursor `json:"cursor"`
}
type ChangePage struct {
	UDPReplyObserver *UDPReplyObserverStatus `json:"udp_reply_observer,omitempty"`
	Cursor           ChangeCursor            `json:"cursor"`
	More             bool                    `json:"more"`
	EvidenceLost     bool                    `json:"evidence_lost"`
	Flows            []FlowEvidence          `json:"flows"`
	Counters         CaptureCounters         `json:"counters"`
}

func cloneFlow(v FlowEvidence) FlowEvidence {
	if v.LocalTCP != nil {
		copy := *v.LocalTCP
		v.LocalTCP = &copy
	}
	if v.GameUDP != nil {
		copy := *v.GameUDP
		v.GameUDP = &copy
	}
	if v.TCPAdmission != nil {
		copy := *v.TCPAdmission
		v.TCPAdmission = &copy
	}
	if v.UDPHealth != nil {
		copy := *v.UDPHealth
		v.UDPHealth = &copy
	}
	if v.LocalInspection != nil {
		copy := *v.LocalInspection
		copy.SentPackets = append([]localstrategy.SentPacket(nil), copy.SentPackets...)
		v.LocalInspection = &copy
	}
	if v.RelayOpen != nil {
		copy := *v.RelayOpen
		v.RelayOpen = &copy
	}
	if v.UDPQueue != nil {
		copy := *v.UDPQueue
		v.UDPQueue = &copy
	}
	return v
}
func (l *EvidenceLedger) ChangeMarker() ChangeCursor {
	l.mu.Lock()
	defer l.mu.Unlock()
	return ChangeCursor{l.ledgerID, l.nextUpdate}
}

// ChangePage returns coalesced cumulative flow snapshots in update order. A
// concurrent later update moves to a later cursor, never behind the consumer.
// Consumers upsert by ledger_id/flow_id; they must not sum successive snapshots.
func (l *EvidenceLedger) ChangePage(q ChangeQuery) (ChangePage, error) {
	return l.changePageWithUDPObserver(q, nil)
}
func (l *EvidenceLedger) changePageWithUDPObserver(q ChangeQuery, observer *UDPReplyObserverStatus) (ChangePage, error) {
	l.mu.Lock()
	out := ChangePage{Cursor: q.Cursor, Flows: []FlowEvidence{}, Counters: l.totals}
	out.UDPReplyObserver = observer
	if q.Cursor.LedgerID != l.ledgerID || q.Cursor.AfterUpdate > l.nextUpdate {
		l.mu.Unlock()
		return out, errors.New("invalid change cursor; service restarted or cursor is stale")
	}
	out.EvidenceLost = q.Cursor.AfterUpdate < l.lostThroughUpdate
	all := make([]FlowEvidence, 0, len(l.flows)+len(l.retired))
	for _, v := range l.flows {
		if !v.pending && v.updateSeq > q.Cursor.AfterUpdate {
			all = append(all, v)
		}
	}
	for _, v := range l.retired {
		if !v.pending && v.updateSeq > q.Cursor.AfterUpdate {
			all = append(all, v)
		}
	}
	highWater := l.nextUpdate
	l.mu.Unlock() // serialization must never stall the capture writer
	sort.Slice(all, func(i, j int) bool { return all[i].updateSeq < all[j].updateSeq })
	count := len(all)
	if count > 32 {
		count = 32
	}
	for _, v := range all[:count] {
		out.Flows = append(out.Flows, cloneFlow(v))
	}
	if observer != nil {
		decorateDirectUDPReplies(out.Flows, *observer)
	}
	for len(out.Flows) > 0 {
		count = len(out.Flows)
		out.More = count < len(all)
		out.Cursor.AfterUpdate = all[count-1].updateSeq
		if !out.More {
			out.Cursor.AfterUpdate = highWater
		}
		raw, _ := json.Marshal(out)
		if len(raw) <= 58000 {
			return out, nil
		}
		out.Flows = out.Flows[:count-1]
	}
	if len(all) > 0 {
		return out, errors.New("single flow exceeds capture page bound")
	}
	out.Cursor.AfterUpdate = highWater

	return out, nil
}
func (l *EvidenceLedger) storeLocked(k evidenceKey, v FlowEvidence) {
	l.nextUpdate++
	v.updateSeq = l.nextUpdate
	v.recordKey = k
	l.flows[k] = v
}
func (l *EvidenceLedger) retireLocked(k evidenceKey) {
	v, ok := l.flows[k]
	if !ok {
		return
	}
	delete(l.flows, k)
	if v.pending {
		return
	}
	l.nextUpdate++
	v.updateSeq = l.nextUpdate
	v.recordKey = k
	if len(l.retired) >= 1024 {
		var victim uint64
		var seq uint64
		for id, old := range l.retired {
			if victim == 0 || old.updateSeq < seq {
				victim, seq = id, old.updateSeq
			}
		}
		old := l.retired[victim]
		delete(l.retired, victim)
		if l.retiredKeys[old.recordKey] == victim {
			delete(l.retiredKeys, old.recordKey)
		}
		if seq > l.lostThroughUpdate {
			l.lostThroughUpdate = seq
		}
	}
	l.retired[v.FlowID] = cloneFlow(v)
	l.retiredKeys[k] = v.FlowID
}

// Reclaim diagnostic storage only. Routing/transform state is untouched; a late
// packet restores cumulative evidence and DIRECT+ metadata from retained history.
func (l *EvidenceLedger) roomLocked() {
	if len(l.flows) < 1024 {
		return
	}
	var oldest evidenceKey
	var at time.Time
	found := false
	for k, v := range l.flows {
		if !found || v.LastSeen.Before(at) {
			oldest, at, found = k, v.LastSeen, true
		}
	}
	if found {
		l.retireLocked(oldest)
		l.lostRecords++
	} // old creation-marker contract remains conservative
}
func (l *EvidenceLedger) lookupLocked(k evidenceKey) (FlowEvidence, bool) {
	if v, ok := l.flows[k]; ok {
		return v, true
	}
	id := l.retiredKeys[k]
	v, ok := l.retired[id]
	if !ok {
		return FlowEvidence{}, false
	}
	delete(l.retired, id)
	delete(l.retiredKeys, k)
	l.roomLocked()
	l.storeLocked(k, v)
	return v, true
}
