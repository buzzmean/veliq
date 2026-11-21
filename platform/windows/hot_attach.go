package windowsplatform

import (
	"sync"
	"time"
)

const hotAttachLimit = 8192
const hotAttachWindow = 8 * time.Second

// HOT_ATTACH_NETWORK_READY proves fencing/reconciliation, never application recovery.
type HotAttachStatus struct {
	Epoch          uint64    `json:"epoch"`
	State          string    `json:"state"`
	Reason         string    `json:"reason,omitempty"`
	StartedAt      time.Time `json:"started_at,omitempty"`
	CompletedAt    time.Time `json:"completed_at,omitempty"`
	Scanned        int       `json:"scanned"`
	TCPReset       int       `json:"tcp_reset"`
	Pending        int       `json:"pending"`
	UDPRetired     int       `json:"udp_retired"`
	BlockedPackets uint64    `json:"blocked_packets"`
	Error          string    `json:"error,omitempty"`
}
type HotAttachFlow struct {
	Epoch    uint64 `json:"epoch"`
	State    string `json:"state"`
	Revision string `json:"policy_revision,omitempty"`
}
type hotAttachTarget struct {
	row      ownedTCPRow
	identity ProcessIdentity
}
type hotAttachState struct {
	targets     []hotAttachTarget
	targetError string
	mu          sync.Mutex
	status      HotAttachStatus
}

func (h *hotAttachState) snapshot() HotAttachStatus {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.status
}
func (h *hotAttachState) begin(reason string) uint64 {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.status = HotAttachStatus{Epoch: h.status.Epoch + 1, State: "HOT_ATTACH_RECONNECTING", Reason: reason, StartedAt: time.Now()}
	return h.status.Epoch
}
func needsHotAttach(d Decision) bool {
	return !d.NewConnectionsOnly && requiresInterception(d)
}
func requiresInterception(d Decision) bool {
	return d.Block || d.Route.Local() || !d.Route.Direct() || d.Deferred || d.ProbeDirect
}
func (l *EvidenceLedger) RecordHotAttach(id ProcessIdentity, t Tuple, epoch uint64, state, revision string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	k := l.keyLocked(id, t)
	v, ok := l.lookupLocked(k)
	if !ok {
		return
	}
	v.HotAttach = &HotAttachFlow{epoch, state, revision}
	l.storeLocked(k, v)
}

// Native table/reset evidence is metadata, not a captured packet. Retire a
// previous policy's counters before assigning the new transition policy.
func (l *EvidenceLedger) RecordHotReset(id ProcessIdentity, t Tuple, epoch uint64, d Decision) {
	l.mu.Lock()
	defer l.mu.Unlock()
	k := l.keyLocked(id, t)
	v, ok := l.lookupLocked(k)
	if !ok || v.HotAttach == nil || v.HotAttach.Epoch != epoch || (v.HotAttach.State != "HOT_ATTACH_PREEXISTING" && v.HotAttach.State != "HOT_ATTACH_RESET_REQUESTED") {
		l.retireLocked(k)
		l.createFlowLocked(k)
	}
	l.recordBytesLocked(id, t, "hot_attach", "", 0)
	v, ok = l.lookupLocked(k)
	if !ok {
		return
	}
	v.Policy = d.Policy
	v.HotAttach = &HotAttachFlow{epoch, "HOT_ATTACH_RESET_REQUESTED", d.Revision}
	v.Route = "HOT_ATTACH"
	l.storeLocked(k, v)
}

func freshHotTCP(e *tcpEntry, id ProcessIdentity, d Decision) bool {
	return e != nil && e.identity.PID == id.PID && e.identity.CreationTime == id.CreationTime && e.decision.Revision == d.Revision && e.mode != "hot_attach" && e.mode != "closed"
}
