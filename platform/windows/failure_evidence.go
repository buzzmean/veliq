package windowsplatform

import (
	"github.com/buzzmean/veliq/core/flowpolicy"
	"time"
)

// A dropped packet is not itself a failed routing decision. Callers must name
// the cause and distinguish fail-close from teardown/queue disposal explicitly.
func (l *EvidenceLedger) RecordDrop(id ProcessIdentity, t Tuple, cause string, fatal bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.recordBytesLocked(id, t, "drop", "", 0)
	l.failureLocked(id, t, cause, fatal, true)
}
func (l *EvidenceLedger) RecordFailure(id ProcessIdentity, t Tuple, cause string, fatal bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.failureLocked(id, t, cause, fatal, false)
}
func (l *EvidenceLedger) failureLocked(id ProcessIdentity, t Tuple, cause string, fatal, drop bool) {
	k := l.keyLocked(id, t)
	v, ok := l.lookupLocked(k)
	if !ok {
		return
	}
	if drop {
		v.DropCause = cause
	}
	if fatal {
		if v.FailureCause == "" {
			v.FailureCause = cause
		}
		if v.Policy.Action == flowpolicy.Block || v.Policy.Action == flowpolicy.RelayRequired || v.Policy.Fallback == flowpolicy.Required || v.Policy.Fallback == flowpolicy.FlowRelay || v.Policy.Fallback == flowpolicy.FailBlock {
			if v.Route != "BLOCK_UNSUPPORTED_IPV6" {
				v.Route = "BLOCK"
			}
			v.RequiredBlocked = v.Policy.Fallback == flowpolicy.Required || v.Policy.Action == flowpolicy.RelayRequired
		}
	}
	l.storeLocked(k, v)
}
func (l *EvidenceLedger) RecordLifecycle(id ProcessIdentity, t Tuple, state string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	k := l.keyLocked(id, t)
	if v, ok := l.lookupLocked(k); ok {
		v.Lifecycle = state
		l.storeLocked(k, v)
	}
}

func (l *EvidenceLedger) RecordTCPAdmission(id ProcessIdentity, t Tuple, state string, wait time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	k := l.keyLocked(id, t)
	if f, ok := l.lookupLocked(k); ok {
		f.TCPAdmission = &TCPAdmissionEvidence{State: state, WaitMS: float64(wait) / float64(time.Millisecond)}
		l.storeLocked(k, f)
	}
}
