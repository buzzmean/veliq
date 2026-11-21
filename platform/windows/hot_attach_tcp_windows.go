//go:build windows

package windowsplatform

import (
	"os"
	"time"
)

func (t *tcpRedirect) resetFromPacket(p []byte, a [80]byte) {
	reset, err := hotTCPReset(p, true)
	if err != nil {
		return
	}
	a[10] &= ^byte(2)
	if err = t.send(reset, a); err != nil && t.b.ctx.Err() == nil {
		t.b.fail(err)
	}
}
func (t *tcpRedirect) quarantineNative(id ProcessIdentity, tuple Tuple, d Decision, p []byte, a [80]byte) {
	t.state.mu.Lock()
	defer t.state.mu.Unlock()
	epoch := t.b.hot.snapshot().Epoch
	t.b.evidence.BeginFlow(id, tuple)
	t.b.evidence.RecordBytes(id, tuple, "captured", "", uint64(len(p)))
	t.b.evidence.RecordPolicy(id, tuple, d, "")
	t.b.evidence.RecordHotAttach(id, tuple, epoch, "HOT_ATTACH_PREEXISTING", d.Revision)
	e := t.state.add(tuple, id, d, "hot_attach", time.Now())
	if e != nil {
		e.hotEpoch = t.b.policyEpoch.Load()
	}
	t.b.hotBlocked()
	t.b.Drops.Add(1)
	t.b.evidence.RecordDrop(id, tuple, "HOT_ATTACH_PENDING", false)
	t.resetFromPacket(p, a)
}
func (t *tcpRedirect) blockNativeInbound(tuple Tuple, classify Classifier) bool {
	t.state.mu.Lock()
	e := t.state.entries[tuple]
	if e != nil {
		if e.mode == "hot_attach" {
			t.state.mu.Unlock()
			return true
		}
		// DIRECT+ native sockets must continue receiving ordinary replies. A stale
		// DIRECT mapping under a new required policy cannot retain that permission.
		epoch := t.b.policyEpoch.Load()
		if e.hotEpoch == epoch {
			block := e.mode != "direct" && needsHotAttach(e.decision)
			t.state.mu.Unlock()
			return block
		}
	}
	t.state.mu.Unlock()
	pid, err := resolveTCPOwner(tuple)
	if err != nil || pid == uint32(os.Getpid()) {
		return false
	}
	id, err := t.b.cache.Lookup(pid)
	if err != nil || !IsCurrent(id) {
		return false
	}
	d := classify(id, tuple)
	if !needsHotAttach(d) && !t.b.hotFrozen(d) {
		return false
	}
	t.state.mu.Lock()
	defer t.state.mu.Unlock()
	e = t.state.entries[tuple]
	return e == nil || e.mode != "direct" || e.decision.Revision != d.Revision
}
