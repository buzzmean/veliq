//go:build windows

package windowsplatform

import (
	"errors"
	"syscall"
	"time"
)

func udpReplyNativeError(err error) uint32 {
	var code syscall.Errno
	if errors.As(err, &code) {
		return uint32(code)
	}
	return 0
}

// nativeDirectUDPBinding uses the existing FLOW association, never process
// memory, a new driver handle or an anti-cheat override. Caller holds b.mu.
func (b *WinDivertBackend) nativeDirectUDPBinding(t Tuple, f *captureFlow) bool {
	if f == nil || f.retired || f.directUDPEndpoint == 0 || f.identity.PID == 0 || f.identity.CreationTime == 0 {
		return false
	}
	a, ok := b.directUDPAssociations.Get(t, f.identity)
	return ok && a.Endpoint == f.directUDPEndpoint
}

// This bounded map consumes the existing FLOW feed only for diagnostics. In
// particular, guarded CS2 DIRECT does not need GameUDP first-flight enrollment.
func (b *WinDivertBackend) trackDirectUDPReplyIdentity(a Association, remove bool) {
	if a.Endpoint == 0 {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if remove {
		b.directUDPAssociations.Delete(a.Tuple, a.Endpoint)
	} else if !b.directUDPAssociations.Put(a) {
		return
	}
	if f := b.flows[a.Tuple]; f != nil && f.directUDPEndpoint != 0 &&
		(remove && f.directUDPEndpoint == a.Endpoint || !remove && (f.directUDPEndpoint != a.Endpoint || f.identity.PID != a.Identity.PID || f.identity.CreationTime != a.Identity.CreationTime)) {
		b.evidence.invalidateDirectUDP(f.identity, a.Tuple, f.directUDPFlowID, "NATIVE_ENDPOINT_ENDED_OR_REUSED")
	}
}

func (b *WinDivertBackend) noteDirectUDP(t Tuple, expected *captureFlow) {
	b.mu.Lock()
	defer b.mu.Unlock()
	f := b.flows[t]
	if f != expected || f == nil || f.retired || f.decision.udpWorker() || f.game != nil || f.decision.GameUDP != nil || f.decision.Block {
		return
	}
	if f.directUDPEndpoint == 0 {
		if a, ok := b.directUDPAssociations.Get(t, f.identity); ok {
			f.directUDPEndpoint = a.Endpoint
		}
	}
	f.directUDPFlowID = b.evidence.NoteDirectUDP(f.identity, t, b.nativeDirectUDPBinding(t, f))
}

// recordPassiveDirectReply is called only by the already existing inbound
// sniff handle. It never sends, reinjects, drops or changes the decision.
func (b *WinDivertBackend) recordPassiveDirectReply(t Tuple, ipBytes int, at time.Time) bool {
	if ipBytes <= 0 || ipBytes > 65535 {
		return false
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	f := b.flows[t]
	if f == nil || f.retired || !f.decision.Route.Direct() || f.decision.udpWorker() || f.game != nil ||
		f.decision.GameUDP != nil || f.decision.Block || !b.nativeDirectUDPBinding(t, f) {
		return false
	}
	if f.directUDPFlowID == 0 {
		return false
	}
	return b.evidence.RecordDirectUDPReply(f.identity, t, f.directUDPFlowID, uint64(ipBytes), at)
}
