package windowsplatform

import (
	"strings"
	"time"
)

// Full close of a planned CONNECT frontend owns both halves of this native
// mapping. A TCP FIN alone is insufficient: a silent origin can retain the
// Engine reservation forever while the local proxy waits for its response.
// Only the exact delegation generation may release it. CloseWrite is unchanged.
func (s *tcpState) closePlannedDelegation(bound Tuple, owner *tcpEntry) {
	s.mu.Lock()
	e := s.entries[bound]
	if e == nil || e.delegationOwner != owner || e.decision.OpenDeferred == nil || e.mode == "closed" || e.mode == "hot_attach" {
		s.mu.Unlock()
		return
	}
	up, local, cancel := e.upstream, e.local, e.openCancel
	e.upstream, e.local = nil, nil
	e.mode, e.last, e.normalTeardown = "closed", time.Now(), true
	s.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	// Release the Engine key synchronously, before the caller may retry the
	// same origin through relay. No wait for a remote FIN or pipe goroutine.
	if up != nil {
		_ = up.Close()
	}
	if local != nil {
		_ = local.Close()
	}
}

// A service-created reserved LOCAL socket must not accidentally become self /
// DIRECT if the OS owner table lags its first SYN. Retry proof on retransmission.
// Does not authorize any arbitrary service socket or change established flows.
func delegatedOwnerPending(d Decision, ownerPID, servicePID uint32, ownerError error) bool {
	return (d.OpenDeferred != nil || d.Route.Local()) && (ownerError != nil || ownerPID != servicePID)
}

func browserTimestampPlan(d Decision) bool {
	if !d.Route.Local() || d.Local == nil {
		return false
	}
	for _, p := range d.Local.Config().User {
		if p.ID != d.LocalStrategyID || p.Preset != "browser-catalog" {
			continue
		}
		for _, a := range p.Actions {
			if a.Native != nil && strings.Contains(a.Native.Fooling, "ts") && !strings.Contains(a.Native.Fooling, "md5sig") {
				return true
			}
		}
	}
	return false
}
