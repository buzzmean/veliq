package browserproxy

import (
	"context"
	"github.com/buzzmean/veliq/core/flowpolicy"
	"net"
	"time"
)

// At most one additional DIRECT address and then relay. Each wrapper forgets
// the first flight as soon as ANY server bytes arrive. Established TLS is never
// replayed/migrated. The overall DIRECT deadline is shared across wrappers.
func (s *Server) watchDirect(ctx context.Context, conn net.Conn, q Request, plan Plan, id uint64, depth int) net.Conn {
	timeout := s.cfg.StallTimeout
	if timeout <= 0 {
		timeout = DefaultStallTimeout
	}
	if !plan.DirectDeadline.IsZero() {
		remaining := time.Until(plan.DirectDeadline)
		if depth == 0 && plan.DirectIndex < 2 && plan.DirectAttempts < 2 && len(plan.DirectCandidates) > 1 {
			remaining /= 2
		}
		if remaining < timeout {
			timeout = remaining
		}
		if timeout <= 0 {
			timeout = time.Nanosecond
		}
	}
	watch := newStallConn(ctx, conn, timeout, func(ctx context.Context) (net.Conn, error) {
		stallCtx, stop := context.WithTimeout(ctx, 5*time.Second)
		defer stop()
		next, nextPlan, err := s.cfg.OnStall(stallCtx, q, plan)
		if err != nil {
			return nil, err
		}
		s.mu.Lock()
		r := s.records[id]
		r.Plan = nextPlan
		r.StallRetried = nextPlan.Policy.Action == flowpolicy.RelayRequired
		s.records[id] = r
		s.mu.Unlock()
		if nextPlan.Policy.Action == flowpolicy.Direct && depth == 0 && nextPlan.Policy.Source != "googlevideo_relay_limit" {
			next = s.watchDirect(ctx, next, q, nextPlan, id, depth+1)
		}
		return next, nil
	}, func(stalled, retried bool, err error) {
		switch {
		case stalled:
			s.reject("DIRECT_STALL")
		case retried:
			s.mu.Lock()
			viaRelay := s.records[id].StallRetried
			s.mu.Unlock()
			if viaRelay {
				s.reject("DIRECT_STALL_RETRIED_VIA_RELAY")
			} else {
				s.reject("DIRECT_STALL_RETRIED_SECOND_ADDRESS")
			}
		case err != nil:
			s.reject("DIRECT_STALL_RETRY_FAILED")
		}
	}, func() {
		if s.cfg.OnDirectAnswered != nil {
			s.cfg.OnDirectAnswered(q, plan)
		}
	})
	watch.handshakeOnly = s.cfg.RequireClientHelloReplay
	return watch
}
