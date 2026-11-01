package windowsplatform

import (
	"sync"
	"time"

	"github.com/buzzmean/neexitlag/core/browserproxy"
	"github.com/buzzmean/neexitlag/core/localstrategy"
)

// Passive observations are deliberately not stored in Decision.OriginDomain,
// DNS caches or HTTP3 admission. They describe this blocked flight only.
type quicOriginCaptureState struct {
	started, emitted, pendingEmitted bool
	owner                            ProcessIdentity
	tuple                            Tuple
	revision, network, profile       string
	result                           localstrategy.QUICOriginObservation
}
type quicOriginPending struct {
	observer localstrategy.QUICOriginObserver
	timer    *time.Timer
}
type quicOriginPool struct {
	window  time.Time
	starts  int
	mu      sync.Mutex
	pending map[*quicOriginCaptureState]*quicOriginPending
}

const quicOriginPendingLimit = 32

func (p *quicOriginPool) clear() {
	p.mu.Lock()
	defer p.mu.Unlock()
	for state, entry := range p.pending {
		entry.timer.Stop()
		state.result = entry.observer.Finish("QUIC_ORIGIN_SCOPE_CHANGED")
		delete(p.pending, state)
	}
}
func quicOriginEligible(id ProcessIdentity, tuple Tuple, d Decision) bool {
	return browserProcess(id) && id.PID != 0 && id.CreationTime != 0 && len(id.Path) <= 2048 && tuple.Protocol == "udp" && tuple.Source.Addr().Is4() && tuple.Source.Port() != 0 && tuple.Destination.Addr().Is4() && browserproxy.PublicDNSAddress(tuple.Destination.Addr()) && tuple.Destination.Port() == 443 && d.Block && d.BlockOnFailure && d.Policy.Source == "browser_native_quic_tcp_fallback" && d.Revision != "" && len(d.Revision) <= 128 && d.Network != "" && len(d.Network) <= 256 && d.Flow.ApplicationID != "" && len(d.Flow.ApplicationID) <= 128
}
func (p *quicOriginPool) observe(s *quicOriginCaptureState, id ProcessIdentity, tuple Tuple, d Decision, payload []byte, first bool, now time.Time) (localstrategy.QUICOriginObservation, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	finish := func(why string) {
		if entry := p.pending[s]; entry != nil {
			if entry.timer != nil {
				entry.timer.Stop()
			}
			s.result = entry.observer.Finish(why)
			delete(p.pending, s)
		} else {
			s.result = localstrategy.QUICOriginObservation{Reason: why, Complete: true}
		}
	}
	emit := func() (localstrategy.QUICOriginObservation, bool) {
		if !s.result.Complete && !s.pendingEmitted {
			s.pendingEmitted = true
			return s.result, true
		}
		if !s.result.Complete || s.emitted {
			return localstrategy.QUICOriginObservation{}, false
		}
		s.emitted = true
		return s.result, true
	}
	if !s.started {
		s.started = true
		s.owner, s.tuple, s.revision, s.network, s.profile = id, tuple, d.Revision, d.Network, d.Flow.ApplicationID
		if !first || !quicOriginEligible(id, tuple, d) {
			finish("QUIC_ORIGIN_SCOPE_UNAVAILABLE")
			return emit()
		}
		if p.window.IsZero() || !now.Before(p.window.Add(time.Second)) {
			p.window = now
			p.starts = 0
		}
		if now.Before(p.window) || p.starts >= 64 {
			finish("QUIC_ORIGIN_RATE_LIMIT")
			return emit()
		}
		p.starts++
		if len(p.pending) >= quicOriginPendingLimit {
			finish("QUIC_ORIGIN_CAPACITY")
			return emit()
		}
		if p.pending == nil {
			p.pending = make(map[*quicOriginCaptureState]*quicOriginPending)
		}
		p.pending[s] = &quicOriginPending{}
	}
	if s.owner != id || s.tuple != tuple || s.revision != d.Revision || s.network != d.Network || s.profile != d.Flow.ApplicationID || !quicOriginEligible(id, tuple, d) {
		finish("QUIC_ORIGIN_SCOPE_CHANGED")
		return emit()
	}
	entry := p.pending[s]
	if entry == nil {
		return emit()
	}
	s.result = entry.observer.Observe(payload, now)
	if s.result.Complete {
		if entry.timer != nil {
			entry.timer.Stop()
		}
		delete(p.pending, s)
	} else if entry.timer == nil {
		entry.timer = time.AfterFunc(localstrategy.QUICOriginDeadline, func() {
			p.mu.Lock()
			defer p.mu.Unlock()
			if p.pending[s] == entry {
				s.result = entry.observer.Finish("QUIC_ORIGIN_TIMEOUT")
				delete(p.pending, s)
			}
		})
	}
	return emit()
}
