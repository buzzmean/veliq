package windowsplatform

import (
	"context"
	"github.com/buzzmean/neexitlag/core/localstrategy"
	"net"
	"sync"
	"time"
)

type tcpEntry struct {
	delegationOwner   *tcpEntry
	openCancel        context.CancelFunc
	openDone          chan struct{}
	openOnce          sync.Once
	hotEpoch          uint64
	normalTeardown    bool
	localState        localstrategy.State
	localBuffer       LocalTCPBuffer
	domainInspections uint8
	tuple             Tuple
	initialSequence   uint32
	identity          ProcessIdentity
	decision          Decision
	mode              string // opening, relay, direct, block, closed
	virtual           uint16
	last              time.Time
	upstream          net.Conn
	local             net.Conn
}

// All methods/entry access require mu. Closed mappings are quarantined so late
// retransmissions cannot attach to a new connection. Active entries never evict.
type tcpState struct {
	mu      sync.Mutex
	entries map[Tuple]*tcpEntry
	ports   map[uint16]*tcpEntry
	limit   int
	next    uint16
}

func newTCPState(limit int) *tcpState {
	return &tcpState{entries: map[Tuple]*tcpEntry{}, ports: map[uint16]*tcpEntry{}, limit: limit, next: 20000}
}
func (s *tcpState) add(t Tuple, id ProcessIdentity, d Decision, mode string, now time.Time) *tcpEntry {
	if len(s.entries) >= s.limit {
		return nil
	}
	e := &tcpEntry{tuple: t, identity: id, decision: d, mode: mode, last: now}
	if mode == "opening" {
		if len(s.ports) >= s.limit {
			return nil
		}
		for i := 0; i < 45536; i++ {
			p := s.next
			s.next++
			if s.next < 20000 {
				s.next = 20000
			}
			if s.ports[p] == nil {
				e.virtual = p
				s.ports[p] = e
				break
			}
		}
		if e.virtual == 0 {
			return nil
		}
	}
	s.entries[t] = e
	return e
}
func (s *tcpState) retire(e *tcpEntry, now time.Time) {
	if e.upstream != nil {
		e.upstream.Close()
		e.upstream = nil
	}
	if e.local != nil {
		e.local.Close()
		e.local = nil
	}
	e.mode = "closed"
	e.last = now
}

// A new SYN sequence means a new native TCP connection, even if Windows reuses
// the same tuple. Keep the old virtual port quarantined, not its routing policy.
func (s *tcpState) existing(t Tuple, flags byte, sequence uint32, now time.Time) *tcpEntry {
	e := s.entries[t]
	if e != nil && flags&0x12 == 2 && sequence != e.initialSequence {
		s.retire(e, now)
		delete(s.entries, t)
		return nil
	}
	return e
}
func (s *tcpState) expire(now time.Time) {
	for t, e := range s.entries {
		age := now.Sub(e.last)
		timeout := 2 * time.Minute
		if e.mode == "closed" {
			timeout = 4 * time.Minute
		}
		if e.mode == "relay" {
			timeout = 2 * time.Hour
			if e.local == nil {
				timeout = 15 * time.Second
			}
		}
		if e.mode == "opening" {
			timeout = 20 * time.Second
		}
		if age <= timeout {
			continue
		}
		if e.virtual != 0 && e.mode != "closed" {
			s.retire(e, now)
			continue
		}
		if e.upstream != nil {
			e.upstream.Close()
		}
		if e.local != nil {
			e.local.Close()
		}
		delete(s.entries, t)
		if e.virtual != 0 {
			delete(s.ports, e.virtual)
		}
	}
	for p, e := range s.ports {
		if s.entries[e.tuple] != e && e.mode == "closed" && now.Sub(e.last) > 4*time.Minute {
			delete(s.ports, p)
		}
	}
}

func (e *tcpEntry) finishOpen() {
	if e.openDone != nil {
		e.openOnce.Do(func() { close(e.openDone) })
	}
}
