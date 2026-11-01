package windowsplatform

import (
	"sync"
	"time"

	"github.com/buzzmean/neexitlag/core/browserproxy"
)

const quicFlowLimit = 1024

type quicFlowEntry struct {
	owner       ProcessIdentity
	endpoint    uint64
	stamp       int64
	seen        time.Time
	spent, dead bool
}
type quicFlowLedger struct {
	mu      sync.Mutex
	entries map[Tuple]*quicFlowEntry
	clock   func() (int64, int64)
	epoch   uint64
	floor   int64
}
type quicFlowPermit struct {
	ledger          *quicFlowLedger
	entry           *quicFlowEntry
	tuple           Tuple
	packetStamp     int64
	issued, claimed bool
	epoch           uint64
	current         func() bool
}

// QUICProbeTrigger is an opaque, one-shot permission to schedule an owned
// public probe. It is not browser routing authority. Only capture can construct
// it, after a fresh kernel FLOW event and complete visible ClientHello.
type QUICProbeTrigger struct {
	key    browserproxy.HTTP3ProbeKey
	permit *quicFlowPermit
}

func (t QUICProbeTrigger) Key() browserproxy.HTTP3ProbeKey { return t.key }
func (t QUICProbeTrigger) BrowserTuple() Tuple {
	if t.permit == nil {
		return Tuple{}
	}
	return t.permit.tuple
}

// Current survives closure of the source browser socket, but never a capture restart.
// It authorizes only the already claimed, separately owned probe.
func (t QUICProbeTrigger) Current() bool {
	p := t.permit
	if p == nil {
		return false
	}
	p.ledger.mu.Lock()
	defer p.ledger.mu.Unlock()
	return p.claimed && p.epoch == p.ledger.epoch && (p.current == nil || p.current())
}
func (t QUICProbeTrigger) Claim() bool {
	p := t.permit
	if p == nil || p.ledger == nil {
		return false
	}
	l := p.ledger
	l.mu.Lock()
	defer l.mu.Unlock()
	if !p.issued || p.claimed || p.epoch != l.epoch || (p.current != nil && !p.current()) || p.entry.dead || l.entries[p.tuple] != p.entry {
		return false
	}
	now, freq := l.ticks()
	if !quicFreshTicks(p.packetStamp, now, freq) {
		return false
	}
	p.claimed = true
	return true
}
func (l *quicFlowLedger) ticks() (int64, int64) {
	if l.clock != nil {
		return l.clock()
	}
	return quicOwnerClock()
}
func quicFreshTicks(at, now, freq int64) bool {
	return freq > 0 && freq <= 1000000000000 && at > 0 && now >= at && now-at <= 2*freq
}
func (l *quicFlowLedger) room(now time.Time) bool {
	if l.entries == nil {
		l.entries = make(map[Tuple]*quicFlowEntry)
	}
	if len(l.entries) < quicFlowLimit {
		return true
	}
	for k, e := range l.entries {
		if now.Sub(e.seen) > 2*time.Minute {
			e.dead = true
			delete(l.entries, k)
		}
	}
	return len(l.entries) < quicFlowLimit
}
func (l *quicFlowLedger) established(t Tuple, id ProcessIdentity, endpoint uint64, stamp int64, now time.Time) {
	if t.Protocol != "udp" || t.Destination.Port() != 443 || endpoint == 0 {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if e := l.entries[t]; e != nil {
		// Duplicate/late FLOW cannot refresh age or restore a consumed first flight.
		if e.owner == id && e.endpoint == endpoint {
			return
		}
		e.dead = true
		e.endpoint = endpoint // A matching close can retire this ambiguous generation.
		return
	}
	if stamp <= l.floor || !l.room(now) {
		return
	}
	l.entries[t] = &quicFlowEntry{owner: id, endpoint: endpoint, stamp: stamp, seen: now}
}
func (l *quicFlowLedger) deleted(t Tuple, endpoint uint64) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if e := l.entries[t]; e != nil && e.endpoint == endpoint {
		e.dead = true
		delete(l.entries, t)
	}
}
func (l *quicFlowLedger) clear() {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, e := range l.entries {
		e.dead = true
	}
	l.entries = nil
	l.epoch++
}

// Every UDP443 first packet consumes freshness, including unselected traffic
// and owner-table fallback. No late FLOW event or packet-cache expiry upgrades it.
func (l *quicFlowLedger) packet(t Tuple, id ProcessIdentity, stamp int64, now time.Time) *quicFlowPermit {
	l.mu.Lock()
	defer l.mu.Unlock()
	e := l.entries[t]
	if e == nil {
		if l.room(now) {
			l.entries[t] = &quicFlowEntry{owner: id, seen: now, spent: true, dead: true}
		} else {
			l.floor = max(l.floor, stamp)
		}
		return nil
	}
	if e.spent || e.dead {
		return nil
	}
	e.spent = true
	ticks, freq := l.ticks()
	if e.owner != id || !browserProcess(id) || e.endpoint == 0 || !quicFreshTicks(e.stamp, stamp, freq) || !quicFreshTicks(stamp, ticks, freq) {
		return nil
	}
	return &quicFlowPermit{ledger: l, entry: e, tuple: t, packetStamp: stamp, epoch: l.epoch}
}
func (p *quicFlowPermit) trigger(domain string, d Decision) QUICProbeTrigger {
	if p == nil {
		return QUICProbeTrigger{}
	}
	l := p.ledger
	l.mu.Lock()
	defer l.mu.Unlock()
	if p.issued || p.entry.dead || l.entries[p.tuple] != p.entry || !quicOriginEligible(p.entry.owner, p.tuple, d) {
		return QUICProbeTrigger{}
	}
	now, freq := l.ticks()
	if !quicFreshTicks(p.packetStamp, now, freq) {
		return QUICProbeTrigger{}
	}
	p.issued = true
	id := p.entry.owner
	return QUICProbeTrigger{key: browserproxy.HTTP3ProbeKey{Host: domain, Endpoint: p.tuple.Destination, PID: id.PID, Birth: id.CreationTime, Executable: id.Path, Network: d.Network, Profile: d.Flow.ApplicationID, Revision: d.Revision}, permit: p}
}
