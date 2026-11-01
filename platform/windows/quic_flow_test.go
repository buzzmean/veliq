package windowsplatform

import (
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestQUICFlowFreshOneShotAndRevocation(t *testing.T) {
	id, tuple, d := quicOriginScopeFixture()
	now := time.Now()
	ticks := int64(1100)
	l := quicFlowLedger{clock: func() (int64, int64) { return ticks, 1000 }}
	l.established(tuple, id, 7, 1000, now)
	p := l.packet(tuple, id, 1050, now)
	if p == nil {
		t.Fatal("fresh kernel flow refused")
	}
	tr := p.trigger("www.youtube.com", d)
	if tr.Key().PID != id.PID || tr.Key().Birth != id.CreationTime || tr.BrowserTuple() != tuple || tr.Current() {
		t.Fatal("scope/claim contract")
	}
	var claims atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if tr.Claim() {
				claims.Add(1)
			}
		}()
	}
	wg.Wait()
	if claims.Load() != 1 || !tr.Current() || p.trigger("api.openai.com", d).Claim() {
		t.Fatal("not one shot")
	}
	l.established(tuple, id, 7, 1100, now)
	if l.packet(tuple, id, 1100, now) != nil {
		t.Fatal("duplicate FLOW revived permit")
	}
	l.deleted(tuple, 7)
	if !tr.Current() {
		t.Fatal("source close incorrectly cancels separate owned probe")
	}
	l.clear()
	if tr.Current() {
		t.Fatal("capture restart revived permit")
	}
}

func TestQUICFlowDenyLateAmbiguousExpiredAndChanged(t *testing.T) {
	for _, mode := range []string{"missing", "late", "wrong-owner", "stale-flow", "stale-packet", "future", "zero-stamp", "wrong-endpoint", "deleted", "changed-policy", "expired-claim", "zero-clock", "spent-before-selected"} {
		t.Run(mode, func(t *testing.T) {
			id, tuple, d := quicOriginScopeFixture()
			now := time.Now()
			ticks, freq := int64(1100), int64(1000)
			l := quicFlowLedger{clock: func() (int64, int64) { return ticks, freq }}
			if mode == "missing" || mode == "late" {
				l.packet(tuple, id, 1050, now)
			}
			l.established(tuple, id, 7, 1000, now)
			stamp := int64(1050)
			switch mode {
			case "wrong-owner":
				id.CreationTime++
			case "stale-flow":
				stamp = 3100
				ticks = 3200
			case "stale-packet":
				ticks = 4000
			case "future":
				stamp = 1200
			case "zero-stamp":
				stamp = 0
			case "zero-clock":
				freq = 0
			case "wrong-endpoint":
				l.established(tuple, id, 8, 1040, now)
			case "deleted":
				l.deleted(tuple, 7)
			case "spent-before-selected":
				l.packet(tuple, ProcessIdentity{}, 1040, now)
			}
			p := l.packet(tuple, id, stamp, now)
			if mode == "changed-policy" && p != nil {
				p.current = func() bool { return false }
			}
			tr := p.trigger("www.youtube.com", d)
			if mode == "expired-claim" {
				ticks = 4000
			}
			if tr.Claim() {
				t.Fatal("invalid flow authorized", mode)
			}
			if l.packet(tuple, id, stamp, now) != nil {
				t.Fatal("second packet revived permission")
			}
		})
	}
}
func TestQUICFlowCapacityAndGenerations(t *testing.T) {
	id, tuple, d := quicOriginScopeFixture()
	now := time.Now()
	l := quicFlowLedger{clock: func() (int64, int64) { return 1500, 1000 }}
	l.established(tuple, id, 7, 1000, now)
	p := l.packet(tuple, id, 1050, now)
	tr := p.trigger("www.youtube.com", d)
	l.deleted(tuple, 8)
	if !tr.Claim() {
		t.Fatal("unrelated close retired generation")
	}
	for i := 1; i < quicFlowLimit; i++ {
		v := tuple
		v.Source = netip.AddrPortFrom(tuple.Source.Addr(), uint16(i))
		l.packet(v, id, 1100, now)
	}
	overflow := tuple
	overflow.Source = netip.AddrPortFrom(tuple.Source.Addr(), 60000)
	if l.packet(overflow, id, 1200, now) != nil || len(l.entries) != quicFlowLimit {
		t.Fatal("capacity escaped")
	}
	l.deleted(tuple, 7)
	l.established(overflow, id, 8, 1150, now)
	if l.packet(overflow, id, 1250, now) != nil {
		t.Fatal("overflow allowed late FLOW")
	}
	l.clear()
	l.established(tuple, id, 8, 1300, now)
	if p.trigger("www.youtube.com", d).Claim() || tr.Current() {
		t.Fatal("old generation revived")
	}
	if !l.packet(tuple, id, 1350, now).trigger("www.youtube.com", d).Claim() {
		t.Fatal("fresh generation refused")
	}
}
