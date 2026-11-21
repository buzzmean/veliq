package routing

import (
	"context"
	"errors"
	"net/netip"
	"sync"
	"testing"
	"time"
)

// Deterministic transport fixture: only the existing engine's relay open and
// per-flow reservation are real. This is not Internet/media acceptance.
type cadenceDatagram struct {
	Datagram
	reply  []byte
	closes int
}

func (d *cadenceDatagram) Send([]byte) error { return nil }
func (d *cadenceDatagram) Receive(context.Context) ([]byte, error) {
	if d.reply != nil {
		b := d.reply
		d.reply = nil
		return b, nil
	}
	return nil, socketPollTimeout{}
}
func (d *cadenceDatagram) Close() error { d.closes++; return d.Datagram.Close() }

type cadenceFixture struct {
	d      *AdaptiveUDP
	direct *cadenceDatagram
	now    time.Time
}

func newCadenceFixture(t *testing.T, e *Engine, port uint16) *cadenceFixture {
	t.Helper()
	f := Flow{PID: uint32(port), ProcessPath: "media.exe", ApplicationID: "media", Network: "ISP-a", Source: netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), port), Destination: netip.MustParseAddrPort("127.0.0.1:19000")}
	d, err := e.OpenAdaptiveUDP(context.Background(), f, "VPS-01", 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	x := &cadenceFixture{d: d, now: time.Now()}
	x.direct = &cadenceDatagram{Datagram: d.current}
	d.current = x.direct
	d.now = func() time.Time { return x.now }
	t.Cleanup(func() { d.Close() })
	return x
}
func (x *cadenceFixture) tick(t *testing.T, i int, reply bool) {
	t.Helper()
	if err := x.d.Send([]byte("outbound media")); err != nil {
		t.Fatal(err)
	}
	if reply && x.d.Route().Direct() {
		x.direct.reply = []byte("inbound media")
	}
	_, err := x.d.Receive(context.Background())
	if x.d.Route().Direct() && err != nil && !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal(err)
	}
	x.now = x.now.Add(100 * time.Millisecond)
}
func TestAdaptiveCadenceTrials(t *testing.T) {
	for _, tc := range []struct {
		name   string
		reply  func(int) bool
		ticks  int
		reason string
	}{
		{"one reply then silence", func(i int) bool { return i == 0 }, 50, DirectInsufficientReplies},
		{"tiny initial burst then silence", func(i int) bool { return i < 3 }, 50, DirectInsufficientReplies},
		{"sustained bidirectional", func(int) bool { return true }, 100, ""},
		{"harmless intermittent read timeout", func(i int) bool { return i%5 != 0 }, 100, ""},
		{"confirmed then sustained inbound loss", func(i int) bool { return i < 20 }, 100, DirectLivenessLost},
		{"confirmed then rare replies never reset degradation", func(i int) bool { return i < 20 || i%9 == 0 }, 100, DirectLivenessLost},
		{"probation rare replies", func(i int) bool { return i%9 == 0 }, 50, DirectInsufficientReplies},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := New(8)
			p := &pinnedProvider{d: &pinnedDatagram{}}
			e.SetRelay("VPS-01", p)
			x := newCadenceFixture(t, e, 1230)
			for i := 0; i < tc.ticks; i++ {
				x.tick(t, i, tc.reply(i))
			}
			health := x.d.Health()
			if tc.reason == "" {
				if !x.d.Route().Direct() || health.State != DirectConfirmed || p.calls != 0 {
					t.Fatal(x.d.Route(), health, p.calls)
				}
				if health.ProbationDurationMS > 1200 {
					t.Fatal("healthy confirmation artificially delayed", health)
				}
			} else {
				if x.d.Route().RelayID != "VPS-01" || health.State != FlowRelayFallback || health.Reason != tc.reason || p.calls != 1 || x.direct.closes != 1 {
					t.Fatal(x.d.Route(), health, p.calls, x.direct.closes)
				}
				frozen := x.d.Health()
				// Further sends stay relay, even after an old direct socket could reply.
				for i := 0; i < 10; i++ {
					x.tick(t, i, true)
				}
				if p.calls != 1 {
					t.Fatal("flow flapped", p.calls)
				}
				if x.d.Health() != frozen {
					t.Fatal("fallback evidence did not freeze", frozen, x.d.Health())
				}
			}
		})
	}
}
func TestAdaptiveBurstCannotPopulateHealthyCache(t *testing.T) {
	e := New(8)
	p := &pinnedProvider{d: &pinnedDatagram{}}
	e.SetRelay("VPS-01", p)
	x := newCadenceFixture(t, e, 1231)
	if err := x.d.Send([]byte("probe")); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 20; i++ {
		x.direct.reply = []byte("burst")
		x.d.Receive(context.Background())
	}
	if h := x.d.Health(); h.State != DirectProbation || h.ProbationReplies != 20 || h.ProbationReplyBytes != 100 || h.ReplyBins != 1 {
		t.Fatal(h)
	}
	if len(e.health) != 0 {
		t.Fatal("burst learned healthy cache", e.health)
	}
	for i := 0; i < 40; i++ {
		x.tick(t, i, false)
	}
	k := udpHealthKey{x.d.flow.ApplicationID, x.d.flow.Network, x.d.flow.Destination.String()}
	if v, ok := e.health[k]; !ok || !v.relay || v.expires.Sub(time.Now()) > 2*time.Minute {
		t.Fatal("failed probation not bounded cached", v, ok)
	}
	if !e.udpCached(x.d.flow, time.Now()) {
		t.Fatal("failed cache not used")
	}
	next := x.d.flow
	next.Source = netip.MustParseAddrPort("127.0.0.1:1238")
	cached, err := e.OpenAdaptiveUDP(context.Background(), next, "VPS-01", 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer cached.Close()
	if cached.Route().RelayID != "VPS-01" || cached.Health().State != FlowRelayFallback || cached.Reason() != "LEARNED_RECENT_DIRECT_FAILURE" || p.calls != 2 {
		t.Fatal("new flow ignored relay cache", cached.Health(), p.calls)
	}

}
func TestAdaptiveCacheLearnsOnlyConfirmedAndThenFailure(t *testing.T) {
	e := New(8)
	e.SetRelay("VPS-01", &pinnedProvider{d: &pinnedDatagram{}})
	x := newCadenceFixture(t, e, 1232)
	x.tick(t, 0, true)
	if len(e.health) != 0 || x.d.Health().State != DirectProbation {
		t.Fatal("single reply learned success")
	}
	for i := 1; i < 20; i++ {
		x.tick(t, i, true)
	}
	k := udpHealthKey{x.d.flow.ApplicationID, x.d.flow.Network, x.d.flow.Destination.String()}
	if v, ok := e.health[k]; !ok || v.relay {
		t.Fatal("confirmed result not cached", v, ok)
	}
	for i := 20; i < 90; i++ {
		x.tick(t, i, i%9 == 0)
	}
	if !e.health[k].relay {
		t.Fatal("degraded result did not replace confirmed cache")
	}
}
func TestAdaptiveConcurrentFlowsRemainIndependent(t *testing.T) {
	e := New(16)
	p := &pinnedProvider{d: &pinnedDatagram{}}
	e.SetRelay("VPS-01", p)
	xs := []*cadenceFixture{newCadenceFixture(t, e, 1233), newCadenceFixture(t, e, 1234), newCadenceFixture(t, e, 1235)}
	var wg sync.WaitGroup
	for j, x := range xs {
		wg.Add(1)
		go func(j int, x *cadenceFixture) {
			defer wg.Done()
			for i := 0; i < 70; i++ {
				x.tick(t, i, j != 0 || i == 0)
			}
		}(j, x)
	}
	wg.Wait()
	if xs[0].d.Route().RelayID != "VPS-01" || !xs[1].d.Route().Direct() || !xs[2].d.Route().Direct() || p.calls != 1 {
		t.Fatal("unrelated flow changed")
	}
	if all := e.Snapshot(); len(all) != 3 {
		t.Fatal("reservation leak", all)
	}
}
func TestAdaptiveConfirmedIdleIsNotLivenessFailure(t *testing.T) {
	e := New(8)
	x := newCadenceFixture(t, e, 1236)
	for i := 0; i < 20; i++ {
		x.tick(t, i, true)
	}
	for i := 0; i < 100; i++ {
		x.now = x.now.Add(time.Second)
		x.d.Receive(context.Background())
	}
	if !x.d.Route().Direct() || x.d.Health().State != DirectConfirmed {
		t.Fatal("idle flow failed")
	}
	// Resume healthy traffic after the entire fixed ring has wrapped many times.
	for i := 0; i < 30; i++ {
		x.tick(t, i, true)
	}
	if !x.d.Route().Direct() {
		t.Fatal("healthy resume failed")
	}
}
func TestAdaptiveProbationStartsOnActualOutbound(t *testing.T) {
	e := New(8)
	x := newCadenceFixture(t, e, 1237)
	x.now = x.now.Add(time.Hour)
	x.d.Receive(context.Background())
	if x.d.Health().ProbationDurationMS != 0 || !x.d.Route().Direct() {
		t.Fatal("idle open started probation")
	}
	for i := 0; i < 20; i++ {
		x.tick(t, i, true)
	}
	if x.d.Health().State != DirectConfirmed {
		t.Fatal(x.d.Health())
	}
}

func TestCadenceRequiresContinuedOutboundNotOnlyReplies(t *testing.T) {
	var h udpCadence
	start := time.Now()
	for i := 0; i < 20; i++ {
		h.observe(start, false, 10)
	}
	for i := 0; i < 30; i++ {
		now := start.Add(time.Duration(i) * 100 * time.Millisecond)
		h.observe(now, true, 10)
		confirmed, failure := h.check(now, 3*time.Second)
		if confirmed || failure != "" {
			t.Fatal("burst-only outbound confirmed", confirmed, failure)
		}
	}
	if confirmed, failure := h.check(start.Add(3*time.Second), 3*time.Second); confirmed || failure != DirectInsufficientReplies {
		t.Fatal(confirmed, failure)
	}
}
func TestCadenceSustainedRecoveryClearsDegradation(t *testing.T) {
	var h udpCadence
	start := time.Now()
	for i := 0; i < 70; i++ {
		now := start.Add(time.Duration(i) * 100 * time.Millisecond)
		h.observe(now, false, 10)
		// Brief 1.5s loss after confirmation, then genuinely sustained recovery.
		if i < 20 || i >= 35 {
			h.observe(now, true, 10)
		}
		_, failure := h.check(now, 3*time.Second)
		if failure != "" {
			t.Fatal("short degradation falsely failed", i, failure)
		}
	}
	if h.stateName() != DirectConfirmed || !h.degraded.IsZero() {
		t.Fatal(h.snapshot(start.Add(7 * time.Second)))
	}
}
