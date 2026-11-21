package gameudp

import (
	"bytes"
	"errors"
	"io"
	"net/netip"
	"strings"
	"testing"
	"time"
)

const app = `C:\Steam\steamapps\common\PUBG\TslGame\Binaries\Win64\TslGame.exe`

func fixture(t *testing.T) (*Engine, *Flow, time.Time) {
	t.Helper()
	e := New()
	e.Configure(app, true)
	e.SetReason("")
	at := time.Unix(1000, 0)
	f, err := e.Open(Key{Network: strings.Repeat("a", 64), Application: app, PID: 77, Birth: 100, Source: netip.MustParseAddrPort("192.0.2.1:50000"), Destination: netip.MustParseAddrPort("18.157.46.1:7766")}, at)
	if err != nil {
		t.Fatal(err)
	}
	return e, f, at
}

type brokenRandom struct{}

func (brokenRandom) Read([]byte) (int, error) {
	return 0, errors.New("secret material must not escape")
}
func TestGeneratedIndependentQUICShape(t *testing.T) {
	for _, v := range Variants() {
		a, err := Generate(v, nil)
		if err != nil {
			t.Fatal(err)
		}
		b, err := Generate(v, nil)
		if err != nil {
			t.Fatal(err)
		}
		if len(a) < 1200 || len(a) > MaxPayload || a[0] != v.First || !bytes.Equal(a[1:5], []byte{0, 0, 0, 1}) || a[5] != 8 || a[14] != 8 || a[23] != 0 {
			t.Fatal("invalid generated long header")
		}
		if bytes.Equal(a[6:14], b[6:14]) || bytes.Equal(a[26:], b[26:]) {
			t.Fatal("flow random identity reused")
		}
	}
	if _, err := Generate(Variants()[0], brokenRandom{}); err == nil || strings.Contains(err.Error(), "secret") {
		t.Fatal("unsafe random failure", err)
	}
	if _, err := Generate(Variants()[0], io.LimitReader(bytes.NewReader(make([]byte, 10)), 10)); err == nil {
		t.Fatal("short random read")
	}
	bad := Variants()[0]
	bad.Repeats = 17
	if _, err := Generate(bad, nil); err == nil {
		t.Fatal("unbounded repeats")
	}
}
func TestCutoffAndGenerationNeverRestartExistingFlow(t *testing.T) {
	e, f, at := fixture(t)
	total := 0
	for i := 0; i < 10; i++ {
		p, k := e.Plan(f, at)
		if i < 2 && (k != 12 || len(p) != 1250) {
			t.Fatal("owner-proven default not preserved", k)
		}
		if i >= 2 && k != 0 {
			t.Fatal("cutoff")
		}
		total += k
		for j := 0; j < k; j++ {
			e.FakeSent(f, len(p)+28, nil)
		}
		e.Outgoing(f, 60, at)
	}
	if total != 24 || e.Snapshot().Flows[0].Fakes != 24 {
		t.Fatal("wrong explicit local-only exception budget")
	}
	e.Configure(app, false)
	e.Configure(app, true)
	if _, k := e.Plan(f, at); k != 0 {
		t.Fatal("toggle restarted old first flight")
	}
}
func TestScopeOnlyExactPUBGIPv4PublicHighUDP(t *testing.T) {
	for _, tc := range []struct {
		exe, proto, dst string
		want            bool
	}{
		{app, "udp", "18.157.46.1:7766", true}, {strings.ToUpper(app), "udp", "18.157.46.1:7766", true},
		{`C:\Other\TslGame.exe`, "udp", "18.157.46.1:7766", false}, {`C:\Games\cs2.exe`, "udp", "18.157.46.1:7766", false},
		{app, "tcp", "18.157.46.1:7766", false}, {app, "udp", "8.8.8.8:53", false}, {app, "udp", "1.1.1.1:443", false},
		{app, "udp", "192.168.1.1:7766", false}, {app, "udp", "127.0.0.1:7766", false}, {app, "udp", "100.64.1.1:7766", false},
		{app, "udp", "[2606:4700:4700::1111]:7766", false}, {app, "udp", "224.0.0.1:7766", false},
	} {
		if got := Eligible(tc.exe, app, tc.proto, netip.MustParseAddrPort(tc.dst)); got != tc.want {
			t.Fatal(tc, got)
		}
	}
}
func TestReplyBurstCannotTeachHealthyNetwork(t *testing.T) {
	for _, replies := range []int{0, 1, 15} {
		e, f, at := fixture(t)
		prime(e, f, at)
		for sec := 0; sec <= 7; sec++ {
			now := at.Add(time.Duration(sec) * time.Second)
			e.Outgoing(f, 60, now)
			if sec == 0 {
				for i := 0; i < replies; i++ {
					e.Reply(f, 50, now)
				}
			}
			e.Tick(now)
		}
		s := e.Snapshot()
		if s.Flows[0].State != "INSUFFICIENT_REPLIES" || len(s.Learning) != 1 || s.Learning[0].Confirmed || s.Learning[0].Index != 1 {
			t.Fatal("burst/silence learned healthy", s)
		}
		f2, err := e.Open(f.key, at.Add(8*time.Second))
		if err != nil || f2.e.Variant.Repeats != 6 {
			t.Fatal("next flow did not try alternative", err)
		}
		if f.e.Variant.Repeats != 12 {
			t.Fatal("active flow migrated")
		}
	}
}
func sustain(e *Engine, f *Flow, at time.Time) {
	prime(e, f, at)
	for i := 0; i < 8; i++ {
		now := at.Add(time.Duration(i) * time.Second / 2)
		e.Outgoing(f, 60, now)
		e.Reply(f, 100, now)
		e.Tick(now)
	}
}
func TestSustainedHealthAndConfirmedLivenessLoss(t *testing.T) {
	e, f, at := fixture(t)
	sustain(e, f, at)
	s := e.Snapshot()
	if s.Flows[0].State != "SUSTAINED_REPLIES" || !s.Learning[0].Confirmed {
		t.Fatal(s)
	}
	for i := 4; i <= 10; i++ {
		now := at.Add(time.Duration(i) * time.Second)
		e.Outgoing(f, 50, now)
		e.Tick(now)
	}
	s = e.Snapshot()
	if s.Flows[0].State != "INSUFFICIENT_REPLIES" || s.Learning[0].Index != 1 {
		t.Fatal("liveness loss not bounded", s)
	}
	old := s.Learning[0]
	e.Tick(at.Add(11 * time.Second))
	if e.Snapshot().Learning[0] != old {
		t.Fatal("flow advanced more than once")
	}
}
func TestIdleReadGapDoesNotFailAndLearningIsNetworkScoped(t *testing.T) {
	e, f, at := fixture(t)
	sustain(e, f, at)
	e.Tick(at.Add(30 * time.Second))
	if e.Snapshot().Flows[0].State != "SUSTAINED_REPLIES" {
		t.Fatal("idle mistaken for failure")
	}
	k := f.key
	k.Network = strings.Repeat("b", 64)
	g, err := e.Open(k, at.Add(30*time.Second))
	if err != nil || g.e.Variant.ID != Variants()[0].ID {
		t.Fatal("network cache crossed", err)
	}
}
func TestFiniteAlternativesAndHardGlobalBudget(t *testing.T) {
	e, f, at := fixture(t)
	for trial := 0; trial < len(Variants()); trial++ {
		if trial > 0 {
			var err error
			f, err = e.Open(f.key, at)
			if err != nil {
				t.Fatal(err)
			}
		}
		prime(e, f, at)
		for sec := 0; sec <= 7; sec++ {
			now := at.Add(time.Duration(sec) * time.Second)
			e.Outgoing(f, 50, now)
			e.Tick(now)
		}
		at = at.Add(8 * time.Second)
	}
	if _, err := e.Open(f.key, at); err == nil {
		t.Fatal("unbounded candidate cycling")
	}
	e, f, at = fixture(t)
	total := 0
	for i := 0; i < 30; i++ {
		g, err := e.Open(f.key, at)
		if err != nil {
			t.Fatal(err)
		}
		_, k := e.Plan(g, at)
		total += k
	}
	if total > MaxFakePerSecond {
		t.Fatal("global fake rate unbounded", total)
	}
}

func TestConflictStopsOldFirstFlightAndDoesNotResumeIt(t *testing.T) {
	e, f, at := fixture(t)
	e.SetReason("FOREIGN_UDP_CAPTURE")
	if _, k := e.Plan(f, at); k != 0 {
		t.Fatal("double processing")
	}
	e.SetReason("")
	if _, k := e.Plan(f, at); k != 0 {
		t.Fatal("old flow resumed priming")
	}
}
func TestIncompletePrimingDoesNotTeachNetworkFailure(t *testing.T) {
	e, f, at := fixture(t)
	e.Plan(f, at)
	e.FakeSent(f, 0, errors.New("send"))
	for i := 0; i < 8; i++ {
		e.Outgoing(f, 60, at.Add(time.Duration(i)*time.Second))
	}
	e.Tick(at.Add(7 * time.Second))
	if len(e.Snapshot().Learning) != 0 {
		t.Fatal("unsent strategy learned as network failure")
	}
}

func prime(e *Engine, f *Flow, at time.Time) {
	for n := 0; n < f.e.Variant.Cutoff; n++ {
		p, k := e.Plan(f, at)
		for i := 0; i < k; i++ {
			e.FakeSent(f, len(p)+28, nil)
		}
	}
}
func TestIncompletePrimingWithoutSendErrorDoesNotTeachFailure(t *testing.T) {
	e, f, at := fixture(t)
	p, k := e.Plan(f, at)
	for i := 0; i < k; i++ {
		e.FakeSent(f, len(p)+28, nil)
	}
	for i := 0; i < 8; i++ {
		e.Outgoing(f, 50, at.Add(time.Duration(i)*time.Second))
	}
	e.Tick(at.Add(7 * time.Second))
	if len(e.Snapshot().Learning) != 0 {
		t.Fatal("incomplete first flight taught a failure")
	}
}
