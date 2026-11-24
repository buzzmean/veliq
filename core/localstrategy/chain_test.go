package localstrategy

import (
	"bytes"
	"encoding/binary"
	"github.com/buzzmean/veliq/core/optimizer"
	"net/netip"
	"sort"
	"sync"
	"testing"
	"time"
)

func chainProfile(actions ...Action) Profile {
	p := profile()
	p.Strategy = "chain"
	p.SplitPosition = 0
	p.Actions = actions
	p.Cutoff = 1
	return p
}
func confirmed(e *LocalStrategyEngine, seq uint32) *State {
	st := &State{}
	syn := packet(6, nil)
	syn[33] = 2
	binary.BigEndian.PutUint32(syn[24:], seq-1)
	checksumTransport(syn)
	e.Process(syn, st, metadata())
	st.ConfirmHandshake(seq, 99)
	return st
}
func tlsInput(seq uint32) []byte {
	p := packet(6, fakeHello())
	binary.BigEndian.PutUint32(p[24:], seq)
	binary.BigEndian.PutUint32(p[28:], 100)
	checksumTransport(p)
	return p
}
func checkPacket(t *testing.T, p []byte) {
	t.Helper()
	if finish(sum(p[:20])) != 0 || finish(sum(p[12:20])+6+uint32(len(p)-20)+sum(p[20:])) != 0 {
		t.Fatal("invalid IP/TCP checksum")
	}
}
func TestChainOldSequenceFakeCannotEnterStream(t *testing.T) {
	for _, seq := range []uint32{0, 1, 42, 0xfffffff0} {
		for _, ttl := range []uint8{2, 5, 8, 16} {
			p := chainProfile(Action{Kind: "fake-tls", TTL: ttl}, Action{Kind: "tcp-multisplit", Anchor: "sni", Positions: []uint16{1, 5}}, Action{Kind: "tcp-disorder"})
			e := engine(t, p)
			st := confirmed(e, seq)
			raw := tlsInput(seq)
			saved := append([]byte(nil), raw...)
			r := e.Process(raw, st, metadata())
			if !r.Modified || r.FakePackets != 1 || r.FakeTTL != ttl || len(r.Packets) != 4 {
				t.Fatal(r)
			}
			if !bytes.Equal(raw, saved) {
				t.Fatal("input mutated")
			}
			// Serial arithmetic models the RFC TCP receiver window, even at wraparound.
			// A fake ending strictly before RCV.NXT is wholly duplicate, not stream data.
			accepted := [][]byte{}
			for i, q := range r.Packets {
				checkPacket(t, q)
				payload, _ := packetPayload(q, "tcp")
				delta := int32(binary.BigEndian.Uint32(q[24:]) - seq)
				if i == 0 {
					if q[8] != ttl || delta+int32(len(payload)) != 0 || delta >= 0 {
						t.Fatal("fake could overlap application bytes")
					}
					continue
				}
				if delta < 0 || int(delta)+len(payload) > len(raw)-40 {
					t.Fatal("bad real sequence")
				}
				accepted = append(accepted, q)
			}
			if binary.BigEndian.Uint32(accepted[0][24:]) == seq {
				t.Fatal("disorder did not reorder")
			}
			sort.Slice(accepted, func(i, j int) bool {
				return int32(binary.BigEndian.Uint32(accepted[i][24:])-seq) < int32(binary.BigEndian.Uint32(accepted[j][24:])-seq)
			})
			got := []byte{}
			for _, q := range accepted {
				data, _ := packetPayload(q, "tcp")
				got = append(got, data...)
			}
			if !bytes.Equal(got, raw[40:]) {
				t.Fatal("application stream changed")
			}
			if e.Process(raw, st, metadata()).Modified {
				t.Fatal("cutoff/retransmission produced extra fake")
			}
		}
	}
}
func TestFakeRequiresConfirmedFirstCompleteClientHello(t *testing.T) {
	p := chainProfile(Action{Kind: "fake-tls", TTL: 5})
	e := engine(t, p)
	raw := tlsInput(1000)
	cases := []*State{{}, confirmed(e, 999), confirmed(e, 1000)}
	cases[2].handshakeConfirmed = false
	for _, st := range cases {
		if e.Process(raw, st, metadata()).Modified {
			t.Fatal("uncertain handshake modified")
		}
	}
	st := confirmed(e, 1000)
	bad := append([]byte(nil), raw...)
	bad[8] = 5
	if e.Process(bad, st, metadata()).Modified {
		t.Fatal("fake TTL not strictly below original")
	}
	for n := 0; n < len(fakeHello()); n++ {
		e := engine(t, p)
		st := confirmed(e, 1000)
		q := packet(6, fakeHello()[:n])
		binary.BigEndian.PutUint32(q[24:], 1000)
		binary.BigEndian.PutUint32(q[28:], 100)
		if e.Process(q, st, metadata()).Modified {
			t.Fatalf("truncated hello %d", n)
		}
	}
	if r := e.Process(packet(6, []byte("GET / HTTP/1.1\r\nHost: example.org\r\n\r\n")), confirmed(e, 1000), metadata()); r.Modified {
		t.Fatal("fake on HTTP")
	}
}
func TestFinitePresetsAndBounds(t *testing.T) {
	var profiles []Profile
	for _, name := range []string{"discord", "youtube"} {
		rows, defaultID, err := PresetProfiles(name, `C:\Apps\`+name+`.exe`, true)
		if err != nil || defaultID == "" || len(rows) != 7 {
			t.Fatal(err)
		}
		profiles = append(profiles, rows...)
	}
	e := New()
	if err := e.Reload(Config{Version: 1, Enabled: true, User: profiles}); err != nil {
		t.Fatal("two presets do not fit bounded config", err)
	}
	for _, actions := range [][]Action{{{Kind: "fake-tls", TTL: 1}}, {{Kind: "fake-tls", TTL: 17}}, {{Kind: "tcp-disorder"}}, {{Kind: "tcp-multisplit", Positions: []uint16{5, 1}}}, {{Kind: "shell"}}, {{Kind: "fake-tls", TTL: 5}, {Kind: "fake-tls", TTL: 5}}} {
		if e.Validate(Config{Version: 1, User: []Profile{chainProfile(actions...)}}) == nil {
			t.Fatal("unsafe plan accepted", actions)
		}
	}
}
func initialQUIC() []byte {
	p := make([]byte, 1200)
	p[0] = 0xc0
	p[4] = 1
	p[5] = 8
	i := 14
	p[i] = 0
	i++
	p[i] = 0
	i++
	n := len(p) - i - 2
	p[i] = byte(0x40 | n>>8)
	p[i+1] = byte(n)
	return p
}
func TestQUICFallbackIsExplicitScopedNewFlowBounded(t *testing.T) {
	rows, selected, _ := PresetProfiles("discord", `C:\test\chosen.exe`, true)
	e := New()
	if err := e.Reload(Config{Version: 1, Enabled: true, User: rows}); err != nil {
		t.Fatal(err)
	}
	raw := packet(17, initialQUIC())
	m := metadata()
	m.Protocol = "udp"
	m.StrategyID = selected
	for _, tc := range []struct {
		app, dest string
		want      bool
	}{{m.Application, "203.0.113.9:443", true}, {"control.exe", "203.0.113.9:443", false}, {m.Application, "203.0.113.9:50000", false}, {m.Application, "203.0.113.9:19300", false}} {
		q := append([]byte(nil), raw...)
		x := m
		x.Application = tc.app
		x.Destination = netip.MustParseAddrPort(tc.dest)
		binary.BigEndian.PutUint16(q[22:], x.Destination.Port())
		r := e.Process(q, &State{}, x)
		if r.Suppress != tc.want {
			t.Fatal(tc, r)
		}
	}
	st := &State{}
	for i := 0; i < 8; i++ {
		if !e.Process(raw, st, m).Suppress {
			t.Fatal("lost fallback")
		}
	}
	if e.Process(raw, st, m).Suppress {
		t.Fatal("unbounded drops")
	}
	st = &State{}
	e.Process(raw, st, m)
	st.quicUntil = time.Now().Add(-time.Second)
	if e.Process(raw, st, m).Suppress {
		t.Fatal("timeout not released")
	}
	st = &State{}
	e.Process(packet(17, []byte("already active UDP")), st, m)
	if e.Process(raw, st, m).Suppress {
		t.Fatal("existing UDP flow acquired fallback")
	}
	malformed := append([]byte(nil), raw...)
	malformed[33] = 255
	if e.Process(malformed, &State{}, m).Suppress {
		t.Fatal("malformed Initial suppressed")
	}
	e.Suspend(true)
	if e.Process(raw, &State{}, m).Suppress {
		t.Fatal("suspended engine blocks UDP")
	}
}
func TestChainParallelFlowsAndReloadFailOpen(t *testing.T) {
	e := engine(t, chainProfile(Action{Kind: "fake-tls", TTL: 5}, Action{Kind: "tcp-multisplit", Positions: []uint16{1, 5}}))
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			seq := uint32(1000 + i)
			st := confirmed(e, seq)
			if !e.Process(tlsInput(seq), st, metadata()).Modified {
				t.Error("parallel flow lost strategy")
			}
			e.Fail(st)
			if e.Process(tlsInput(seq), st, metadata()).Modified {
				t.Error("failed state modified")
			}
		}(i)
	}
	wg.Wait()
	st := confirmed(e, 1000)
	e.Reload(Config{Version: 1})
	if e.Process(tlsInput(1000), st, metadata()).Modified {
		t.Fatal("reload not fail-open")
	}
}
func FuzzComposablePacketPlans(f *testing.F) {
	f.Add(tlsInput(123))
	f.Add(packet(17, initialQUIC()))
	f.Fuzz(func(t *testing.T, p []byte) {
		e := New()
		cfg := chainProfile(Action{Kind: "fake-tls", TTL: 5}, Action{Kind: "tcp-multisplit", Anchor: "sni", Positions: []uint16{1, 5}}, Action{Kind: "tcp-disorder"})
		e.Reload(Config{Version: 1, Enabled: true, User: []Profile{cfg}})
		st := confirmed(e, 123)
		r := e.Process(p, st, metadata())
		if len(r.Packets) > 5 {
			t.Fatal("unbounded output")
		}
		for _, q := range r.Packets {
			checkPacket(t, q)
		}
	})
}

func TestAutoPrefersWorkingLocalBeforeFasterRelayAndExpires(t *testing.T) {
	now := time.Now()
	direct := optimizer.RouteMeasurement{Available: false, Samples: 1, ObservedAt: now}
	local := optimizer.RouteMeasurement{Available: true, Samples: 1, RTT: 100 * time.Millisecond, Stability: 1, ObservedAt: now}
	relay := local
	relay.RTT = time.Millisecond
	working := []Working{{Strategy: "fake5", Measurement: local, Expires: now.Add(15 * time.Minute)}}
	if got := Recommend(direct, working, relay, now.Add(5*time.Minute)); got != "fake5" {
		t.Fatal("local success lost to VPS traffic cost", got)
	}
	if got := Recommend(direct, working, relay, now.Add(16*time.Minute)); got != "" {
		t.Fatal("expired target evidence reused", got)
	}
}

func TestPresetRejectsRelativeExecutableScope(t *testing.T) {
	for _, app := range []string{"chrome.exe", "folder/chrome.exe", `C:chrome.exe`} {
		if _, _, err := PresetProfiles("youtube", app, true); err == nil {
			t.Fatal("relative scope accepted", app)
		}
	}
}
func TestFakeOnlyHasCompleteChecksumsWithoutInputMutation(t *testing.T) {
	e := engine(t, chainProfile(Action{Kind: "fake-tls", TTL: 5}))
	st := confirmed(e, 1000)
	raw := tlsInput(1000)
	raw[10] = 0
	raw[11] = 0
	raw[36] = 0
	raw[37] = 0 // native checksum offload metadata
	before := append([]byte(nil), raw...)
	r := e.Process(raw, st, metadata())
	if !r.Modified || len(r.Packets) != 2 {
		t.Fatal(r)
	}
	for _, q := range r.Packets {
		checkPacket(t, q)
	}
	if !bytes.Equal(before, raw) {
		t.Fatal("input modified")
	}
}

func TestTrustedCONNECTOriginDoesNotBorrowOuterSNI(t *testing.T) {
	e := New()
	p := chainProfile(Action{Kind: "tcp-multisplit", Positions: []uint16{1}})
	p.Domains = []string{"inner.example"}
	p.IPs = nil
	if err := e.Reload(Config{Version: 1, Enabled: true, User: []Profile{p}}); err != nil {
		t.Fatal(err)
	}
	data := packet(6, fakeHello())
	// Untrusted metadata must never override the actual observed SNI.
	untrusted := metadata()
	untrusted.Domain = "inner.example"
	if r := e.Process(data, &State{}, untrusted); r.Modified {
		t.Fatal("untrusted origin authorized transform")
	}
	trusted := metadata()
	trusted.Domain = "inner.example"
	trusted.TrustedOrigin = true
	if r := e.Process(data, &State{}, trusted); !r.Modified || r.Domain != "inner.example" {
		t.Fatal("owner-validated CONNECT origin not applied", r)
	}
}
