package localstrategy

import (
	"bytes"
	"encoding/binary"
	"net/netip"
	"testing"
)

func continuousUDPProfile() Profile {
	p := profile()
	p.Protocol, p.Strategy, p.Cutoff, p.ContinuousUDP = "udp", "udp-fragment-24", 0, true
	return p
}

func TestContinuousUDPFragmentPreservesEveryDatagram(t *testing.T) {
	p := continuousUDPProfile()
	e, st, m := engine(t, p), &State{}, metadata()
	m.Protocol = "udp"
	for i := 0; i < 512; i++ {
		payload := bytes.Repeat([]byte{byte(i)}, 17+i%1200)
		raw := packet(17, payload)
		before := append([]byte(nil), raw...)
		r := e.Process(raw, st, m)
		if !r.Modified || len(r.Packets) != 2 || r.FakePackets != 0 || r.FakeAt(0) || r.FakeAt(1) || r.First != (i == 0) {
			t.Fatalf("datagram %d: missing bounded fragment plan: %+v", i, r)
		}
		var body []byte
		for j, q := range r.Packets {
			offset := binary.BigEndian.Uint16(q[6:])
			if finish(sum(q[:20])) != 0 || int(offset&8191)*8 != len(body) || offset&0x4000 != 0 || (offset&0x2000 != 0) != (j == 0) || len(q) > len(raw) {
				t.Fatal("invalid fragment headers")
			}
			body = append(body, q[20:]...)
		}
		if !bytes.Equal(raw, before) || !bytes.Equal(body, raw[20:]) || finish(sum(raw[12:20])+17+uint32(len(body))+sum(body)) != 0 {
			t.Fatal("original/reassembled UDP or checksum changed")
		}
		e.Commit(r, len(raw))
	}
	if got := e.Metrics(); got.Modified != 512 || got.Extra != 512 || got.Flows != 1 || got.RelayAvoided != 0 {
		t.Fatal(got)
	}
}

func TestContinuousUDPRequiresExplicitFragmentOptIn(t *testing.T) {
	for _, change := range []func(*Profile){
		func(p *Profile) { p.Protocol = "tcp" },
		func(p *Profile) { p.Strategy = "tcp-split-1" },
		func(p *Profile) { p.Cutoff = 1 },
		func(p *Profile) { p.IPs = nil },
		func(p *Profile) { p.Strategy = "chain"; p.Actions = []Action{{Kind: "fake-tls", TTL: 5}} },
	} {
		p := continuousUDPProfile()
		change(&p)
		if _, err := compile(p); err == nil {
			t.Fatalf("unsafe continuous configuration accepted: %+v", p)
		}
	}
	p := continuousUDPProfile()
	p.ContinuousUDP, p.Cutoff = false, 8
	e, st, m := engine(t, p), &State{}, metadata()
	m.Protocol = "udp"
	for i := 0; i < 10; i++ {
		if got := e.Process(packet(17, bytes.Repeat([]byte{1}, 100)), st, m).Modified; got != (i < 8) {
			t.Fatal("legacy cutoff changed", i, got)
		}
	}
}

func TestContinuousUDPIsolationAndReload(t *testing.T) {
	p := continuousUDPProfile()
	e, m := engine(t, p), metadata()
	m.Protocol = "udp"
	raw := packet(17, bytes.Repeat([]byte{1}, 100))
	for _, change := range []func(*Metadata){
		func(m *Metadata) { m.Application = "other.exe" },
		func(m *Metadata) { m.Destination = netip.MustParseAddrPort("203.0.113.9:80") },
		func(m *Metadata) { m.Destination = netip.MustParseAddrPort("198.51.100.1:443") },
	} {
		other := m
		change(&other)
		if e.Process(raw, &State{}, other).Modified {
			t.Fatal("fragmentation escaped application/endpoint scope")
		}
	}
	st := &State{}
	if !e.Process(raw, st, m).Modified {
		t.Fatal("initial fragment missing")
	}
	changed := p
	changed.Enabled = false
	if err := e.Reload(Config{Version: 1, Enabled: true, User: []Profile{changed}}); err != nil {
		t.Fatal(err)
	}
	if e.Process(raw, st, m).Modified {
		t.Fatal("disabled flow still fragmented")
	}
	if err := e.Reload(Config{Version: 1, Enabled: true, User: []Profile{p}}); err != nil {
		t.Fatal(err)
	}
	if e.Process(raw, st, m).Modified {
		t.Fatal("old flow restarted after reload")
	}
	if !e.Process(raw, &State{}, m).Modified {
		t.Fatal("fresh flow not enabled")
	}
}
