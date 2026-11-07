package windowsplatform

import (
	"bytes"
	"encoding/binary"
	"errors"
	"github.com/buzzmean/neexitlag/core/gameudp"
	"github.com/buzzmean/neexitlag/core/routing"
	"net/netip"
	"strings"
	"testing"
	"time"
)

func TestGameInitialPrimerNeverAdvancesToRelay(t *testing.T) {
	_, tuple := gamePacket()
	id := ProcessIdentity{PID: 77, CreationTime: 100, Path: `C:\Games\cs2.exe`}
	e := gameudp.NewLadder(&gameudp.Budget{})
	e.Configure(id.Path, true)
	e.SetLocalOnly(true)
	e.SetReason("")
	if err := e.SetPrimer(&gameudp.Primer{Endpoint: tuple.Destination.String(), TTL: 4, Repeats: 6, Cutoff: 2}); err != nil {
		t.Fatal(err)
	}
	base := Decision{GameUDP: e, GameRelayID: "fixture-unused-relay", Network: strings.Repeat("a", 64), Flow: routing.Flow{PID: id.PID, Protocol: "udp", ProcessPath: id.Path, Source: tuple.Source, Destination: tuple.Destination, PinnedPolicy: &routing.Policy{}}}
	at := time.Unix(1000, 0)
	for trial := 0; trial < 10; trial++ {
		tuple.Source = netip.AddrPortFrom(tuple.Source.Addr(), uint16(50000+trial))
		d, f, err := BindGameUDP(base, id, tuple, at)
		if err != nil || !d.Route.Direct() || d.BlockOnFailure || e.Evidence(f).Stage != gameudp.Local {
			t.Fatal("explicit primer escaped local", err, d)
		}
		for i := 0; i < 8; i++ {
			now := at.Add(time.Duration(i) * time.Second)
			payload, n := e.Plan(f, now)
			for j := 0; j < n; j++ {
				e.FakeSent(f, len(payload)+28, nil)
			}
			e.Outgoing(f, 64, now)
			e.Tick(now)
		}
		if e.Evidence(f).State != "INSUFFICIENT_REPLIES" || len(e.Snapshot().Learning) != 0 {
			t.Fatal("failed primer trained ladder", e.Snapshot())
		}
		at = at.Add(10 * time.Second)
	}
}

func TestGameInitialPrimerSenderAndTTL(t *testing.T) {
	for _, fail := range []bool{false, true} {
		raw, tuple := gamePacket()
		before := append([]byte(nil), raw...)
		id := ProcessIdentity{PID: 77, CreationTime: 100, Path: `C:\Games\cs2.exe`}
		e := gameudp.NewLadder(&gameudp.Budget{})
		e.Configure(id.Path, true)
		e.SetReason("")
		e.SetLocalOnly(true)
		if err := e.SetPrimer(&gameudp.Primer{Endpoint: tuple.Destination.String(), TTL: 4, Repeats: 6, Cutoff: 2}); err != nil {
			t.Fatal(err)
		}
		at := time.Unix(1000, 0)
		f, err := e.Open(gameudp.Key{Network: strings.Repeat("a", 64), Application: id.Path, PID: id.PID, Birth: id.CreationTime, Source: tuple.Source, Destination: tuple.Destination}, at)
		if err != nil {
			t.Fatal(err)
		}
		ledger := NewEvidenceLedger()
		ledger.BeginFlow(id, tuple)
		originals, fakes := 0, 0
		send := func(p []byte) error {
			if bytes.Equal(p, before) {
				originals++
				return nil
			}
			if fail {
				return errors.New("fixture")
			}
			if originals >= 2 || p[8] != 4 || len(p) != 1278 {
				t.Fatal("scope/cutoff/TTL/length")
			}
			qt, _, err := ParseUDP(p)
			if err != nil || qt != tuple {
				t.Fatal("tuple", err)
			}
			sum := uint32(0)
			for i := 0; i < 20; i += 2 {
				sum += uint32(binary.BigEndian.Uint16(p[i:]))
			}
			for sum>>16 != 0 {
				sum = (sum & 65535) + (sum >> 16)
			}
			if sum != 65535 {
				t.Fatal("TTL IP checksum")
			}
			fakes++
			return nil
		}
		for i := 0; i < 16; i++ {
			if err = SendGameUDP(e, f, id, tuple, raw, send, ledger, at); err != nil {
				t.Fatal(err)
			}
		}
		if originals != 16 || !bytes.Equal(raw, before) || !fail && fakes != 12 || fail && fakes != 0 {
			t.Fatal("original/fake count", originals, fakes)
		}
		if e.Evidence(f).FakeErrors == 0 && fail {
			t.Fatal("missing fake error")
		}
	}
	payload, err := gameudp.InitialPayload()
	if err != nil {
		t.Fatal(err)
	}
	p, _ := gamePacket()
	p[8] = 4
	if _, err = gameUDPPacketTTL(p, payload, 4); err == nil {
		t.Fatal("TTL not reduced")
	}
}
