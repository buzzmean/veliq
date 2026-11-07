package windowsplatform

import (
	"bytes"
	"encoding/binary"
	"github.com/buzzmean/neexitlag/core/gameudp"
	"strings"
	"testing"
	"time"
)

func TestSTUNSenderPreservesOriginalAndScopesShortPayload(t *testing.T) {
	raw, tuple := gamePacket()
	before := append([]byte(nil), raw...)
	payload, err := gameudp.STUNPayload()
	if err != nil {
		t.Fatal(err)
	}
	if _, err = GameUDPPacket(raw, payload); err == nil {
		t.Fatal("unscoped short payload")
	}
	bad := append([]byte(nil), payload...)
	bad[4] ^= 1
	if _, err = gameUDPPacketTTL(raw, bad, 8); err == nil {
		t.Fatal("malformed short payload")
	}
	id := ProcessIdentity{PID: 77, CreationTime: 100, Path: `C:\Games\cs2.exe`}
	e := gameudp.NewLadder(&gameudp.Budget{})
	e.Configure(id.Path, true)
	e.SetLocalOnly(true)
	e.SetReason("")
	if err = e.SetPrimer(&gameudp.Primer{Kind: "stun", Endpoint: tuple.Destination.String(), TTL: 8, Repeats: 6, Cutoff: 2, DataCutoff: 4}); err != nil {
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
	nonces := map[string]bool{}
	expected := before
	send := func(p []byte) error {
		if bytes.Equal(p, expected) {
			originals++
			return nil
		}
		got, d, err := ParseUDP(p)
		if err != nil || got != tuple || !gameudp.IsSTUNBinding(d) || p[8] != 8 || len(p) != 48 {
			t.Fatal("fake shape", err)
		}
		if nonces[string(d[8:])] {
			t.Fatal("reused STUN transaction")
		}
		nonces[string(d[8:])] = true
		fakes++
		return nil
	}
	for i := 0; i < 8; i++ {
		original := raw
		if i >= 2 {
			original = append(append([]byte(nil), raw[:28]...), []byte{128, 1, 2, 3, 4, 5, 6}...)
			binary.BigEndian.PutUint16(original[2:], uint16(len(original)))
			binary.BigEndian.PutUint16(original[24:], uint16(len(original)-20))
		}
		expected = append([]byte(nil), original...)
		if err = SendGameUDP(e, f, id, tuple, original, send, ledger, at); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(original, expected) {
			t.Fatal("original bytes modified")
		}
	}
	if originals != 8 || fakes != 36 || !bytes.Equal(raw, before) {
		t.Fatal("count or original changed", originals, fakes)
	}
}
