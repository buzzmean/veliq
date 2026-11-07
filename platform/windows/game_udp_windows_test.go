//go:build windows

package windowsplatform

import (
	"bufio"
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/buzzmean/neexitlag/core/gameudp"
	"github.com/buzzmean/neexitlag/core/routing"
)

// Native PID/birth lookup + the real capture dispatch. Only final WinDivert
// writes are replaced; this is not actual-driver or game/anti-cheat acceptance.
func nativeGameIdentity(t *testing.T) ProcessIdentity {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^TestHotAttachIdentityChild$", "-test.v")
	cmd.Env = append(os.Environ(), "NEEXITLAG_HOT_IDENTITY_CHILD=1")
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err = cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { stdin.Close(); cmd.Wait() })
	ready := make(chan struct{})
	go func() {
		s := bufio.NewScanner(stdout)
		for s.Scan() {
			if s.Text() == "IDENTITY_READY" {
				close(ready)
				return
			}
		}
	}()
	select {
	case <-ready:
	case <-time.After(5 * time.Second):
		t.Fatal("identity helper")
	}
	id, err := NewDiscovery().Lookup(uint32(cmd.Process.Pid))
	if err != nil {
		t.Fatal(err)
	}
	return id
}
func TestNativeGameUDPFirstFlightAndUnselectedProcess(t *testing.T) {
	id := nativeGameIdentity(t)
	for _, tc := range []struct {
		selected bool
		endpoint uint64
	}{{false, 1}, {true, 1}, {true, 0}} {
		selected := tc.selected
		b, _ := captureFixture(t)
		b.gameGuard.ready = true
		e := gameudp.New()
		e.Configure(id.Path, true)
		e.SetReason("")
		p, _ := gamePacket()
		b.trackFlow(nativeGameFlowAddress(id.PID, tc.endpoint))
		fake, original := 0, 0
		b.packetWriter = func(q []byte, _ [80]byte) error {
			if bytes.Equal(p, q) {
				original++
			} else {
				fake++
			}
			return nil
		}
		classify := func(_ ProcessIdentity, tuple Tuple) Decision {
			d := Decision{Flow: routing.Flow{PID: id.PID, ProcessPath: id.Path, Protocol: "udp", Source: tuple.Source, Destination: tuple.Destination}, Revision: "game", Network: strings.Repeat("a", 64)}
			if selected {
				d.GameUDP = e
			}
			return d
		}
		for i := 0; i < 4; i++ {
			b.processUDP(nil, p, [80]byte{}, classify)
		}
		want := 0
		if selected && tc.endpoint != 0 {
			want = 24
		}
		if fake != want || original != 4 {
			t.Fatal(fake, original, selected)
		}
		raw, err := json.Marshal(b.evidence.Snapshot(id.PID))
		if err != nil || len(raw) == 0 {
			t.Fatal(err)
		}
	}
}

// The real native dispatch and UDP worker with a transport test double. It
// proves per-flow capture accounting, not real mTLS/Internet/game acceptance.
func TestNativeGameUDPRelayStageNoDirectLeak(t *testing.T) {
	id := nativeGameIdentity(t)
	b, _ := captureFixture(t)
	b.gameGuard.ready = true
	p, tuple := gamePacket()
	b.associations.Put(Association{Identity: id, Tuple: tuple, Endpoint: 1})
	e := gameudp.NewLadder(nil)
	e.Configure(id.Path, true)
	e.SetReason("")
	at := time.Now()
	network := strings.Repeat("a", 64)
	if err := e.Restore([]gameudp.Learning{{Network: network, Application: id.Path, Stage: gameudp.Relay, Index: 0, Tried: 7, Expires: at.Add(time.Minute)}}, at); err != nil {
		t.Fatal(err)
	}
	b.packetWriter = func(q []byte, a [80]byte) error {
		if a[10]&2 != 0 {
			t.Error("game relay leaked outbound original")
		}
		return nil
	}
	d := Decision{Revision: "game", GameUDP: e, GameRelayID: "VPS-01", Network: network, Flow: routing.Flow{PID: id.PID, ProcessPath: id.Path, ApplicationID: "selected-game", Protocol: "udp", Source: tuple.Source, Destination: tuple.Destination}}
	var a [80]byte
	a[10] = 2
	b.processUDP(nil, p, a, func(ProcessIdentity, Tuple) Decision { return d })
	captureWait(t, func() bool {
		s := b.evidence.Snapshot(id.PID)
		return len(s.Flows) == 1 && s.Flows[0].Counters.ReplyBytes > 0 && s.Flows[0].Counters.RelayedBytes == 4
	})
	f := b.evidence.Snapshot(id.PID).Flows[0]
	if f.Route != "RELAY" || f.RelayID != "VPS-01" || f.Counters.DirectBytes != 0 || f.Counters.GameFakePackets != 0 || f.GameUDP == nil || f.GameUDP.Stage != gameudp.Relay || f.Counters.RelayedBytes != 4 {
		t.Fatal(f)
	}
}
