package windowsplatform

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"testing"

	"github.com/buzzmean/neexitlag/core/localstrategy"
	"github.com/buzzmean/neexitlag/core/routing"
)

func TestContinuousUDPReinjectionAndNativeFailureFallback(t *testing.T) {
	for _, split := range []int{8, 16, 24} {
		for _, failAt := range []int{-1, 9} {
			engine := localstrategy.New()
			id := ProcessIdentity{PID: 42, CreationTime: 100, Path: `C:\Games\cs2.exe`}
			raw, tuple := gamePacket()
			// Use a valid nonzero IP ID and payload large enough for two fragments.
			raw = append(raw[:28], bytes.Repeat([]byte{7}, 100)...)
			binary.BigEndian.PutUint16(raw[2:], uint16(len(raw)))
			binary.BigEndian.PutUint16(raw[4:], 7)
			binary.BigEndian.PutUint16(raw[24:], uint16(len(raw)-20))
			if err := engine.Reload(localstrategy.Config{Version: 1, Enabled: true, User: []localstrategy.Profile{{ID: "fragment", Version: 1, Application: id.Path, Protocol: "udp", Ports: []uint16{tuple.Destination.Port()}, IPs: []string{tuple.Destination.Addr().String()}, Strategy: fmt.Sprintf("udp-fragment-%d", split), ContinuousUDP: true, Cutoff: 0, Enabled: true}}}); err != nil {
				t.Fatal(err)
			}
			decision := Decision{Route: routing.Route{Kind: routing.DirectPlusRoute}, Local: engine, LocalStrategyID: "fragment"}
			ledger, state := NewEvidenceLedger(), &localstrategy.State{}
			for i := 0; i < 16; i++ {
				var sent [][]byte
				err := SendLocal(decision, state, id, tuple, raw, func(p []byte) error {
					sent = append(sent, append([]byte(nil), p...))
					if i == failAt && len(sent) == 2 {
						return errors.New("fixture send failure")
					}
					return nil
				}, ledger)
				if err != nil {
					t.Fatal(err)
				}
				switch {
				case i == failAt:
					if len(sent) != 3 || !bytes.Equal(sent[2], raw) || state.Applied() {
						t.Fatal("failed plan must pass original and disable this flow", i, len(sent))
					}
				case failAt >= 0 && i > failAt:
					if len(sent) != 1 || !bytes.Equal(sent[0], raw) {
						t.Fatal("failed flow retried fragmentation", i)
					}
				default:
					if len(sent) != 2 || binary.BigEndian.Uint16(sent[0][6:]) != 0x2000 || binary.BigEndian.Uint16(sent[1][6:]) != uint16(split/8) || len(sent[0]) != 20+split {
						t.Fatal("missing fragmentation after cutoff", i)
					}
				}
			}
			counts := ledger.Snapshot(id.PID).Flows[0].Counters
			modified := uint64(16)
			if failAt >= 0 {
				modified = uint64(failAt)
			}
			if counts.DirectPlus != modified || counts.Direct != 16-modified || counts.RelayedBytes != 0 || counts.ReplyBytes != 0 {
				t.Fatal("incorrect wire result or relay fallback", counts)
			}
		}
	}
}
