//go:build windows

package windowsplatform

import (
	"testing"
	"time"

	"github.com/buzzmean/veliq/core/flowpolicy"
	"github.com/buzzmean/veliq/core/gameudp"
	"github.com/buzzmean/veliq/core/routing"
)

// In-memory dispatch fixtures: no driver handle, process lookup or networking.
func directUDPBackendFixture(t *testing.T) (*WinDivertBackend, ProcessIdentity, Tuple, *captureFlow) {
	l, id, tuple, _ := directUDPFixture(t, 28017, true)
	b := NewWinDivert(DriverFiles{}, nil)
	b.evidence = l
	f := &captureFlow{identity: id, endpoint: 123, decision: Decision{Policy: flowpolicy.Result{Action: flowpolicy.Direct}}}
	b.flows[tuple] = f
	b.directUDPAssociations.Put(Association{Identity: id, Tuple: tuple, Endpoint: f.endpoint})
	b.noteDirectUDP(tuple, f)
	return b, id, tuple, f
}

func TestDirectUDPReplyPassiveDispatchBoundaries(t *testing.T) {
	for _, name := range []string{"plain", "retired", "blocked", "relay", "worker", "local-socket", "game-engine", "game-flow", "new-endpoint", "new-birth", "stale-ledger"} {
		t.Run(name, func(t *testing.T) {
			b, id, tuple, f := directUDPBackendFixture(t)
			switch name {
			case "game-engine":
				f.decision.GameUDP = &gameudp.Engine{}
			case "game-flow":
				f.game = &gameudp.Flow{}
			case "retired":
				f.retired = true
			case "blocked":
				f.decision.Block = true
			case "relay":
				f.decision.Route = routing.Route{RelayID: "VPS-01"}
			case "worker":
				f.decision.ProbeDirect = true
			case "local-socket":
				f.decision.cs2LocalSocket = true
			case "new-endpoint":
				b.directUDPAssociations.Put(Association{Identity: id, Tuple: tuple, Endpoint: 124})
			case "new-birth":
				other := id
				other.CreationTime++
				b.directUDPAssociations.Put(Association{Identity: other, Tuple: tuple, Endpoint: 123})
			case "stale-ledger":
				b.evidence.BeginFlow(id, tuple)
			}
			before := f.decision
			got := b.recordPassiveDirectReply(tuple, 80, time.Now())
			if got != (name == "plain") || f.decision.Policy != before.Policy || f.decision.Route != before.Route || b.RX.Load() != 0 || b.TX.Load() != 0 || b.Drops.Load() != 0 {
				t.Fatalf("passive boundary %s: %v", name, got)
			}
		})
	}
}

func TestDirectUDPReplyGuardedFlowWithoutGameEnrollment(t *testing.T) {
	l, id, tuple, _ := directUDPFixture(t, 28017, true)
	id.Path = `C:\Steam\cs2.exe`
	// Rebuild the ledger for the exact native identity, without enabling GameUDP.
	l = NewEvidenceLedger()
	l.BeginFlow(id, tuple)
	l.RecordBytes(id, tuple, "captured", "", 80)
	l.RecordPolicy(id, tuple, Decision{Policy: flowpolicy.Result{Action: flowpolicy.Direct, Source: "cs2_auto"}}, "")
	l.RecordBytes(id, tuple, "direct", "", 80)
	b := NewWinDivert(DriverFiles{}, nil)
	b.evidence = l
	b.cache = NewProcessCache(&discoveryFixture{id}, func(ProcessIdentity) bool { return true })
	f := &captureFlow{identity: id, decision: Decision{Policy: flowpolicy.Result{Action: flowpolicy.Direct}}}
	b.flows[tuple] = f
	b.trackFlowEvent(cs2FlowEvent(id, tuple, 567, true), func(ProcessIdentity, Tuple) Decision { return f.decision })
	b.noteDirectUDP(tuple, f)
	if f.endpoint != 0 || f.decision.CS2Auto || f.game != nil || f.decision.GameUDP != nil || !b.recordPassiveDirectReply(tuple, 80, time.Now()) {
		t.Fatal("passive FLOW observation requires or changes game enrollment")
	}
	b.trackDirectUDPReplyIdentity(Association{Tuple: tuple, Endpoint: 567}, true)
	if b.flows[tuple] != f || b.recordPassiveDirectReply(tuple, 80, time.Now()) {
		t.Fatal("diagnostic FLOW delete changed routing or accepted ended endpoint")
	}
	x := b.evidence.Snapshot(id.PID).Flows[0]
	if x.DirectUDPReply.IdentityBound {
		t.Fatal("ended native endpoint still claims coverage")
	}
}
