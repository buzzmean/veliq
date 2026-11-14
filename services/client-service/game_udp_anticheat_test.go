package clientservice

import (
	"context"
	"encoding/json"
	wp "github.com/buzzmean/neexitlag/platform/windows"
	"testing"
)

type gameGuardFixture struct {
	hotBackendFixture
	guard wp.GameUDPGuardStatus
}

func (b *gameGuardFixture) GameUDPGuardStatus() wp.GameUDPGuardStatus { return b.guard }
func TestGameAntiCheatGateAppliesOnlyToRelevantExecutable(t *testing.T) {
	idle := wp.GameUDPGuardStatus{Ready: true, DriverAntiCheat: "VANGUARD_OR_FACEIT", FaceitDriverRunning: true}
	for _, guard := range []wp.GameUDPGuardStatus{idle, {Ready: true, DriverAntiCheat: "VANGUARD_OR_FACEIT", VanguardDriverRunning: true}, {Ready: true, DriverAntiCheat: "VANGUARD_OR_FACEIT", FaceitDriverRunning: true, FaceitClientRunning: true}, {Ready: true, AntiCheatQueryError: "GAME_DRIVER_STATUS_UNAVAILABLE"}} {
		if r := gameAntiCheatReason(`C:\Steam\PUBG\TslGame.exe`, guard); r != "" {
			t.Fatal("unrelated driver gated PUBG", r)
		}
		if r := gameAntiCheatReason(`C:\Riot\VALORANT-Win64-Shipping.exe`, guard); r == "" {
			t.Fatal("Vanguard game enabled")
		}
	}
	if gameAntiCheatReason(`C:\Steam\cs2.exe`, idle) != "" {
		t.Fatal("idle FACEIT gated VAC CS2")
	}
	idle.FaceitClientRunning = true
	if gameAntiCheatReason(`C:\Steam\cs2.exe`, idle) == "" {
		t.Fatal("FACEIT context unguarded")
	}
}
func TestPUBGWithLoadedFACEITDriverActuallyClassifiesAndCanEnable(t *testing.T) {
	c, id := gameController(t)
	b := &gameGuardFixture{hotBackendFixture: hotBackendFixture{ready: true}, guard: wp.GameUDPGuardStatus{Ready: true, DriverAntiCheat: "VANGUARD_OR_FACEIT", FaceitDriverRunning: true}}
	c.Backend = b
	c.updateGamesGate()
	if !c.games.items["pubg"].Engine.Ready() {
		t.Fatal("PUBG blocked", c.gameStatus())
	}
	if d := c.Classify(id, policyTuple("udp", 7766)); d.GameUDP == nil {
		t.Fatal("not classified", d)
	}
	if _, err := c.handleGameUDP(context.Background(), "gameudp.set", json.RawMessage(`{"profile_id":"pubg","enabled":true}`)); err != nil {
		t.Fatal(err)
	}
	// Neither conflict nor unavailable capture may be bypassed by this exception.
	for _, guard := range []wp.GameUDPGuardStatus{{Ready: true, Conflict: true}, {Ready: false}, {Ready: true, Error: "GAME_PROCESS_LIST_UNAVAILABLE"}} {
		b.guard = guard
		c.updateGamesGate()
		if c.games.items["pubg"].Engine.Ready() {
			t.Fatal("real guard bypassed", guard)
		}
	}
}
func TestPUBGActiveArmedIsDistinctFromActuallyObservedDecoys(t *testing.T) {
	c, _ := gameController(t)
	c.Backend = &gameGuardFixture{hotBackendFixture: hotBackendFixture{ready: true}, guard: wp.GameUDPGuardStatus{Ready: true, DriverAntiCheat: "VANGUARD_OR_FACEIT", FaceitDriverRunning: true}}
	c.updateGamesGate()
	p := c.gameStatus().Profiles[0]
	if p.State != "READY_NEW_FLOWS" || !p.Ready || p.Activity != "WAITING_NEW_FLOW" || len(p.Engine.Flows) != 0 || p.Reason != "" {
		t.Fatal("false pending or false traffic evidence", p)
	}
	c.Backend.(*gameGuardFixture).guard.Conflict = true
	p = c.gameStatus().Profiles[0]
	if p.State != "PENDING" || p.Ready || p.Reason != "FOREIGN_UDP_INTERCEPTOR" {
		t.Fatal("real conflict masked", p)
	}
}
