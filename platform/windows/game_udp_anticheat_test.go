package windowsplatform

import (
	"testing"
	"time"
)

func TestGameAntiCheatInstalledStoppedIsNotActive(t *testing.T) {
	s := GameUDPGuardStatus{}
	for _, name := range []string{"vgk", "vgc", "FACEIT", "FACEITService"} {
		observeGameAntiCheatService(&s, name, false)
	}
	if s.DriverAntiCheat != "" || s.Conflict {
		t.Fatal(s)
	}
	observeGameAntiCheatService(&s, "FACEIT", true)
	if !s.FaceitDriverRunning || s.FaceitClientRunning || s.VanguardDriverRunning || s.Conflict {
		t.Fatal(s)
	}
	observeGameAntiCheatProcess(&s, "FACEITClient.exe")
	if !s.FaceitClientRunning {
		t.Fatal(s)
	}
}
func TestGameVanguardAndFaceitEvidenceIndependent(t *testing.T) {
	s := GameUDPGuardStatus{}
	observeGameAntiCheatService(&s, "vgk", true)
	if !s.VanguardDriverRunning || s.FaceitDriverRunning || s.FaceitClientRunning {
		t.Fatal(s)
	}
	observeGameAntiCheatProcess(&s, "BEService.exe")
	if s.FaceitClientRunning || s.VanguardClientRunning || s.Conflict {
		t.Fatal(s)
	}
}

func TestGameProcessScanDoesNotHoldPacketGuardAndResetDiscardsOldObservation(t *testing.T) {
	var g gameGuardState
	entered := make(chan struct{})
	finish := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		g.processSnapshot(time.Now(), func() GameUDPGuardStatus { close(entered); <-finish; return GameUDPGuardStatus{Conflict: true} })
	}()
	<-entered
	// Both calls acquire the same mutex used by packet priming/REFLECT. A slow
	// SCM scan must not delay either one. No timeout loosening or real SCM queries.
	inspected := make(chan struct{})
	go func() {
		defer close(inspected)
		s := g.processSnapshot(time.Now(), func() GameUDPGuardStatus { t.Error("duplicate startup scan"); return GameUDPGuardStatus{} })
		if s.Error != "GAME_PROCESS_CHECK_PENDING" {
			t.Error("startup not guarded")
		}
		g.reset()
	}()
	select {
	case <-inspected:
	case <-time.After(time.Second):
		close(finish)
		<-done
		t.Fatal("slow process scan held packet lock")
	}
	close(finish)
	<-done
	if s := g.processSnapshot(time.Now(), func() GameUDPGuardStatus { return GameUDPGuardStatus{} }); s.Conflict {
		t.Fatal("stale pre-reset scan published")
	}
}
