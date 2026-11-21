package windowsplatform

import "strings"

// Presence is informational. The service decides applicability per exact game
// executable. Merely installed/stopped SCM entries never establish activity.
func observeGameAntiCheatProcess(s *GameUDPGuardStatus, name string) {
	switch strings.ToLower(name) {
	case "vgc.exe":
		s.VanguardClientRunning = true
	case "faceit.exe", "faceitclient.exe", "faceitservice.exe":
		s.FaceitClientRunning = true
	}
	updateGameAntiCheatPresence(s)
}
func observeGameAntiCheatService(s *GameUDPGuardStatus, name string, running bool) {
	if !running {
		return
	}
	switch strings.ToLower(name) {
	case "vgk":
		s.VanguardDriverRunning = true
	case "vgc":
		s.VanguardClientRunning = true
	case "faceit":
		s.FaceitDriverRunning = true
	case "faceitservice":
		s.FaceitClientRunning = true
	}
	updateGameAntiCheatPresence(s)
}
func updateGameAntiCheatPresence(s *GameUDPGuardStatus) {
	if s.VanguardDriverRunning || s.VanguardClientRunning || s.FaceitDriverRunning || s.FaceitClientRunning {
		s.DriverAntiCheat = "VANGUARD_OR_FACEIT"
	}
}
