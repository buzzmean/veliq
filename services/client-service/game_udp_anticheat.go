package clientservice

import (
	"path"

	"github.com/buzzmean/neexitlag/core/gameudp"
	wp "github.com/buzzmean/neexitlag/platform/windows"
)

func gameAntiCheatReason(executable string, guard wp.GameUDPGuardStatus) string {
	base := path.Base(gameudp.Canonical(executable))
	switch base {
	case "valorant.exe", "valorant-win64-shipping.exe", "faceit.exe", "faceitclient.exe", "faceitservice.exe":
		return "DRIVER_ANTICHEAT_COMPATIBILITY_UNVERIFIED"
	case "cs2.exe":
		// A loaded FACEIT driver alone is not proof that this CS2 is a FACEIT match.
		// An active client/service is conservative context; exact match detection
		// would require a separate verified integration, not process inspection.
		legacyUnknown := guard.DriverAntiCheat != "" && !guard.FaceitDriverRunning && !guard.VanguardDriverRunning && !guard.VanguardClientRunning && !guard.FaceitClientRunning
		if guard.FaceitClientRunning && guard.FaceitDriverRunning || guard.AntiCheatQueryError != "" || legacyUnknown {
			return "DRIVER_ANTICHEAT_COMPATIBILITY_UNVERIFIED"
		}
	}
	// PUBG/BattlEye and other games do not inherit unrelated installed drivers.
	// Real foreign WinDivert conflict/readiness checks remain independent.
	return ""
}
