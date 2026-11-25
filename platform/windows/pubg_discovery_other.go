//go:build !windows

package windowsplatform

import "github.com/buzzmean/veliq/core/gameudp"

func DiscoverPUBG(string) PUBGInstallation { return PUBGInstallation{Reason: "WINDOWS_REQUIRED"} }

func DiscoverSteamGame(_ string, _ gameudp.Preset) PUBGInstallation {
	return PUBGInstallation{Reason: "WINDOWS_REQUIRED"}
}
