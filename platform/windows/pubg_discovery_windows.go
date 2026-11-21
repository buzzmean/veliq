//go:build windows

package windowsplatform

import (
	"github.com/buzzmean/neexitlag/core/gameudp"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
	"os"
	"path/filepath"
)

func DiscoverPUBG(ownerSID string) PUBGInstallation {
	return DiscoverSteamGame(ownerSID, gameudp.Presets()[0])
}
func DiscoverSteamGame(ownerSID string, p gameudp.Preset) PUBGInstallation {
	roots := []string{}
	if _, err := windows.StringToSid(ownerSID); err == nil {
		if k, err := registry.OpenKey(registry.USERS, ownerSID+`\Software\Valve\Steam`, registry.QUERY_VALUE); err == nil {
			if p, _, err := k.GetStringValue("SteamPath"); err == nil {
				roots = append(roots, p)
			}
			k.Close()
		}
	}
	for _, view := range []uint32{registry.WOW64_64KEY, registry.WOW64_32KEY} {
		if k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Valve\Steam`, registry.QUERY_VALUE|view); err == nil {
			if p, _, err := k.GetStringValue("InstallPath"); err == nil {
				roots = append(roots, p)
			}
			k.Close()
		}
	}
	for _, base := range []string{os.Getenv("ProgramFiles(x86)"), os.Getenv("ProgramFiles")} {
		if base != "" {
			roots = append(roots, filepath.Join(base, "Steam"))
		}
	}
	return FindSteamGame(roots, p)
}
