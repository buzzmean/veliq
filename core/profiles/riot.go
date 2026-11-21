package profiles

import "strings"

// Launcher identities only. No ancestry inheritance to games, services or drivers.
func RiotLauncherExecutables() []string {
	return []string{"RiotClientServices.exe", "RiotClientUx.exe", "RiotClientUxRender.exe", "RiotClientCrashHandler.exe"}
}
func RiotLauncherPath(exe string) bool {
	p := normalize(exe)
	if !strings.Contains(p, "/riot games/riot client/") {
		return false
	}
	name := p[strings.LastIndex(p, "/")+1:]
	for _, n := range RiotLauncherExecutables() {
		if strings.EqualFold(name, n) {
			return true
		}
	}
	return false
}
