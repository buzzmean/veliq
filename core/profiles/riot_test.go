package profiles

import "testing"

func TestRiotLauncherNeverMatchesGameOrAntiCheat(t *testing.T) {
	r := New(Defaults())
	for _, name := range RiotLauncherExecutables() {
		p, ok := r.Match(Identity{PID: 1, CreationTime: 1, Path: `C:\Riot Games\Riot Client\` + name})
		if !ok || p.ID != "riot-client" || p.Mode != Auto {
			t.Fatal(name, p, ok)
		}
	}
	for _, exe := range []string{`C:\Riot Games\VALORANT\live\ShooterGame\Binaries\Win64\VALORANT-Win64-Shipping.exe`, `C:\Riot Games\League of Legends\Game\League of Legends.exe`, `C:\Program Files\Riot Vanguard\vgc.exe`, `C:\Other\RiotClientServices.exe`} {
		if p, ok := r.Match(Identity{PID: 1, CreationTime: 1, Path: exe}); ok {
			t.Fatal("outside launcher", exe, p)
		}
	}
}
