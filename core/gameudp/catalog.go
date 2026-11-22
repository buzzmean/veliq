package gameudp

// Presets describe discovery and opt-in, not a claim of anti-cheat compatibility.
type Preset struct {
	ID             string   `json:"id"`
	Name           string   `json:"name"`
	SteamID        string   `json:"steam_id"`
	Executable     string   `json:"executable"`
	Relative       []string `json:"-"`
	DefaultEnabled bool     `json:"default_enabled"`
	AntiCheat      string   `json:"anti_cheat"`
	// AlternateExecutable, when set, is a fallback in the same verified directory.
	AlternateExecutable string `json:"-"`
}

func Presets() []Preset {
	return []Preset{
		{"pubg", "PUBG: BATTLEGROUNDS", "578080", "TslGame.exe", []string{"TslGame", "Binaries", "Win64", "TslGame.exe"}, true, "BattlEye: runtime compatibility unverified", ""},
		{"cs2", "Counter-Strike 2", "730", "cs2.exe", []string{"game", "bin", "win64", "cs2.exe"}, false, "VAC; active FACEIT context requires verified compatibility", ""},
		{"dota2", "Dota 2", "570", "dota2.exe", []string{"game", "bin", "win64", "dota2.exe"}, false, "runtime compatibility unverified", ""},
		{"apex", "Apex Legends", "1172470", "r5apex_dx12.exe", []string{"r5apex_dx12.exe"}, false, "Easy Anti-Cheat: runtime compatibility unverified", "r5apex.exe"},
	}
}
