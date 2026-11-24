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
}

func Presets() []Preset {
	return []Preset{
		{"pubg", "PUBG: BATTLEGROUNDS", "578080", "TslGame.exe", []string{"TslGame", "Binaries", "Win64", "TslGame.exe"}, true, "BattlEye: runtime compatibility unverified"},
		{"cs2", "Counter-Strike 2", "730", "cs2.exe", []string{"game", "bin", "win64", "cs2.exe"}, false, "VAC; active FACEIT context requires verified compatibility"},
		{"dota2", "Dota 2", "570", "dota2.exe", []string{"game", "bin", "win64", "dota2.exe"}, false, "runtime compatibility unverified"},
		{"apex", "Apex Legends", "1172470", "r5apex_dx12.exe", []string{"r5apex_dx12.exe"}, false, "Easy Anti-Cheat: runtime compatibility unverified"},
		{"rocket-league", "Rocket League", "252950", "RocketLeague.exe", []string{"Binaries", "Win64", "RocketLeague.exe"}, false, "runtime compatibility unverified"},
		{"warzone", "Call of Duty / Warzone", "1938090", "cod.exe", []string{"cod.exe"}, false, "Ricochet: runtime compatibility unverified"},
		{"rob-run", "ROB RUN", "", "ROB RUN.exe", nil, false, "runtime compatibility unverified"},
		{"wardogs", "WARDOGS", "", "WARDOGS-Win64-Shipping.exe", nil, false, "runtime compatibility unverified"},
	}
}
