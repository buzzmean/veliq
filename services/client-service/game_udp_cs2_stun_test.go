package clientservice

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"testing"
)

func TestCS2STUNSidecarUsesExistingGameProfileOnReload(t *testing.T) {
	c := New(context.Background())
	defer c.Close()
	dir := t.TempDir()
	c.customPath = filepath.Join(dir, "profiles.json")
	oldProfile := gameDisk{Version: 2, Games: []gameDiskEntry{
		{ProfileID: "cs2", Path: `D:\Steam\CS2\cs2.exe`, Enabled: true, LocalOnly: true},
		{ProfileID: "pubg", Path: `D:\Steam\PUBG\TslGame.exe`, Enabled: true, LocalOnly: true},
	}}
	raw, err := json.Marshal(oldProfile)
	if err != nil {
		t.Fatal(err)
	}
	profilePath := filepath.Join(dir, "game-udp.json")
	if err := os.WriteFile(profilePath, raw, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "game-udp-cs2.json"), []byte(`{"endpoint":"203.0.113.10:27015"}`), 0600); err != nil {
		t.Fatal(err)
	}
	c.loadGames()
	if c.games.error != "" || c.games.cs2STUNInvalid || c.games.items["cs2"] == nil || c.games.items["pubg"] == nil {
		t.Fatal("game settings did not load")
	}
	if s := c.games.items["cs2"].Engine.Snapshot(); s.CS2STUNEndpoint != "203.0.113.10:27015" || !s.LocalOnly {
		t.Fatal(s)
	}
	if s := c.games.items["pubg"].Engine.Snapshot(); s.CS2STUNEndpoint != "" {
		t.Fatal("CS2 endpoint leaked to PUBG", s)
	}
	if err := c.saveGamesLocked(); err != nil {
		t.Fatal(err)
	}
	saved, err := os.ReadFile(profilePath)
	if err != nil || bytes.Contains(saved, []byte("203.0.113.10")) || bytes.Contains(saved, []byte("primer")) {
		t.Fatal("the existing game profile format must remain readable by 715", err)
	}
}

func TestCS2STUNServerPortScopeRequiresValidConfigAndCS2Profile(t *testing.T) {
	for _, tc := range []struct {
		name    string
		config  string
		ports   []uint16
		invalid bool
	}{
		{"ports", `{"ports":[27016,27015,27015]}`, []uint16{27015, 27016}, false},
		{"privileged port", `{"ports":[53,27015]}`, nil, true},
		{"both selectors", `{"endpoint":"203.0.113.10:27015","ports":[27015]}`, nil, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := New(context.Background())
			defer c.Close()
			dir := t.TempDir()
			c.customPath = filepath.Join(dir, "profiles.json")
			if err := os.WriteFile(filepath.Join(dir, "game-udp-cs2.json"), []byte(tc.config), 0600); err != nil {
				t.Fatal(err)
			}
			c.loadCS2STUNScope()
			if c.games.cs2STUNInvalid != tc.invalid {
				t.Fatalf("invalid config: got %v, want %v", c.games.cs2STUNInvalid, tc.invalid)
			}
			cs2 := c.newGameLadder("cs2", `D:\Steam\CS2\cs2.exe`)
			if len(cs2.Snapshot().CS2STUNPorts) != 0 {
				t.Fatal("CS2 STUN requires local-only mode")
			}
			cs2.SetLocalOnly(true)
			if got := cs2.Snapshot().CS2STUNPorts; !slices.Equal(got, tc.ports) {
				t.Fatalf("CS2 STUN ports: got %v, want %v", got, tc.ports)
			}
			for _, other := range []struct{ id, path string }{
				{"pubg", `D:\Steam\PUBG\TslGame.exe`},
				{"cs2", `D:\Steam\Apex\r5apex_dx12.exe`},
			} {
				engine := c.newGameLadder(other.id, other.path)
				engine.SetLocalOnly(true)
				if len(engine.Snapshot().CS2STUNPorts) > 0 {
					t.Fatalf("CS2 STUN scope leaked to %s", other.path)
				}
			}
		})
	}
}
