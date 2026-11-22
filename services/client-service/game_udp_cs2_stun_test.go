package clientservice

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
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
