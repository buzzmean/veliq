package clientservice

import (
	"context"
	"encoding/json"
	"github.com/buzzmean/neexitlag/core/gameudp"
	"os"
	"path/filepath"
	"testing"
)

const primerRequest = `{"profile_id":"pubg","enabled":true,"local_only":true,"primer":{"endpoint":"18.157.46.1:7766","ttl":4,"repeats":6,"cutoff":2}}`

func TestGamePrimerIPCAndPersistence(t *testing.T) {
	c, _ := gameController(t)
	c.customPath = filepath.Join(t.TempDir(), "profiles.json")
	if _, err := c.Handle(context.Background(), "gameudp.set", json.RawMessage(primerRequest)); err != nil {
		t.Fatal(err)
	}
	g := c.games.items["pubg"]
	if g.Primer == nil || g.Engine.Snapshot().Primer == nil || !g.LocalOnly {
		t.Fatal("not applied")
	}
	for _, request := range []string{`{"profile_id":"pubg","enabled":true,"local_only":false}`, `{"profile_id":"pubg","enabled":true,"primer":{"endpoint":"18.157.46.1:7766","ttl":17,"repeats":6,"cutoff":2}}`, `{"profile_id":"pubg","enabled":true,"primer":{"endpoint":"18.157.46.1:7766","ttl":4,"repeats":6,"cutoff":2,"unexpected":1}}`} {
		if _, err := c.Handle(context.Background(), "gameudp.set", json.RawMessage(request)); err == nil {
			t.Fatal("invalid request accepted")
		}
	}
	// Legacy toggle omits the option and must preserve endpoint and no-relay policy.
	if _, err := c.Handle(context.Background(), "gameudp.set", json.RawMessage(`{"profile_id":"pubg","enabled":false}`)); err != nil {
		t.Fatal(err)
	}
	fresh := New(context.Background())
	defer fresh.Close()
	fresh.customPath = c.customPath
	fresh.loadGames()
	got := fresh.games.items["pubg"]
	if fresh.games.error != "" || got.Enabled || !got.LocalOnly || got.Primer == nil || *got.Primer != *g.Primer || got.Engine.Snapshot().Primer == nil {
		t.Fatal("persistence", fresh.games.error)
	}
	if _, err := c.Handle(context.Background(), "gameudp.set", json.RawMessage(`{"profile_id":"pubg","enabled":false,"primer":null}`)); err != nil {
		t.Fatal(err)
	}
	if g.Primer != nil || g.Engine.Snapshot().Primer != nil || !g.LocalOnly {
		t.Fatal("explicit clear")
	}
}
func TestGamePrimerSaveFailureAndInvalidDisk(t *testing.T) {
	c, id := gameController(t)
	dir := t.TempDir()
	file := filepath.Join(dir, "file")
	if err := os.WriteFile(file, []byte("fixture"), 0600); err != nil {
		t.Fatal(err)
	}
	c.customPath = filepath.Join(file, "profiles.json")
	if _, err := c.Handle(context.Background(), "gameudp.set", json.RawMessage(primerRequest)); err == nil {
		t.Fatal("save error ignored")
	}
	g := c.games.items["pubg"]
	if g.Primer != nil || g.LocalOnly || g.Engine.Snapshot().Primer != nil {
		t.Fatal("failed save mutated runtime")
	}
	c.customPath = filepath.Join(dir, "profiles.json")
	raw, err := json.Marshal(gameDisk{Version: 2, Games: []gameDiskEntry{{ProfileID: "pubg", Path: id.Path, Enabled: true, Primer: &gameudp.Primer{Endpoint: "18.157.46.1:7766", TTL: 17, Repeats: 6, Cutoff: 2}}}})
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(dir, "game-udp.json"), raw, 0600); err != nil {
		t.Fatal(err)
	}
	c.games.items = map[string]*gameEntry{}
	c.loadGames()
	g = c.games.items["pubg"]
	if c.games.error != "GAME_UDP_CONFIG_INVALID" || g.Enabled || !g.LocalOnly || !g.Engine.Snapshot().LocalOnly {
		t.Fatal("corrupt primer granted relay or activation")
	}
}
