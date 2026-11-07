package clientservice

import (
	"context"
	"encoding/json"
	"path/filepath"
	"testing"
)

func TestSTUNPrimerIPCPolicyAndPersistence(t *testing.T) {
	c, _ := gameController(t)
	c.customPath = filepath.Join(t.TempDir(), "profiles.json")
	req := json.RawMessage(`{"profile_id":"pubg","enabled":true,"local_only":true,"primer":{"kind":"stun","data_cutoff":4,"endpoint":"18.157.46.1:7766","ttl":8,"repeats":6,"cutoff":2}}`)
	if _, err := c.Handle(context.Background(), "gameudp.set", req); err != nil {
		t.Fatal(err)
	}
	fresh := New(context.Background())
	defer fresh.Close()
	fresh.customPath = c.customPath
	fresh.loadGames()
	g := fresh.games.items["pubg"]
	if fresh.games.error != "" || g == nil || !g.Enabled || !g.LocalOnly || g.Primer == nil || g.Primer.Kind != "stun" || g.Primer.DataCutoff != 4 {
		t.Fatal("STUN config lost or relay enabled", fresh.games.error)
	}
	g = c.games.items["pubg"]
	if _, err := c.Handle(context.Background(), "gameudp.set", json.RawMessage(`{"profile_id":"pubg","enabled":true,"local_only":false}`)); err == nil {
		t.Fatal("STUN permitted without local_only")
	}
	if _, err := c.Handle(context.Background(), "gameudp.set", json.RawMessage(`{"profile_id":"pubg","enabled":false,"primer":null}`)); err != nil {
		t.Fatal(err)
	}
	if g.Primer != nil || g.Engine.Snapshot().Primer != nil || !g.LocalOnly {
		t.Fatal("clear lost route restriction")
	}
}
