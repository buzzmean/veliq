package clientservice

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/buzzmean/neexitlag/core/gameudp"
	"github.com/buzzmean/neexitlag/core/profiles"
	wp "github.com/buzzmean/neexitlag/platform/windows"
)

func TestSelectedGamesUseSTUN687WithoutRelay(t *testing.T) {
	for _, game := range []struct{ name, exe, preset string }{
		{"Rocket League", "RocketLeague.exe", "rocket-league"},
		{"ROB RUN", "ROB RUN.exe", "rob-run"},
		{"Warzone", "cod.exe", "warzone"},
		{"Apex DX12", "r5apex_dx12.exe", "apex"},
		{"Apex legacy", "r5apex.exe", "apex"},
		{"PUBG", "TslGame.exe", "pubg"},
	} {
		t.Run(game.name, func(t *testing.T) {
			c, _, _ := cs2GameFixture(t)
			image := `D:\Games\Selected\` + game.exe
			p := profiles.Profile{ID: "selected-game", Name: game.name, Mode: profiles.Auto, Executables: []string{image}, AppPreset: "game-udp-" + game.preset}
			raw, _ := json.Marshal(p)
			if _, err := c.Handle(context.Background(), "profile.set", raw); err != nil {
				t.Fatal(err)
			}
			c.discoverGames()
			c.updateGamesGate()
			id := wp.ProcessIdentity{PID: 88, CreationTime: 123, Path: image}
			tuple := policyTuple("udp", 7000)
			decision := c.Classify(id, tuple)
			if decision.GameUDP == nil || decision.GameRelayID != "" {
				t.Fatalf("selected Rocket route %+v", decision)
			}
			bound, f, err := wp.BindGameUDP(decision, id, tuple, time.Now())
			if err != nil || !bound.Route.Direct() || decision.GameUDP.Evidence(f).Variant.ID != "stun-binding-ttl8-k6-n2-d4" {
				t.Fatal(err, bound)
			}
			for _, v := range []wp.Tuple{destTuple("udp", "192.168.1.2", 7000), policyTuple("udp", 443), policyTuple("tcp", 443)} {
				d := c.Classify(id, v)
				if d.GameUDP != nil || !d.Route.Direct() || d.Flow.PinnedPolicy == nil {
					t.Fatalf("non-game flow %+v", d)
				}
			}
			c.games.items[p.ID].Engine.SetReason("FOREIGN_UDP_INTERCEPTOR")
			d := c.Classify(id, tuple)
			if d.GameUDP != nil || !d.Route.Direct() || d.Flow.PinnedPolicy == nil {
				t.Fatal("guard lost direct pin", d)
			}
			p.Mode = profiles.Direct
			raw, _ = json.Marshal(p)
			if _, err := c.Handle(context.Background(), "profile.set", raw); err != nil {
				t.Fatal(err)
			}
			if d := c.Classify(id, tuple); d.GameUDP != nil && d.GameUDP.Snapshot().STUNAuto {
				t.Fatal("DIRECT opt-out ignored", gameudp.Canonical(image))
			}
		})
	}
}
