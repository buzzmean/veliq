package clientservice

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/buzzmean/neexitlag/core/gameudp"
	"github.com/buzzmean/neexitlag/core/profiles"
	wp "github.com/buzzmean/neexitlag/platform/windows"
)

func gameController(t *testing.T) (*Controller, wp.ProcessIdentity) {
	path := `C:\Steam\steamapps\common\PUBG\TslGame\Binaries\Win64\TslGame.exe`
	p := profiles.Profile{ID: "pubg", Name: "PUBG", Executables: []string{path}, Mode: profiles.Direct}
	c := policyController(t, p)
	c.registerGame(gameudp.Presets()[0], path)
	g := c.games.items["pubg"]
	if g == nil {
		t.Fatal("PUBG not registered")
	}
	g.Engine.SetReason("")
	c.network.Store(&wp.NetworkContext{Fingerprint: strings.Repeat("a", 64), ObservedAt: time.Now()})
	return c, wp.ProcessIdentity{PID: 42, CreationTime: 100, Path: path}
}
func TestGameDefaultPUBGAndOtherOptInScope(t *testing.T) {
	c, id := gameController(t)
	preferGameRelay(c)
	d := c.Classify(id, policyTuple("udp", 7766))
	if d.GameUDP == nil || !d.Route.Direct() {
		t.Fatal(d)
	}
	for _, tc := range []struct {
		proto string
		port  uint16
	}{{"tcp", 443}, {"udp", 53}, {"udp", 443}} {
		d = c.Classify(id, policyTuple(tc.proto, tc.port))
		if d.GameUDP != nil || !d.Route.Direct() {
			t.Fatal("low port/TCP changed", d)
		}
	}
	d = c.Classify(wp.ProcessIdentity{PID: 43, CreationTime: 101, Path: `C:\Other\TslGame.exe`}, policyTuple("udp", 7766))
	if d.GameUDP != nil || !d.Route.Direct() {
		t.Fatal("basename inherited feature", d)
	}
	p := gameudp.Presets()[1]
	path := `C:\Steam\steamapps\common\CS2\game\bin\win64\cs2.exe`
	c.registerGame(p, path)
	if g := c.games.items["cs2"]; g == nil || g.Enabled {
		t.Fatal("CS2 automatically modified", g)
	}
	for _, p := range gameudp.Presets() {
		if p.ID != "pubg" && p.DefaultEnabled {
			t.Fatal("unverified anticheat enabled", p)
		}
	}
}
func TestGameOptOutPersistsAndRediscoveryDoesNotEnable(t *testing.T) {
	c, id := gameController(t)
	c.customPath = filepath.Join(t.TempDir(), "profiles.json")
	if _, err := c.handleGameUDP(context.Background(), "gameudp.set", json.RawMessage(`{"profile_id":"pubg","enabled":false}`)); err != nil {
		t.Fatal(err)
	}
	c.registerGame(gameudp.Presets()[0], id.Path)
	if c.games.items["pubg"].Enabled {
		t.Fatal("optout overwritten")
	}
	fresh := New(context.Background())
	defer fresh.Close()
	fresh.customPath = c.customPath
	fresh.loadGames()
	if fresh.games.error != "" || fresh.games.items["pubg"] == nil || fresh.games.items["pubg"].Enabled {
		t.Fatal("optout lost", fresh.games.error)
	}
}
func TestGameCannotOverrideProtectedOrAnticheatProfiles(t *testing.T) {
	for _, path := range []string{`C:\Apps\ChatGPT.exe`, `C:\Apps\chrome.exe`, `C:\Riot\VALORANT-Win64-Shipping.exe`, `C:\FACEIT\FACEIT.exe`} {
		p := profiles.Profile{ID: "custom-game", Name: "selected", Executables: []string{path}, Mode: profiles.Direct, Custom: true}
		c := policyController(t, p)
		if _, err := c.handleGameUDP(context.Background(), "gameudp.set", json.RawMessage(`{"profile_id":"custom-game","enabled":true}`)); err == nil {
			t.Fatal("unsafe game selection", path)
		}
	}
}
func TestGameArbitraryFullPathAndPerGameIsolation(t *testing.T) {
	c, id := gameController(t)
	path := `D:\Games\Other\game.exe`
	p := profiles.Profile{ID: "other", Name: "Other game", Executables: []string{path}, Mode: profiles.Direct, Custom: true}
	if err := c.Profiles.Upsert(p); err != nil {
		t.Fatal(err)
	}
	if _, err := c.handleGameUDP(context.Background(), "gameudp.set", json.RawMessage(`{"profile_id":"other","enabled":true}`)); err != nil {
		t.Fatal(err)
	}
	g := c.games.items["other"]
	if g == nil || g.Path != path || g.Engine == c.games.items["pubg"].Engine {
		t.Fatal("not isolated", g)
	}
	g.Engine.SetReason("")
	other := id
	other.Path = path
	other.PID++
	d := c.Classify(other, policyTuple("udp", 7766))
	if d.GameUDP != g.Engine {
		t.Fatal(d)
	}
}
func TestGamePathValidation(t *testing.T) {
	for _, p := range []string{"game.exe", `\\server\share\game.exe`, `C:\A\..\game.exe`, "C:/x\n/game.exe"} {
		if gamePath(p) {
			t.Fatal("invalid path", p)
		}
	}
	if !gamePath(`C:\Users\USER\Games\game.exe`) {
		t.Fatal("owner local profile path rejected")
	}
}
func TestAntiCheatPresenceDoesNotMasqueradeAsForeignWinDivert(t *testing.T) {
	c, _ := gameController(t)
	c.conflicts.Store(&wp.ConflictScan{AntiCheats: []string{"BEService"}, ObservedAt: time.Now()})
	n := wp.NetworkContext{}
	c.mergeConflicts(&n)
	if len(n.Conflicts) != 0 || len(n.AntiCheats) != 1 {
		t.Fatal("anti-cheat presence blocked unrelated routing", n)
	}
	c.conflicts.Store(&wp.ConflictScan{Conflicts: []string{"winws"}, AntiCheats: []string{"BEService"}, ObservedAt: time.Now()})
	c.mergeConflicts(&n)
	if len(n.Conflicts) != 1 {
		t.Fatal("real interceptor conflict lost")
	}
}
func TestGameStatusRemainsWithinIPCFrameWithLongPathsAndAllCaches(t *testing.T) {
	c := New(context.Background())
	defer c.Close()
	now := time.Now()
	path := `C:\` + strings.Repeat(`a\`, 1000) + `g.exe`
	for i := 0; i < 8; i++ {
		e := gameudp.NewLadder(c.games.budget)
		e.Configure(path, true)
		learning := []gameudp.Learning{}
		for n := 0; n < 16; n++ {
			learning = append(learning, gameudp.Learning{Network: strings.Repeat(string(rune('a'+n)), 64), Application: path, Stage: gameudp.Direct, Confirmed: true, Expires: now.Add(time.Hour)})
		}
		if err := e.Restore(learning, now); err != nil {
			t.Fatal(err)
		}
		id := strings.Repeat(string(rune('A'+i)), 128)
		c.games.items[id] = &gameEntry{ProfileID: id, Path: path, Name: id, Enabled: true, Engine: e}
	}
	status := c.gameStatus()
	raw, err := json.Marshal(status)
	if err != nil || len(raw) > 56*1024 {
		t.Fatal("oversized IPC", len(raw), err)
	}
	trimmed := false
	for _, p := range status.Profiles {
		trimmed = trimmed || p.Engine.Truncated
	}
	if !trimmed {
		t.Fatal("silent cache truncation")
	}
}
func TestGameFeatureCannotPreemptProtectedHelperGroup(t *testing.T) {
	c, id := gameController(t)
	id.Path = `C:\Games\helper.exe`
	id.PID++
	p := profiles.Profile{ID: "custom-helper", Name: "selected", Executables: []string{id.Path}, Mode: profiles.Direct, Custom: true}
	if err := c.Profiles.Upsert(p); err != nil {
		t.Fatal(err)
	}
	var protected profiles.Profile
	for _, v := range c.Profiles.List() {
		if v.ID == "chatgpt-desktop" {
			protected = v
			break
		}
	}
	protected.Identity.Helpers = append(protected.Identity.Helpers, "helper.exe")
	if err := c.Profiles.Upsert(protected); err != nil {
		t.Fatal(err)
	}
	e := gameudp.NewLadder(c.games.budget)
	e.Configure(id.Path, true)
	e.SetReason("")
	c.games.items[p.ID] = &gameEntry{ProfileID: p.ID, Path: id.Path, Enabled: true, Engine: e}
	// A binding previously verified by the existing ancestry mechanism.
	c.groupBindings[id.PID] = groupBinding{identity: id, profile: protected.ID}
	d := c.Classify(id, policyTuple("udp", 7766))
	if d.GameUDP != nil || d.Route.RelayID != "VPS-01" || !d.BlockOnFailure {
		t.Fatal("game opt-in preempted protected helper ancestry", d)
	}
}

func TestPUBGColdLocalFirstAfterDiscoveryCustomEnableAndReload(t *testing.T) {
	c, id := gameController(t)
	if p := c.games.items["pubg"].Engine.Snapshot().InitialPolicy; p != "LOCAL_FIRST_UNCONFIRMED_ENDPOINT" {
		t.Fatal("discovery DIRECT-first", p)
	}
	c.customPath = filepath.Join(t.TempDir(), "profiles.json")
	if _, err := c.handleGameUDP(context.Background(), "gameudp.set", json.RawMessage(`{"profile_id":"pubg","enabled":true}`)); err != nil {
		t.Fatal(err)
	}
	fresh := New(context.Background())
	defer fresh.Close()
	fresh.customPath = c.customPath
	fresh.loadGames()
	if fresh.games.error != "" || fresh.games.items["pubg"].Engine.Snapshot().InitialPolicy != "LOCAL_FIRST_UNCONFIRMED_ENDPOINT" {
		t.Fatal("reload lost policy", fresh.games.error)
	}
	fresh.games.items["pubg"].Engine.SetReason("")
	now := time.Now()
	flow, err := fresh.games.items["pubg"].Engine.Open(gameudp.Key{Network: strings.Repeat("a", 64), Application: id.Path, PID: id.PID, Birth: id.CreationTime, Source: policyTuple("udp", 7766).Source, Destination: policyTuple("udp", 7766).Destination}, now)
	if err != nil || fresh.games.items["pubg"].Engine.Evidence(flow).Stage != gameudp.Local {
		t.Fatal("first reloaded packet is not local", err)
	}
	other := c.newGameLadder(`D:\Games\Other\game.exe`)
	if other.Snapshot().InitialPolicy != "DIRECT_FIRST" {
		t.Fatal("other game default changed")
	}
}

func TestGameLocalOnlyPersistsAndCannotFallThroughWhenGuardNotReady(t *testing.T) {
	c, id := gameController(t)
	c.customPath = filepath.Join(t.TempDir(), "profiles.json")
	if _, err := c.Handle(context.Background(), "gameudp.set", json.RawMessage(`{"profile_id":"pubg","enabled":true,"local_only":true}`)); err != nil {
		t.Fatal(err)
	}
	g := c.games.items["pubg"]
	if !g.LocalOnly || !g.Engine.Snapshot().LocalOnly {
		t.Fatal("policy not applied")
	}
	g.Engine.SetReason("CAPTURE_NOT_READY")
	preferGameRelay(c)
	d, ok := c.classifyGameUDP(id, policyTuple("udp", 7766))
	if !ok || !d.Route.Direct() || d.GameUDP != nil || d.Flow.PinnedPolicy == nil {
		t.Fatal("local guard fell through", d)
	}
	c.network.Store(nil)
	d, ok = c.classifyGameUDP(id, policyTuple("udp", 7766))
	if !ok || !d.Route.Direct() || d.GameUDP != nil {
		t.Fatal("missing network escaped policy", d)
	}
	// An older client omitting the new option must not silently grant relay.
	if _, err := c.Handle(context.Background(), "gameudp.set", json.RawMessage(`{"profile_id":"pubg","enabled":false}`)); err != nil {
		t.Fatal(err)
	}
	fresh := New(context.Background())
	defer fresh.Close()
	fresh.customPath = c.customPath
	fresh.loadGames()
	if fresh.games.error != "" || !fresh.games.items["pubg"].LocalOnly || !fresh.games.items["pubg"].Engine.Snapshot().LocalOnly {
		t.Fatal("local-only lost", fresh.games.error)
	}
}
func TestGameLocalOnlySaveFailurePreservesPolicy(t *testing.T) {
	c, _ := gameController(t)
	// A file cannot serve as the destination directory.
	path := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(path, []byte("fixture"), 0600); err != nil {
		t.Fatal(err)
	}
	c.customPath = filepath.Join(path, "profiles.json")
	if _, err := c.Handle(context.Background(), "gameudp.set", json.RawMessage(`{"profile_id":"pubg","enabled":true,"local_only":true}`)); err == nil {
		t.Fatal("save failure ignored")
	}
	g := c.games.items["pubg"]
	if g.LocalOnly || g.Engine.Snapshot().LocalOnly {
		t.Fatal("failed save changed policy")
	}
}

func TestGameLocalOnlyInvalidLearningCannotRestoreRelayDefault(t *testing.T) {
	c, id := gameController(t)
	c.customPath = filepath.Join(t.TempDir(), "profiles.json")
	raw, err := json.Marshal(gameDisk{Version: 2, Games: []gameDiskEntry{{ProfileID: "pubg", Path: id.Path, Enabled: true, LocalOnly: true, Learning: []gameudp.Learning{{LocalOnly: true, Stage: gameudp.Relay, Network: strings.Repeat("a", 64), Application: id.Path, Expires: time.Now().Add(time.Hour)}}}}})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(filepath.Dir(c.customPath), "game-udp.json"), raw, 0600); err != nil {
		t.Fatal(err)
	}
	c.games.items = map[string]*gameEntry{}
	c.loadGames()
	c.registerGame(gameudp.Presets()[0], id.Path)
	if c.games.error != "GAME_UDP_CONFIG_INVALID" || !c.games.items["pubg"].LocalOnly {
		t.Fatal("invalid learning erased restriction")
	}
	c.gameStatus()
	d, ok := c.classifyGameUDP(id, policyTuple("udp", 7766))
	if !ok || !d.Route.Direct() || d.GameUDP != nil {
		t.Fatal("invalid learning enabled relay/decoys", d)
	}
}
