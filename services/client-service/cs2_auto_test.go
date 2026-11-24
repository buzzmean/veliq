package clientservice

import (
	"context"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/buzzmean/neexitlag/core/flowpolicy"
	"github.com/buzzmean/neexitlag/core/gameudp"
	"github.com/buzzmean/neexitlag/core/profiles"
	wp "github.com/buzzmean/neexitlag/platform/windows"
)

func cs2GameFixture(t *testing.T) (*Controller, wp.ProcessIdentity, profiles.Profile) {
	t.Helper()
	path := `D:\Steam\steamapps\common\Counter-Strike Global Offensive\game\bin\win64\cs2.exe`
	p := profiles.Profile{ID: "cs2", Name: "Counter-Strike 2", Executables: []string{path}, Mode: profiles.Direct, AppPreset: "game-udp-cs2"}
	c := policyController(t, p)
	c.customPath = filepath.Join(t.TempDir(), "profiles.json")
	c.Backend = &gameGuardFixture{hotBackendFixture: hotBackendFixture{ready: true}, guard: wp.GameUDPGuardStatus{Ready: true}}
	c.network.Store(&wp.NetworkContext{Fingerprint: strings.Repeat("a", 64), ObservedAt: time.Now()})
	c.registerGame(gameudp.Presets()[1], path)
	return c, wp.ProcessIdentity{PID: 32, CreationTime: 123, Path: path}, p
}

func TestCS2AutoReleasedDesktopProfileAndPrivateScope(t *testing.T) {
	c, owner, p := cs2GameFixture(t)
	ctx := context.Background()
	// 715 can leave local_only=true saved when the user later selects AUTO.
	call := func(method string, payload any) {
		t.Helper()
		b, err := json.Marshal(payload)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = c.Handle(ctx, method, b); err != nil {
			t.Fatal(method, err)
		}
	}
	call("gameudp.set", map[string]any{"profile_id": p.ID, "enabled": true, "local_only": true})
	p.Mode = profiles.Auto
	call("profile.set", p)
	call("gameudp.set", map[string]any{"profile_id": p.ID, "enabled": false})
	g := c.games.items[p.ID]
	if !g.CS2Auto || !g.Engine.Ready() || g.Engine.Snapshot().LocalOnly || g.Enabled {
		t.Fatalf("legacy mode overrode AUTO: %+v", c.gameStatus())
	}
	c.acceptanceRelays["VPS-01"] = acceptanceRelaySource{session: &readinessSession{done: make(chan struct{})}, address: "198.51.100.10:443"}
	d := c.Classify(owner, policyTuple("udp", 27015))
	if !d.CS2Auto || d.GameUDP != g.Engine || !d.Route.Direct() || d.GameRelayID != "" || d.GameQualityRelayID != "" {
		t.Fatalf("AUTO decision %+v", d)
	}
	if !c.cs2AutoProfile(p, owner) {
		t.Fatal("verified CS2 TCP eligibility unavailable")
	}
	copyOwner := owner
	copyOwner.Path = `C:\Downloads\cs2.exe`
	if other := c.Classify(copyOwner, policyTuple("udp", 27015)); other.CS2Auto || c.cs2AutoProfile(p, copyOwner) {
		t.Fatal("basename inherited AUTO")
	}
	for _, tuple := range []wp.Tuple{destTuple("udp", "192.168.1.200", 27015), destTuple("udp", "8.8.8.8", 53), destTuple("udp", "8.8.8.8", 443)} {
		if other := c.Classify(owner, tuple); other.CS2Auto || other.GameUDP != nil || !other.Route.Direct() {
			t.Fatalf("unsupported service captured: %+v", other)
		}
	}
	p.Mode = profiles.Direct
	call("profile.set", p)
	call("gameudp.set", map[string]any{"profile_id": p.ID, "enabled": false})
	if g.CS2Auto || g.Engine.Enabled() || c.Classify(owner, policyTuple("udp", 27015)).CS2Auto {
		t.Fatal("DIRECT selection ignored")
	}
}

func TestCS2AutoFreshDiscoveryReloadAndGuard(t *testing.T) {
	c, owner, p := cs2GameFixture(t)
	p.Mode = profiles.Auto
	raw, _ := json.Marshal(p)
	if _, err := c.Handle(context.Background(), "profile.set", raw); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Handle(context.Background(), "gameudp.set", json.RawMessage(`{"profile_id":"cs2","enabled":false}`)); err != nil {
		t.Fatal(err)
	}
	fresh := New(context.Background())
	t.Cleanup(fresh.Close)
	if err := fresh.SetCustomPath(c.customPath); err != nil {
		t.Fatal(err)
	}
	fresh.enabled = true
	fresh.Backend = &gameGuardFixture{hotBackendFixture: hotBackendFixture{ready: true}, guard: wp.GameUDPGuardStatus{Ready: true, FaceitClientRunning: true, FaceitDriverRunning: true}}
	fresh.network.Store(c.network.Load())
	fresh.registerGame(gameudp.Presets()[1], owner.Path)
	s := fresh.gameStatus()
	if len(s.Profiles) != 1 || !s.Profiles[0].CS2Auto || s.Profiles[0].Reason != "DRIVER_ANTICHEAT_COMPATIBILITY_UNVERIFIED" {
		t.Fatalf("guarded mode %+v", s)
	}
	d := fresh.Classify(owner, policyTuple("udp", 27015))
	if !d.Route.Direct() || d.GameUDP != nil || d.Flow.PinnedPolicy == nil {
		t.Fatalf("guard allowed non-direct %+v", d)
	}
	// A full, denied, or timed-out outcome may only originate from the game observer.
	fresh.clubMode.Store(true)
	if _, err := fresh.HandleOwnerIPC(context.Background(), "gameudp.cs2.outcome", json.RawMessage(`{"outcome":"TIMEOUT"}`)); err == nil || err.Error() != "CLUB_ADMIN_MANAGED" {
		t.Fatalf("club gate %v", err)
	}
}

func TestCS2AutoExactProfileStaysDirectBeforeSteamDiscovery(t *testing.T) {
	c, id, p := cs2GameFixture(t)
	p.Mode = profiles.Auto
	if err := c.Profiles.Upsert(p); err != nil {
		t.Fatal(err)
	}
	c.games.items[p.ID].SteamCS2 = false
	for _, endpoint := range []wp.Tuple{destTuple("udp", "8.8.8.8", 443), destTuple("udp", "2606:4700:4700::1111", 27015), policyTuple("udp", 27015)} {
		d := c.Classify(id, endpoint)
		if d.Flow.PinnedPolicy == nil || !d.Route.Direct() || d.GameUDP != nil || d.ProbeDirect || d.Deferred || d.Block || d.Policy.Source != "cs2_auto" {
			t.Fatalf("early policy %+v", d)
		}
	}
}

func TestCS2EndpointStatusThroughManagedReadOnlyIPC(t *testing.T) {
	c, id, p := cs2GameFixture(t)
	p.Mode = profiles.Auto
	if err := c.Profiles.Upsert(p); err != nil {
		t.Fatal(err)
	}
	n := c.network.Load()
	c.updateGamesGate()
	e := c.games.items[p.ID].Engine
	now := time.Now()
	target := policyTuple("udp", 27015)
	for i := range 16 {
		d := target.Destination
		if i > 0 {
			d = destTuple("udp", "8.8.4.4", uint16(28000+i)).Destination
		}
		if _, err := e.OpenCS2(gameudp.Key{PID: id.PID, Birth: id.CreationTime, Application: id.Path, Network: n.Fingerprint, Source: target.Source, Destination: d}, now); err != nil {
			t.Fatal(err)
		}
	}
	c.clubMode.Store(true)
	args, _ := json.Marshal(map[string]string{"profile_id": p.ID, "destination": target.Destination.String()})
	out, err := c.HandleOwnerIPC(context.Background(), "gameudp.cs2.endpoint", args)
	if err != nil {
		t.Fatal(err)
	}
	v := out.(cs2EndpointStatus)
	if v.Matched != 1 || len(v.Flows) != 1 || v.Flows[0].Destination != target.Destination.String() || v.Flows[0].Stage != gameudp.Direct || v.Truncated || v.Flows[0].Application != "" {
		t.Fatalf("%+v", v)
	}
	if _, err := c.HandleOwnerIPC(context.Background(), "gameudp.cs2.endpoint", json.RawMessage(`{"destination":"*","profile_id":"cs2"}`)); err == nil {
		t.Fatal("accepted wildcard")
	}
	p.Identity = profiles.IdentityFor(id.Path, p.AppPreset)
	p.Identity.Helpers = []string{"helper.exe"}
	if gameProfileSafe(p) {
		t.Fatal("CS2 group helpers permitted")
	}
}

func TestCS2AutoImportedRulesCannotDispatchRelay(t *testing.T) {
	c, id, p := cs2GameFixture(t)
	p.Mode = profiles.Auto
	p.RelayID = "VPS-01"
	p.Rules = []flowpolicy.Rule{{ID: "legacy", Protocol: "udp", Ports: []flowpolicy.PortRange{{First: 27019, Last: 27019}}, Action: flowpolicy.RelayRequired, RelayID: "VPS-01", Fallback: flowpolicy.Required}}
	raw, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Handle(context.Background(), "profile.set", raw); err != nil {
		t.Fatal(err)
	}
	c.updateGamesGate()
	denied := c.Classify(id, policyTuple("udp", 27019))
	if !denied.Block || denied.GameUDP != nil || denied.Route.RelayID != "" || denied.Policy.RelayID != "" {
		t.Fatalf("legacy rule leaked: %+v", denied)
	}
	next := c.Classify(id, policyTuple("udp", 27020))
	if next.Block || !next.CS2Auto || next.GameRelayID != "" || next.Route.RelayID != "" {
		t.Fatalf("unrelated target lost AUTO: %+v", next)
	}
}
