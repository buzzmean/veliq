package clientservice

import (
	"context"
	"encoding/json"
	"github.com/buzzmean/veliq/core/optimizer"
	"github.com/buzzmean/veliq/core/profiles"
	windowsplatform "github.com/buzzmean/veliq/platform/windows"
	"net/netip"
	"path/filepath"
	"testing"
	"time"
)

func TestServiceUnavailableProfilesAndAuthenticatedCommandsBoundary(t *testing.T) {
	c := New(context.Background())
	defer c.Close()
	if c.Snapshot().Connected {
		t.Fatal("false connected state")
	}
	if _, e := c.Handle(context.Background(), "optimize", json.RawMessage(`{"enabled":true}`)); e == nil {
		t.Fatal("missing backend accepted")
	}
	if e := c.SetCustomPath(filepath.Join(t.TempDir(), "profiles.json")); e != nil {
		t.Fatal(e)
	}
	p := profiles.Profile{ID: "custom", Name: "Game", Executables: []string{`C:\Games\Game.exe`}, Mode: profiles.Auto, Custom: true}
	b, _ := json.Marshal(p)
	if _, e := c.Handle(context.Background(), "profile.set", b); e != nil {
		t.Fatal(e)
	}
	c.mu.Lock()
	c.enabled = true
	c.mu.Unlock()
	now := time.Now()
	c.Selector = optimizer.New(optimizer.Parameters{MinimumImprovement: 5, MaxAge: time.Minute})
	for i := 0; i < 5; i++ {
		at := now.Add(time.Duration(i-4) * time.Second)
		c.Selector.Observe(optimizer.RouteMeasurement{RouteID: optimizer.Direct, RTT: 50 * time.Millisecond, Stability: 1, Available: true, Samples: 10, ObservedAt: at})
		c.Selector.Observe(optimizer.RouteMeasurement{RouteID: "FRA", RTT: 20 * time.Millisecond, Stability: 1, Available: true, Samples: 10, ObservedAt: at})
		c.Selector.Select(at)
	}
	tuple := windowsplatform.Tuple{Protocol: "udp", Source: netip.MustParseAddrPort("10.0.0.1:123"), Destination: netip.MustParseAddrPort("1.1.1.1:456")}
	identity := windowsplatform.ProcessIdentity{PID: 42, Path: `C:\Games\Game.exe`, CreationTime: 123}
	decision := c.Classify(identity, tuple)
	if !decision.Route.Direct() || decision.Flow.PID != 42 {
		t.Fatal("real identity classification", decision)
	}
	identity.Path = `C:\Other\Game.exe`
	if !c.Classify(identity, tuple).Route.Direct() {
		t.Fatal("non-selected executable routed")
	}
	c2 := New(context.Background())
	defer c2.Close()
	if e := c2.SetCustomPath(c.customPath); e != nil {
		t.Fatal(e)
	}
	if len(c2.Profiles.List()) != len(profiles.Defaults())+1 {
		t.Fatal("local profile persistence")
	}
}
func TestAcceptanceProfileCleanupPersistsWithoutDeletingDefaults(t *testing.T) {
	c := New(context.Background())
	defer c.Close()
	path := filepath.Join(t.TempDir(), "profiles.json")
	if e := c.SetCustomPath(path); e != nil {
		t.Fatal(e)
	}
	p := profiles.Profile{ID: "e2e-temp", Name: "test client", Executables: []string{`C:\Lab\test-game.exe`}, Mode: profiles.Direct, Custom: true}
	raw, _ := json.Marshal(p)
	if _, e := c.Handle(context.Background(), "profile.set", raw); e != nil {
		t.Fatal(e)
	}
	if _, e := c.Handle(context.Background(), "profile.delete", json.RawMessage(`{"id":"cs2"}`)); e == nil {
		t.Fatal("default profile deleted")
	}
	if _, e := c.Handle(context.Background(), "profile.delete", json.RawMessage(`{"id":"e2e-temp"}`)); e != nil {
		t.Fatal(e)
	}
	c2 := New(context.Background())
	defer c2.Close()
	if e := c2.SetCustomPath(path); e != nil {
		t.Fatal(e)
	}
	if len(c2.Profiles.List()) != len(profiles.Defaults()) {
		t.Fatal("temporary acceptance profile survived cleanup")
	}
}
