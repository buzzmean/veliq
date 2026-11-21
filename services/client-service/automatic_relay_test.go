package clientservice

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/buzzmean/neexitlag/core/flowpolicy"
	"github.com/buzzmean/neexitlag/core/optimizer"
	"github.com/buzzmean/neexitlag/core/profiles"
	"github.com/buzzmean/neexitlag/core/routing"
	wp "github.com/buzzmean/neexitlag/platform/windows"
)

type unwantedGameRelay struct{ calls atomic.Int32 }

func (r *unwantedGameRelay) OpenDatagram(context.Context, netip.AddrPort) (routing.Datagram, error) {
	r.calls.Add(1)
	return nil, errors.New("game must not open a relay")
}
func (r *unwantedGameRelay) OpenTCP(context.Context, netip.AddrPort) (net.Conn, error) {
	r.calls.Add(1)
	return nil, errors.New("game must not open a relay")
}
func preferGameRelay(c *Controller) {
	c.Selector = optimizer.New(optimizer.Parameters{MinimumImprovement: 5, MaxAge: time.Minute})
	now := time.Now()
	for i := 0; i < 5; i++ {
		at := now.Add(time.Duration(i-4) * time.Second)
		c.Selector.Observe(optimizer.RouteMeasurement{RouteID: optimizer.Direct, RTT: 150 * time.Millisecond, Stability: 1, Available: true, Samples: 10, ObservedAt: at})
		c.Selector.Observe(optimizer.RouteMeasurement{RouteID: "VPS-01", RTT: time.Millisecond, Stability: 1, Available: true, Samples: 10, ObservedAt: at})
		c.Selector.Select(at)
	}
}

func TestGameAndUnknownLegacyAUTODoNotInheritGlobalRelayOrBackups(t *testing.T) {
	for _, app := range []string{`C:\Steam\steamapps\common\Counter-Strike 2\cs2.exe`, `D:\Steam\steamapps\common\Other\game.exe`, `C:\Apps\unknown.exe`} {
		t.Run(app, func(t *testing.T) {
			p := profiles.Profile{ID: "legacy-game", Name: "Legacy AUTO", Executables: []string{app}, Mode: profiles.Auto, Custom: true}
			c := policyController(t, p)
			preferGameRelay(c)
			if c.Selector.Select(time.Now()).Primary != "VPS-01" {
				t.Fatal("fixture did not actually prefer relay")
			}
			spy := &unwantedGameRelay{}
			c.Engine.SetRelay("VPS-01", spy)
			c.syncPolicies()
			id := wp.ProcessIdentity{PID: 42, CreationTime: 10, Path: app}
			for _, proto := range []string{"udp", "tcp"} {
				d := c.Classify(id, policyTuple(proto, 27025))
				if !d.Route.Direct() || d.Route.Local() || d.Policy.Source != "auto_direct_default" || d.Flow.PinnedPolicy == nil || !d.Flow.PinnedPolicy.Route.Direct() || len(d.Flow.PinnedPolicy.Backups) != 0 {
					t.Fatal("global relay escaped into game", d)
				}
			}
			// Actual socket open with a deliberately stale engine AUTO entry proves
			// that the transport selector cannot undo the classification decision.
			target, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
			if err != nil {
				t.Fatal(err)
			}
			defer target.Close()
			c.Engine.SetPolicy(p.ID, routing.Policy{Auto: true})
			flow := routing.Flow{PID: 42, ProcessPath: app, ApplicationID: p.ID, Source: netip.MustParseAddrPort("127.0.0.1:51001"), Destination: target.LocalAddr().(*net.UDPAddr).AddrPort()}
			conn, err := c.Engine.OpenUDP(context.Background(), flow)
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			if err = conn.Send([]byte("direct-game")); err != nil {
				t.Fatal(err)
			}
			target.SetReadDeadline(time.Now().Add(time.Second))
			buf := make([]byte, 64)
			n, _, err := target.ReadFromUDP(buf)
			if err != nil || string(buf[:n]) != "direct-game" || spy.calls.Load() != 0 {
				t.Fatal("not DIRECT", err, spy.calls.Load())
			}
		})
	}
}

func TestGameDefaultsAndPersistedAUTOOverrideRemainSafe(t *testing.T) {
	c := New(context.Background())
	defer c.Close()
	for _, p := range c.Profiles.List() {
		if (p.ID == "cs2" || p.ID == "steam") && p.Mode != profiles.Direct {
			t.Fatal(p)
		}
	}
	path := filepath.Join(t.TempDir(), "profiles.json")
	if err := c.SetCustomPath(path); err != nil {
		t.Fatal(err)
	}
	for _, p := range c.Profiles.List() {
		if p.ID != "cs2" {
			continue
		}
		p.Mode = profiles.Auto // an old persisted installation, not a fresh default
		raw, _ := json.Marshal(p)
		if _, err := c.Handle(context.Background(), "profile.set", raw); err != nil {
			t.Fatal(err)
		}
	}
	c2 := New(context.Background())
	defer c2.Close()
	if err := c2.SetCustomPath(path); err != nil {
		t.Fatal(err)
	}
	c2.enabled = true
	preferGameRelay(c2)
	d := c2.Classify(wp.ProcessIdentity{PID: 5, CreationTime: 10, Path: `C:\Games\cs2.exe`}, policyTuple("udp", 27025))
	if !d.Route.Direct() || d.Policy.Source != "auto_direct_default" {
		t.Fatal(d)
	}
	for _, r := range c2.profileRoutingAudit().Profiles {
		if r.ID == "cs2" && (r.Origin != "local_override" || r.AutomaticRelayAllowed || r.DefaultRoute != "DIRECT") {
			t.Fatal(r)
		}
	}
}

func TestGenericLearnedRelayCannotBecomeImplicitApplicationRelay(t *testing.T) {
	p := profiles.Profile{ID: "unknown", Name: "unknown", Executables: []string{`C:\Apps\unknown.exe`}, Mode: profiles.Auto, Custom: true}
	c := policyController(t, p)
	now := time.Now()
	c.network.Store(&wp.NetworkContext{Fingerprint: "net", ObservedAt: now})
	key := c.learnKey(p, "net", "tcp", "unknown.example", 443)
	result := flowpolicy.Result{Action: flowpolicy.Relay, RelayID: "VPS-01", Fallback: flowpolicy.FailOpen, Source: "verified_trial"}
	if err := c.AutoLearned.Record(flowpolicy.Learned{Key: key, Result: result, Success: true, Score: 1, Observed: now, Expires: now.Add(time.Minute)}, now); err != nil {
		t.Fatal(err)
	}
	d := c.Classify(wp.ProcessIdentity{PID: 2, CreationTime: 10, Path: p.Executables[0]}, policyTuple("tcp", 443))
	if d.Deferred {
		d = wp.ResolveDeferredDecision(d, "unknown.example", "SNI_FOUND")
	}
	if !d.Route.Direct() || d.Route.Local() || d.Policy.Source != "auto_direct_default" {
		t.Fatal(d)
	}
}

func TestProfileRoutingAuditShowsBuiltinVersusOverrideAndIsBounded(t *testing.T) {
	c := New(context.Background())
	defer c.Close()
	view, err := c.Handle(context.Background(), "profiles.routing", nil)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, r := range view.(profileRoutingAudit).Profiles {
		if r.ID == "cs2" {
			found = true
			if r.Origin != "built_in" || r.DefaultRoute != "DIRECT" {
				t.Fatal(r)
			}
		}
	}
	if !found {
		t.Fatal("missing builtin CS audit")
	}
	for i := 0; i < 75; i++ {
		p := profiles.Profile{ID: fmt.Sprintf("custom-%03d", i), Name: "Custom", Executables: []string{fmt.Sprintf("game-%d.exe", i)}, Mode: profiles.Direct, Custom: true}
		if err := c.Profiles.Upsert(p); err != nil {
			t.Fatal(err)
		}
	}
	a := c.profileRoutingAudit()
	raw, _ := json.Marshal(a)
	if !a.Truncated || len(a.Profiles) != 64 || len(raw) >= 65536 {
		t.Fatal("unbounded IPC audit", len(raw), len(a.Profiles))
	}
}

func TestExplicitRelayAndProtectedPresetsAreNotDisabled(t *testing.T) {
	for _, preset := range []string{"openai", "anthropic", "telegram", "discord"} {
		p := profiles.Profile{ID: "protected", Name: "protected", Executables: []string{`C:\Apps\protected.exe`}, Mode: profiles.Auto, AppPreset: preset, Custom: true}
		c := policyController(t, p)
		d := c.Classify(wp.ProcessIdentity{PID: 2, CreationTime: 10, Path: p.Executables[0]}, policyTuple("udp", 443))
		if d.Route.RelayID != "VPS-01" || !d.BlockOnFailure {
			t.Fatal("protected relaxed", preset, d)
		}
		if _, err := c.Engine.OpenUDP(context.Background(), d.Flow); err == nil {
			t.Fatal("protected DIRECT leak", preset)
		}
	}
	p := profiles.Profile{ID: "explicit-game", Name: "game", Executables: []string{`C:\Games\game.exe`}, Mode: profiles.Manual, RelayID: "VPS-01", Fallback: flowpolicy.Required, Custom: true}
	c := policyController(t, p)
	d := c.Classify(wp.ProcessIdentity{PID: 2, CreationTime: 10, Path: p.Executables[0]}, policyTuple("udp", 27025))
	if d.Route.RelayID != "VPS-01" || !d.BlockOnFailure {
		t.Fatal("explicit choice discarded", d)
	}
	if _, err := c.Engine.OpenUDP(context.Background(), d.Flow); err == nil {
		t.Fatal("explicit fail-closed lost")
	}
	// Explicit narrowly scoped rules are operator opt-in, not global optimizer.
	p.Mode, p.RelayID = profiles.Auto, ""
	p.Rules = []flowpolicy.Rule{{ID: "blocked-endpoint", Protocol: "udp", Ports: []flowpolicy.PortRange{{First: 27025, Last: 27025}}, Action: flowpolicy.RelayRequired, RelayID: "VPS-01", Fallback: flowpolicy.Required}}
	c.Profiles.Upsert(p)
	d = c.Classify(wp.ProcessIdentity{PID: 2, CreationTime: 10, Path: p.Executables[0]}, policyTuple("udp", 27025))
	if d.Route.RelayID != "VPS-01" || !d.BlockOnFailure {
		t.Fatal("explicit rule discarded", d)
	}
}
