package clientservice

import (
	"context"
	"encoding/json"
	"net/netip"
	"path/filepath"
	"testing"

	"github.com/buzzmean/neexitlag/core/flowpolicy"
	"github.com/buzzmean/neexitlag/core/localstrategy"
	"github.com/buzzmean/neexitlag/core/profiles"
	wp "github.com/buzzmean/neexitlag/platform/windows"
)

func TestCS2FragmentIPCIsScopedAndCannotSelectRelay(t *testing.T) {
	for _, strategy := range []string{"udp-fragment-8", "udp-fragment-16", "udp-fragment-24"} {
		t.Run(strategy, func(t *testing.T) {
			const app = `C:\Games\CS2\cs2.exe`
			p := profiles.Profile{ID: "cs2", Name: "Counter-Strike 2", Executables: []string{app}, Mode: profiles.Direct, Fallback: flowpolicy.FailOpen,
				Rules: []flowpolicy.Rule{{ID: "server", Protocol: "udp", CIDRs: []string{"203.0.113.9/32"}, Ports: []flowpolicy.PortRange{{First: 27015, Last: 27015}}, Action: flowpolicy.DirectPlus, Strategy: "fragment", Fallback: flowpolicy.FailOpen}}}
			c := policyController(t, p)
			if err := c.SetCustomPath(filepath.Join(t.TempDir(), "profiles.json")); err != nil {
				t.Fatal(err)
			}
			cfg := localstrategy.Config{Version: 1, Enabled: true, User: []localstrategy.Profile{{ID: "fragment", Version: 1, Application: app, Protocol: "udp", Ports: []uint16{27015}, IPs: []string{"203.0.113.9/32"}, Strategy: strategy, ContinuousUDP: true, Cutoff: 0, Enabled: true}}}
			raw, err := json.Marshal(cfg)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := c.Handle(context.Background(), "local.set", raw); err != nil {
				t.Fatal(err)
			}
			fresh := New(context.Background())
			defer fresh.Close()
			if err := fresh.SetCustomPath(c.customPath); err != nil {
				t.Fatal(err)
			}
			if got := fresh.Local.Config(); len(got.User) != 1 || !got.User[0].ContinuousUDP || got.User[0].Cutoff != 0 || got.User[0].Strategy != strategy {
				t.Fatal("continuous opt-in did not persist", got)
			}
			id := wp.ProcessIdentity{PID: 42, CreationTime: 100, Path: app}
			tuple := wp.Tuple{Protocol: "udp", Source: netip.MustParseAddrPort("192.0.2.1:55000"), Destination: netip.MustParseAddrPort("203.0.113.9:27015")}
			d := c.Classify(id, tuple)
			if !d.Route.Local() || d.Local == nil || d.LocalStrategyID != "fragment" || d.GameUDP != nil || d.ProbeDirect || d.Policy.Fallback != flowpolicy.FailOpen || d.Policy.RelayID != "" || d.Route.RelayID != "" {
				t.Fatal("target escaped local-only decision", d)
			}
			for _, tc := range []struct{ app, protocol, destination string }{
				{app, "udp", "203.0.113.8:27015"},
				{app, "udp", "203.0.113.9:27016"},
				{app, "tcp", "203.0.113.9:27015"},
				{`C:\Other\cs2.exe`, "udp", "203.0.113.9:27015"},
			} {
				other, flow := id, tuple
				other.Path, flow.Protocol, flow.Destination = tc.app, tc.protocol, netip.MustParseAddrPort(tc.destination)
				got := c.Classify(other, flow)
				if !got.Route.Direct() || got.Route.Local() || got.ProbeDirect || got.Policy.RelayID != "" {
					t.Fatal("scope leak", tc, got)
				}
			}
			// Disabling the strategy still cannot authorize a relay fallback.
			cfg.Enabled = false
			raw, _ = json.Marshal(cfg)
			if _, err := c.Handle(context.Background(), "local.set", raw); err != nil {
				t.Fatal(err)
			}
			got := c.Classify(id, tuple)
			if !got.Route.Direct() || got.ProbeDirect || got.Policy.RelayID != "" || got.Policy.Fallback != flowpolicy.FailOpen {
				t.Fatal("disabled strategy authorized relay", got)
			}
		})
	}
}
