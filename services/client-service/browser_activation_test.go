package clientservice

import (
	"context"
	"encoding/json"
	"github.com/buzzmean/neexitlag/core/flowpolicy"
	"github.com/buzzmean/neexitlag/core/profiles"
	wp "github.com/buzzmean/neexitlag/platform/windows"
	"net"
	"testing"
)

func TestChromeActivationRequiresObservedPACBeforePublishingAUTO(t *testing.T) {
	c := New(context.Background())
	defer c.Close()
	c.BrowserOwnerSID = "S-1-test"
	p := profiles.Profile{ID: "chrome", Name: "Chrome", Executables: []string{`C:\Apps\chrome.exe`}, Mode: profiles.Direct, Custom: true}
	c.Profiles.Upsert(p)
	p.Mode = profiles.Auto
	raw, _ := json.Marshal(p)
	if _, err := c.Handle(context.Background(), "profile.set", raw); err == nil {
		t.Fatal("AUTO published without listener/PAC/Chrome owner proof")
	}
	if current, _ := c.Profiles.Match(wp.ProcessIdentity{PID: 10, CreationTime: 1, Path: p.Executables[0]}); current.Mode != profiles.Direct {
		t.Fatal("failed activation modified previous profile", current)
	}
	prepare, _ := json.Marshal(map[string]string{"profile_id": p.ID, "directory": t.TempDir()})
	result, err := c.Handle(context.Background(), "browser.prepare", prepare)
	if err != nil {
		t.Fatal(err)
	}
	if result.(map[string]any)["health_url"] == "" {
		t.Fatal("missing Chrome readiness challenge")
	}
	if c.Snapshot().Optimizing {
		t.Fatal("prepare enabled capture")
	}
	if _, err := c.Handle(context.Background(), "browser.confirm", []byte(`{"profile_id":"chrome","health_url":"guessed"}`)); err == nil {
		t.Fatal("IPC alone certified Chrome PAC")
	}
	if _, err := c.Handle(context.Background(), "profile.set", raw); err == nil {
		t.Fatal("bound listener alone certified Chrome AUTO")
	}
}

func TestChromeDNSBootstrapNeverUsesRelayOrDeferredCapture(t *testing.T) {
	c := New(context.Background())
	defer c.Close()
	p := profiles.Profile{ID: "chrome", Name: "Chrome", Executables: []string{`C:\Apps\chrome.exe`}, Mode: profiles.Auto}
	c.Profiles.Upsert(p)
	c.enabled = true
	c.settings.Automatic = true
	id := wp.ProcessIdentity{PID: 10, CreationTime: 1, Path: p.Executables[0]}
	for _, proto := range []string{"udp", "tcp"} {
		tuple := policyTuple(proto, 53)
		d := c.Classify(id, tuple)
		if !d.Route.Direct() || d.Block || d.Deferred || d.ProbeDirect || d.Policy.Source != "browser_dns" {
			t.Fatal("DNS bootstrap hijacked", proto, d)
		}
	}
	// No port-443 bypass, including ECH and QUIC.
	for _, proto := range []string{"udp", "tcp"} {
		d := c.Classify(id, policyTuple(proto, 443))
		if proto == "tcp" {
			d = wp.ResolveDeferredDecision(d, "public-name.example", "ECH_OUTER_SNI_ONLY")
		}
		if d.Block || d.Route.RelayID != "VPS-01" || !d.BlockOnFailure || d.Policy.Action != flowpolicy.RelayRequired {
			t.Fatal("opaque flow blocked before authenticated open or leaked", proto, d)
		}
	}
}

func TestChromePrepareBindFailurePreservesPreviousRouting(t *testing.T) {
	c := New(context.Background())
	defer c.Close()
	c.BrowserOwnerSID = "S-1-test"
	p := profiles.Profile{ID: "chrome", Name: "Chrome", Executables: []string{`C:\Apps\chrome.exe`}, Mode: profiles.Direct, Custom: true}
	c.Profiles.Upsert(p)
	occupied, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer occupied.Close()
	c.browser.address = occupied.Addr().String()
	raw, _ := json.Marshal(map[string]string{"profile_id": p.ID, "directory": t.TempDir()})
	if _, err := c.Handle(context.Background(), "browser.prepare", raw); err == nil {
		t.Fatal("bound port incorrectly reported ready")
	}
	current, _ := c.Profiles.Match(wp.ProcessIdentity{PID: 10, CreationTime: 1, Path: p.Executables[0]})
	if c.enabled || c.browser.server != nil || current.Mode != profiles.Direct {
		t.Fatal("failed prepare mutated routing/capture")
	}
	view, statusErr := c.Handle(context.Background(), "browser.status", nil)
	if statusErr != nil || view.(browserStatusView).LastError != "browser.prepare: CHROME_LISTENER_BIND_FAILED" {
		t.Fatal("listener failure was not diagnosed safely", view, statusErr)
	}
}

func TestOptimizeCannotArmLegacyChromeAUTOWithoutPAC(t *testing.T) {
	c := New(context.Background())
	defer c.Close()
	c.Demo = true
	c.BrowserOwnerSID = "S-1-test"
	c.Profiles.Upsert(profiles.Profile{ID: "chrome", Name: "Chrome", Executables: []string{`C:\Apps\chrome.exe`}, Mode: profiles.Auto})
	if _, err := c.Handle(context.Background(), "optimize", []byte(`{"enabled":true}`)); err == nil {
		t.Fatal("Optimize armed native Chrome without PAC activation")
	}
	if c.enabled {
		t.Fatal("failed readiness changed global capture state")
	}
}

func TestChromeRecoveryKeepsRulesWithoutOpaqueDIRECTBlock(t *testing.T) {
	p := profiles.Profile{ID: "chrome", Name: "Chrome", Executables: []string{`C:\Apps\chrome.exe`}, Mode: profiles.Direct, Fallback: flowpolicy.Required, BrowserRecoveryRules: []flowpolicy.Rule{{ID: "protected", Domains: []string{"private.example"}, Action: flowpolicy.RelayRequired, RelayID: "VPS-01"}}}
	c := New(context.Background())
	defer c.Close()
	c.Profiles.Upsert(p)
	c.enabled = true
	id := wp.ProcessIdentity{PID: 10, CreationTime: 1, Path: p.Executables[0]}
	d := c.Classify(id, policyTuple("tcp", 443))
	if d.Deferred || d.Block || !d.Route.Direct() {
		t.Fatal("guarded recovery reintroduced opaque BLOCK", d)
	}
	p.Mode = profiles.Auto
	prepareAuto(&p)
	if len(p.Rules) != 1 || len(p.BrowserRecoveryRules) != 0 || p.Rules[0].Domains[0] != "private.example" {
		t.Fatal("AUTO lost preserved security rules", p)
	}
	c.Profiles.Upsert(p)
	d = wp.ResolveDeferredDecision(c.Classify(id, policyTuple("tcp", 443)), "private.example", "SNI_FOUND")
	if d.Block || d.Route.RelayID != "VPS-01" || !d.BlockOnFailure {
		t.Fatal("restored explicit rule lost fail-closed semantics", d)
	}
}
