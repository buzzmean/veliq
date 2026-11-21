package clientservice

import (
	"context"
	"encoding/json"
	"github.com/buzzmean/neexitlag/core/flowpolicy"
	"github.com/buzzmean/neexitlag/core/localstrategy"
	"github.com/buzzmean/neexitlag/core/optimizer"
	"github.com/buzzmean/neexitlag/core/profiles"
	windowsplatform "github.com/buzzmean/neexitlag/platform/windows"
	"net/netip"
	"path/filepath"
	"testing"
	"time"
)

func TestLocalIPCAndAutoTargetIsolation(t *testing.T) {
	c := New(context.Background())
	defer c.Close()
	c.SetCustomPath(filepath.Join(t.TempDir(), "profiles.json"))
	cfg := localstrategy.Config{Version: 1, Enabled: true, User: []localstrategy.Profile{{ID: "split", Version: 1, Application: "chosen.exe", Protocol: "tcp", Ports: []uint16{443}, IPs: []string{"203.0.113.9"}, Strategy: "tcp-split-1", Cutoff: 1, Enabled: true}}}
	b, _ := json.Marshal(cfg)
	if _, err := c.Handle(context.Background(), "local.set", b); err != nil {
		t.Fatal(err)
	}
	other := New(context.Background())
	defer other.Close()
	if err := other.SetCustomPath(c.customPath); err != nil || !other.Local.Config().Enabled {
		t.Fatal("persist", err)
	}
	c.network.Store(&windowsplatform.NetworkContext{Fingerprint: "net", ObservedAt: time.Now()})
	c.enabled = true
	c.Profiles.Upsert(profiles.Profile{ID: "app", Name: "app", Executables: []string{"chosen.exe"}, Mode: profiles.Auto})
	id := windowsplatform.ProcessIdentity{PID: 42, CreationTime: 100, Path: "chosen.exe"}
	tuple := windowsplatform.Tuple{Protocol: "tcp", Source: netip.MustParseAddrPort("192.0.2.1:1234"), Destination: netip.MustParseAddrPort("203.0.113.9:443")}
	k, err := c.localKey(id.Path, tuple.Destination.String(), "tcp")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	good := optimizer.RouteMeasurement{Available: true, Samples: 10, ObservedAt: now, RTT: 20 * time.Millisecond, Stability: 1}
	bad := good
	bad.Available = false
	c.Learned.Record(k, "DIRECT", bad, false, now)
	c.Learned.Record(k, "split", good, true, now)
	if d := c.Classify(id, tuple); !d.Route.Local() || d.LocalStrategyID != "split" {
		t.Fatal(d)
	}
	c.network.Store(&windowsplatform.NetworkContext{Fingerprint: "changed", ObservedAt: now})
	if c.Classify(id, tuple).Route.Local() {
		t.Fatal("cache crossed network")
	}
	c.network.Store(&windowsplatform.NetworkContext{Fingerprint: "net", ObservedAt: now, Conflicts: []string{"winws"}})
	if !c.Classify(id, tuple).Route.Direct() || c.Classify(id, tuple).Route.Local() {
		t.Fatal("conflict not failopen")
	}
	c.network.Store(&windowsplatform.NetworkContext{Fingerprint: "net", ObservedAt: now})
	cfg.User[0].Cutoff = 2
	b, _ = json.Marshal(cfg)
	c.Handle(context.Background(), "local.set", b)
	if c.Classify(id, tuple).Route.Local() {
		t.Fatal("old evidence survived config change")
	}
}

func TestTargetFailureDoesNotAuthorizeAutomaticRelayForUnknownApplication(t *testing.T) {
	c := New(context.Background())
	defer c.Close()
	c.enabled = true
	c.network.Store(&windowsplatform.NetworkContext{Fingerprint: "net", ObservedAt: time.Now()})
	id := windowsplatform.ProcessIdentity{PID: 42, CreationTime: 100, Path: "chosen.exe"}
	tuple := windowsplatform.Tuple{Protocol: "tcp", Source: netip.MustParseAddrPort("192.0.2.1:1234"), Destination: netip.MustParseAddrPort("203.0.113.9:443")}
	c.Profiles.Upsert(profiles.Profile{ID: "app", Name: "app", Executables: []string{"chosen.exe"}, Mode: profiles.Auto})
	now := time.Now()
	k, _ := c.localKey(id.Path, tuple.Destination.String(), "tcp")
	bad := optimizer.RouteMeasurement{Available: false, Samples: 10, ObservedAt: now}
	relay := optimizer.RouteMeasurement{RouteID: "VPS-01", Available: true, Samples: 10, ObservedAt: now, RTT: 20 * time.Millisecond, Stability: 1}
	c.Learned.Record(k, "DIRECT", bad, false, now)
	c.Learned.Record(k, "RELAY", relay, true, now)
	if got := c.Classify(id, tuple).Route; !got.Direct() || got.Local() {
		t.Fatal("target evidence silently opted unknown application into relay", got)
	}
}

func TestPresetIPCInstallationAndStrictEvidence(t *testing.T) {
	c := New(context.Background())
	defer c.Close()
	if err := c.SetCustomPath(filepath.Join(t.TempDir(), "profiles.json")); err != nil {
		t.Fatal(err)
	}
	raw := json.RawMessage(`{"application":"C:\\Apps\\chrome.exe","preset":"youtube","quic_fallback":true}`)
	v, err := c.Handle(context.Background(), "local.preset.apply", raw)
	if err != nil {
		t.Fatal(err)
	}
	result := v.(map[string]any)
	if result["strategy_id"] == "" || len(c.Local.Config().User) != 7 {
		t.Fatal(result)
	}
	if _, err = c.Handle(context.Background(), "local.preset.apply", raw); err != nil || len(c.Local.Config().User) != 7 {
		t.Fatal("duplicate preset profiles", err)
	}
	other := New(context.Background())
	defer other.Close()
	if err := other.SetCustomPath(c.customPath); err != nil || len(other.Local.Config().User) != 7 {
		t.Fatal("preset persistence", err)
	}
	c.network.Store(&windowsplatform.NetworkContext{Fingerprint: "net", ObservedAt: time.Now()})
	good := optimizer.RouteMeasurement{RouteID: "target", Available: true, Samples: 1, RTT: time.Millisecond, Stability: 1, ObservedAt: time.Now()}
	req, _ := json.Marshal(localRecord{Application: `C:\Apps\chrome.exe`, Destination: "203.0.113.9:443", Protocol: "tcp", Network: "net", Strategy: result["strategy_id"].(string), Success: true, Measurement: good})
	if _, err = c.Handle(context.Background(), "local.record", req); err == nil {
		t.Fatal("chain success accepted without backend transform/identity evidence")
	}
}
func TestPresetAutoDoesNotBorrowVPSPingForUnknownTarget(t *testing.T) {
	c := New(context.Background())
	defer c.Close()
	c.enabled = true
	cfg, _, err := localstrategy.PresetProfiles("youtube", `C:\Apps\chrome.exe`, true)
	if err != nil {
		t.Fatal(err)
	}
	if err = c.Local.Reload(localstrategy.Config{Version: 1, Enabled: true, User: cfg}); err != nil {
		t.Fatal(err)
	}
	c.Profiles.Upsert(profiles.Profile{ID: "app", Name: "Chrome", Executables: []string{`C:\Apps\chrome.exe`}, Mode: profiles.Auto})
	d := c.Classify(windowsplatform.ProcessIdentity{PID: 42, CreationTime: 100, Path: `C:\Apps\chrome.exe`}, windowsplatform.Tuple{Protocol: "tcp", Source: netip.MustParseAddrPort("192.0.2.1:1234"), Destination: netip.MustParseAddrPort("203.0.113.9:443")})
	if !d.Deferred || d.ResolveDomain == nil {
		t.Fatal("Chrome must wait for origin", d)
	}
	d = windowsplatform.ResolveDeferredDecision(d, "ordinary.example", "SNI_FOUND")
	if !d.Route.Direct() || d.Route.Local() {
		t.Fatal("unknown website inherited unrelated ping/strategy", d)
	}
}

func TestTCPProofCannotAuthorizeOpaqueBrowserQUIC(t *testing.T) {
	c := New(context.Background())
	defer c.Close()
	c.enabled = true
	c.network.Store(&windowsplatform.NetworkContext{Fingerprint: "net", ObservedAt: time.Now()})
	app := `C:\Apps\chrome.exe`
	cfg, id, _ := localstrategy.PresetProfiles("youtube", app, true)
	if err := c.Local.Reload(localstrategy.Config{Version: 1, Enabled: true, User: cfg}); err != nil {
		t.Fatal(err)
	}
	c.Profiles.Upsert(profiles.Profile{ID: "chrome", Name: "Chrome", Executables: []string{app}, Mode: profiles.Auto})
	who := windowsplatform.ProcessIdentity{PID: 42, CreationTime: 1, Path: app}
	tuple := windowsplatform.Tuple{Protocol: "udp", Source: netip.MustParseAddrPort("192.0.2.1:50000"), Destination: netip.MustParseAddrPort("203.0.113.9:443")}
	if c.Classify(who, tuple).Route.Local() {
		t.Fatal("unmeasured QUIC got strategy")
	}
	key, _ := c.localKey(app, tuple.Destination.String(), "tcp")
	now := time.Now()
	good := optimizer.RouteMeasurement{RouteID: "target", Available: true, Samples: 1, ObservedAt: now, RTT: time.Millisecond, Stability: 1}
	bad := good
	bad.Available = false
	c.Learned.Record(key, "DIRECT", bad, false, now)
	c.Learned.Record(key, id, good, true, now)
	if got := c.Classify(who, tuple); got.Route.Local() || got.Policy.Action != flowpolicy.RelayRequired || !got.BlockOnFailure {
		t.Fatal("TCP/IP proof must not authorize unknown QUIC inner origin", got)
	}
	tuple.Destination = netip.MustParseAddrPort("203.0.113.9:50000")
	if c.Classify(who, tuple).Route.Local() {
		t.Fatal("voice inherited TCP strategy")
	}
	tuple.Destination = netip.MustParseAddrPort("203.0.113.10:443")
	if c.Classify(who, tuple).Route.Local() {
		t.Fatal("unmeasured destination inherited strategy")
	}
}
