package clientservice

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"github.com/buzzmean/veliq/core/profiles"
	wp "github.com/buzzmean/veliq/platform/windows"
	"net/netip"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func policyReadyFixture(t *testing.T, edge bool) (*Controller, *string, *atomic.Bool, *atomic.Int32) {
	c, p, value := silentFixture(t, edge)
	c.customPath = filepath.Join(t.TempDir(), "profiles.json")
	p.Mode = profiles.Auto
	if edge {
		p.AppPreset = "edge-sites"
	}
	c.Profiles.Upsert(p)
	b := &activationCaptureFixture{}
	b.active.Store(true)
	c.Backend = b
	c.enabled = true
	pstate := &c.browser.readiness
	pstate.enforced.Store(true)
	pstate.target = "127.0.0.1:8443"
	pstate.token = strings.Repeat("a", 64)
	pstate.tls = &tls.Config{}
	alive := &atomic.Bool{}
	alive.Store(true)
	pstate.relay = alive.Load
	calls := &atomic.Int32{}
	pstate.check = func(context.Context, string, string, string, *tls.Config) error { calls.Add(1); return nil }
	remove := func(_ string, owned []string) error {
		if *value == "" {
			return nil
		}
		for _, v := range owned {
			if v == *value {
				*value = ""
				return nil
			}
		}
		return errors.New("foreign preserved")
	}
	if edge {
		c.browser.edge.remove = remove
	} else {
		c.browser.chromeRemove = remove
	}
	return c, value, alive, calls
}
func TestActivationBrowserPolicyRequiresCaptureRelayAndBothCONNECTChecks(t *testing.T) {
	for _, edge := range []bool{false, true} {
		t.Run(map[bool]string{false: "chrome", true: "edge"}[edge], func(t *testing.T) {
			c, value, alive, calls := policyReadyFixture(t, edge)
			method := "browser.silent.apply"
			if edge {
				method = "edge.silent.apply"
			}
			apply := func() {
				t.Helper()
				if _, err := c.Handle(context.Background(), method, []byte(`{"profile_id":"browser"}`)); err != nil {
					t.Fatal(err)
				}
			}
			backend := c.Backend.(*activationCaptureFixture)
			backend.active.Store(false)
			apply()
			if *value != "" || calls.Load() != 0 {
				t.Fatal("policy before capture")
			}
			backend.active.Store(true)
			alive.Store(false)
			apply()
			if *value != "" || calls.Load() != 0 {
				t.Fatal("policy before authenticated relay")
			}
			alive.Store(true)
			c.browser.readiness.check = func(context.Context, string, string, string, *tls.Config) error {
				calls.Add(1)
				return errors.New("CONNECT_CHECK_TLS_FAILED")
			}
			apply()
			if *value != "" {
				t.Fatal("failed real transport accepted")
			}
			calls.Store(0)
			c.browser.readiness.check = func(context.Context, string, string, string, *tls.Config) error { calls.Add(1); return nil }
			apply()
			if *value == "" || calls.Load() != 2 {
				t.Fatal("both endpoints not checked")
			}
			health := c.browserPolicyHealth()
			if (!edge && !health.ChromeReady) || (edge && !health.EdgeReady) {
				t.Fatal("ready not observed")
			}
			alive.Store(false)
			c.RetrySilentBrowserPolicies()
			if *value != "" {
				t.Fatal("relay loss retained policy")
			}
			alive.Store(true)
			c.RetrySilentBrowserPolicies()
			if *value == "" {
				t.Fatal("recovery not automatic")
			}
			if _, err := c.Handle(context.Background(), "optimize", []byte(`{"enabled":false}`)); err != nil {
				t.Fatal(err)
			}
			if *value != "" {
				t.Fatal("disabled optimization retained PAC")
			}
			c.RetrySilentBrowserPolicies()
			if *value != "" {
				t.Fatal("timer reinstalled disabled PAC")
			}
		})
	}
}
func TestActivationBrowserAutomaticOffAndProfileDIRECTDoNotReapplyPAC(t *testing.T) {
	c, value, _, _ := policyReadyFixture(t, false)
	if _, err := c.Handle(context.Background(), "browser.silent.apply", []byte(`{"profile_id":"browser"}`)); err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(Settings{Automatic: false, Failover: "DIRECT", UpdateChannel: "stable"})
	if _, err := c.Handle(context.Background(), "settings.set", raw); err != nil {
		t.Fatal(err)
	}
	c.RetrySilentBrowserPolicies()
	if *value != "" {
		t.Fatal("automatic-off retained PAC")
	}
	c.settings.Automatic = true
	c.RetrySilentBrowserPolicies()
	if *value == "" {
		t.Fatal("automatic-on did not restore PAC")
	}
	p, _ := func() (profiles.Profile, bool) {
		for _, p := range c.Profiles.List() {
			if p.ID == "browser" {
				return p, true
			}
		}
		return profiles.Profile{}, false
	}()
	p.Mode = profiles.Direct
	c.Profiles.Upsert(p)
	c.RetrySilentBrowserPolicies()
	if *value != "" {
		t.Fatal("DIRECT profile retained browser policy")
	}
}
func TestActivationSnapshotUsesRelayAndCaptureAndNeverInfersConnectedFromIPC(t *testing.T) {
	c, _, alive, _ := policyReadyFixture(t, false)
	c.ControlPlaneURL = "https://127.0.0.1:8443"
	if !c.Snapshot().Connected {
		t.Fatal("ready relay hidden")
	}
	alive.Store(false)
	s := c.Snapshot()
	if s.Connected || s.ConnectionReason != "RELAY_NOT_CONNECTED" {
		t.Fatal("relay loss hidden")
	}
}

func TestActivationClosedProxyRemovesPolicyDespiteHealthyRelay(t *testing.T) {
	c, value, _, _ := policyReadyFixture(t, false)
	if _, err := c.Handle(context.Background(), "browser.silent.apply", []byte(`{"profile_id":"browser"}`)); err != nil {
		t.Fatal(err)
	}
	c.browser.server.Close()
	c.RetrySilentBrowserPolicies()
	if *value != "" {
		t.Fatal("closed proxy retained mandatory policy")
	}
}
func TestActivationExpiredProbeLeaseDoesNotTrapOpaqueBrowserTraffic(t *testing.T) {
	c, _, _, _ := policyReadyFixture(t, false)
	if _, err := c.Handle(context.Background(), "browser.silent.apply", []byte(`{"profile_id":"browser"}`)); err != nil {
		t.Fatal(err)
	}
	c.browser.readiness.liveUntil[0].Store(time.Now().Add(-time.Second).UnixNano())
	d := c.Classify(wp.ProcessIdentity{PID: 321, CreationTime: 1, Path: `C:\Apps\chrome.exe`}, wp.Tuple{Protocol: "tcp", Source: netip.MustParseAddrPort("192.0.2.1:12345"), Destination: netip.MustParseAddrPort("93.184.216.34:443")})
	if d.Block || d.Policy.Source != "browser_policy_suspended" || d.Flow.PinnedPolicy == nil || !d.Route.Direct() {
		t.Fatal("stale health trapped browser flow")
	}
}

type captureFirstFailure struct{ activationCaptureFixture }

func (b *captureFirstFailure) Start(ctx context.Context, c wp.Classifier) error {
	if b.starts.Add(1) == 1 {
		return errors.New("fixture capture not ready yet")
	}
	b.active.Store(true)
	return nil
}
func TestActivationStartupRetriesCaptureWithoutCircularPACPrerequisite(t *testing.T) {
	c := New(context.Background())
	defer c.Close()
	c.BrowserOwnerSID = "S-1-test"
	c.browser.readiness.enforced.Store(true)
	p := profiles.Profile{ID: "browser", Name: "Chrome", Mode: profiles.Auto, Custom: true, Executables: []string{`C:\Apps\chrome.exe`}}
	if err := c.Profiles.Upsert(p); err != nil {
		t.Fatal(err)
	}
	b := &captureFirstFailure{}
	c.Backend = b
	started := false
	if err := c.startActivatedCapture(true, &started); err == nil || started || c.Snapshot().ConnectionReason != "CAPTURE_START_FAILED" {
		t.Fatal("first startup failure hidden", err)
	}
	if err := c.startActivatedCapture(true, &started); err != nil || !started || !b.active.Load() || b.starts.Load() != 2 {
		t.Fatal("capture did not retry before PAC", err)
	}
	if c.chromePolicyActive() {
		t.Fatal("backend start published unverified PAC")
	}
	if _, err := c.Handle(context.Background(), "optimize", []byte(`{"enabled":false}`)); err != nil {
		t.Fatal(err)
	}
	started = false
	if err := c.startActivatedCapture(true, &started); err != nil || started || b.active.Load() {
		t.Fatal("explicit off was automatically undone")
	}
}
