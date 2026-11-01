package clientservice

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/buzzmean/neexitlag/core/browserproxy"
	"github.com/buzzmean/neexitlag/core/flowpolicy"
	"github.com/buzzmean/neexitlag/core/profiles"
	wp "github.com/buzzmean/neexitlag/platform/windows"
)

func edgeTestProfile() profiles.Profile {
	return profiles.Profile{ID: "edge", Name: "Edge", Executables: []string{`C:\Edge\msedge.exe`}, Mode: profiles.Direct, Custom: true}
}
func edgeCall(c *Controller, method string, payload any) (any, error) {
	raw, _ := json.Marshal(payload)
	return c.Handle(context.Background(), method, raw)
}

func TestEdgeConfirmedProfilePublicationPreservesPAC(t *testing.T) {
	for _, test := range []struct {
		name     string
		change   func(*profiles.Profile)
		preserve bool
		reject   bool
	}{
		{name: "publish", preserve: true},
		{name: "rename", preserve: true, change: func(p *profiles.Profile) { p.Name = "Renamed Edge" }},
		{name: "changed_guard", change: func(p *profiles.Profile) {
			p.Rules = []flowpolicy.Rule{{ID: "new-protected", Domains: []string{"private.example"}, Action: flowpolicy.RelayRequired, RelayID: "VPS-01"}}
		}},
		{name: "changed_executable", change: func(p *profiles.Profile) { p.Executables = []string{`C:\OtherEdge\msedge.exe`} }},
		{name: "direct", change: func(p *profiles.Profile) { p.Mode = profiles.Direct }},
		{name: "availability_contract"},
		{name: "rejected_update", reject: true, change: func(p *profiles.Profile) { p.Mode = "INVALID" }},
	} {
		t.Run(test.name, func(t *testing.T) {
			c := New(context.Background())
			defer c.Close()
			c.Demo = true
			c.BrowserOwnerSID = "isolated-owner"
			if runtime.GOOS == "windows" {
				self, err := wp.NewDiscovery().Lookup(uint32(os.Getpid()))
				if err != nil {
					t.Fatal(err)
				}
				c.BrowserOwnerSID, err = wp.ProcessUserSID(self)
				if err != nil {
					t.Fatal(err)
				}
			}
			if err := c.SetCustomPath(filepath.Join(t.TempDir(), "profiles.json")); err != nil {
				t.Fatal(err)
			}
			p := edgeTestProfile()
			c.Profiles.Upsert(p)
			server, err := browserproxy.Listen(c.ctx, browserproxy.Config{
				Authorize: func(context.Context, netip.AddrPort, netip.AddrPort) (browserproxy.Owner, error) {
					return browserproxy.Owner{PID: 77, Birth: 1, Exe: p.Executables[0], Profile: p.ID}, nil
				},
				Plan: func(context.Context, browserproxy.Request) (browserproxy.Plan, error) {
					return browserproxy.Plan{}, errors.New("health must not plan an origin")
				},
				Open: func(context.Context, browserproxy.Request, browserproxy.Plan) (net.Conn, error) {
					return nil, errors.New("health must not open an origin")
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			e := c.edgeLocked()
			e.server = server
			e.saved.Address = server.Address()
			policy := ""
			e.write = func(_ string, _ []string, next string) error { policy = next; return nil }
			e.active = func(sid, pac string) bool { return sid == c.BrowserOwnerSID && policy == edgePolicyValue(pac) }
			edgeRemovals, chromeRemovals := 0, 0
			e.remove = func(_ string, owned []string) error {
				if policy == "" {
					return nil
				}
				for _, value := range owned {
					if policy == value {
						policy = ""
						edgeRemovals++
						return nil
					}
				}
				return errors.New("foreign policy preserved")
			}
			c.browser.silent.Owned = []string{"isolated-chrome-policy"}
			c.browser.chromeRemove = func(string, []string) error { chromeRemovals++; return nil }
			prepare := func() string {
				r, err := edgeCall(c, "edge.prepare", map[string]string{"profile_id": p.ID, "directory": t.TempDir(), "recovery_address": "127.0.0.1:17777"})
				if err != nil {
					t.Fatal(err)
				}
				return r.(map[string]any)["health_url"].(string)
			}
			prepare()
			if _, err := edgeCall(c, "edge.policy", map[string]string{"profile_id": p.ID, "operation": "guard"}); err != nil {
				t.Fatal(err)
			}
			health := prepare()
			if _, err := edgeCall(c, "edge.policy", map[string]string{"profile_id": p.ID, "operation": "install"}); err != nil {
				t.Fatal(err)
			}
			conn, err := net.Dial("tcp", server.Address())
			if err != nil {
				t.Fatal(err)
			}
			fmt.Fprintf(conn, "GET %s HTTP/1.1\r\nHost: neexitlag-health.invalid\r\n\r\n", health)
			response, err := http.ReadResponse(bufio.NewReader(conn), nil)
			if err != nil {
				conn.Close()
				t.Fatal(err)
			}
			io.Copy(io.Discard, response.Body)
			response.Body.Close()
			conn.Close()
			if response.StatusCode != 200 {
				t.Fatal("health request rejected", response.StatusCode)
			}
			if _, err := edgeCall(c, "edge.confirm", map[string]string{"profile_id": p.ID, "health_url": health}); err != nil {
				t.Fatal(err)
			}
			if !server.Confirmed(p.ID) || !e.policyActive(c.BrowserOwnerSID) {
				t.Fatal("confirm did not establish actual health/policy readiness")
			}
			p.Mode, p.AppPreset = profiles.Auto, "edge-sites"
			if test.name == "availability_contract" {
				c.browser.readiness.enforced.Store(true)
			}
			if test.change != nil {
				test.change(&p)
			}
			_, err = edgeCall(c, "profile.set", p)
			if (err != nil) != test.reject {
				t.Fatal("unexpected profile update result", err)
			}
			if !test.preserve {
				if e.policyActive(c.BrowserOwnerSID) || edgeRemovals != 1 {
					t.Fatal("changed/rejected scope retained policy", edgeRemovals)
				}
				if !test.reject && p.Mode == profiles.Auto && c.requireEdgeActivation() == nil {
					t.Fatal("scope change reused activation proof")
				}
				return
			}
			if _, err := edgeCall(c, "optimize", map[string]bool{"enabled": true}); err != nil {
				t.Fatalf("after profile.set: confirmed=%t policy_active=%t edge_removals=%d chrome_removals=%d: %v", server.Confirmed(p.ID), e.policyActive(c.BrowserOwnerSID), edgeRemovals, chromeRemovals, err)
			}
			if edgeRemovals != 0 || chromeRemovals != 0 {
				t.Fatal("Edge activation removed a browser policy")
			}
			// A no-op update must not revoke the proof either, but intentional disable
			// must still remove the PAC even after successful profile publication.
			if _, err := edgeCall(c, "profile.set", p); err != nil {
				t.Fatal(err)
			}
			if !e.policyActive(c.BrowserOwnerSID) || edgeRemovals != 0 || chromeRemovals != 0 {
				t.Fatal("no-op Edge update removed a browser policy")
			}
			if _, err := edgeCall(c, "optimize", map[string]bool{"enabled": false}); err != nil {
				t.Fatal(err)
			}
			if e.policyActive(c.BrowserOwnerSID) || edgeRemovals != 1 {
				t.Fatal("disabled optimization retained Edge PAC")
			}
		})
	}
}

func TestEdgePrepareIsolationAndNoSyntheticReadiness(t *testing.T) {
	c := New(context.Background())
	defer c.Close()
	c.BrowserOwnerSID = "owner"
	p := edgeTestProfile()
	c.Profiles.Upsert(p)
	chrome := profiles.Profile{ID: "chrome", Name: "Chrome", Mode: profiles.Direct, Executables: []string{`C:\Chrome\chrome.exe`}, Custom: true}
	c.Profiles.Upsert(chrome)
	old, err := edgeCall(c, "browser.prepare", map[string]string{"profile_id": chrome.ID, "directory": t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	chromePAC, chromeAddress, chromeRecovery := c.browser.expectedPAC, c.browser.address, c.browser.recoveryAddress
	result, err := edgeCall(c, "edge.prepare", map[string]string{"profile_id": p.ID, "directory": t.TempDir(), "recovery_address": "127.0.0.1:17777"})
	if err != nil {
		t.Fatal(err)
	}
	_ = old
	edge := result.(map[string]any)
	if edge["address"] == chromeAddress || edge["health_url"] == "" {
		t.Fatal("missing independent Edge endpoint/challenge")
	}
	if c.browser.expectedPAC != chromePAC || c.browser.address != chromeAddress || c.browser.recoveryAddress != chromeRecovery || c.enabled {
		t.Fatal("Edge changed Chrome/Optimize")
	}
	if _, err = edgeCall(c, "edge.confirm", map[string]string{"profile_id": p.ID, "health_url": edge["health_url"].(string)}); err == nil {
		t.Fatal("listener alone certified Edge")
	}
	p.Mode = profiles.Auto
	p.AppPreset = "edge-sites"
	if _, err = edgeCall(c, "profile.set", p); err == nil {
		t.Fatal("unproved Edge AUTO accepted")
	}
	if _, err = edgeCall(c, "browser.prepare", map[string]string{"profile_id": p.ID, "directory": t.TempDir()}); err == nil {
		t.Fatal("Edge admitted into Chrome lane")
	}
}
func TestEdgeBindFailureDoesNotBreakChrome(t *testing.T) {
	c := New(context.Background())
	defer c.Close()
	c.BrowserOwnerSID = "owner"
	p := edgeTestProfile()
	c.Profiles.Upsert(p)
	occupied, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer occupied.Close()
	c.browser.edge = &edgeRuntime{saved: edgeSaved{Address: occupied.Addr().String()}}
	if _, err = edgeCall(c, "edge.prepare", map[string]string{"profile_id": p.ID, "directory": t.TempDir(), "recovery_address": "127.0.0.1:17777"}); err == nil {
		t.Fatal("bind failure ignored")
	}
	if c.enabled || c.browser.server != nil || c.browser.expectedPAC != "" {
		t.Fatal("failed Edge prepare changed Chrome/capture")
	}
}
func TestEdgePolicyJournalBeforeRegistryWriteAndGuardNoDirectLeak(t *testing.T) {
	c := New(context.Background())
	defer c.Close()
	c.BrowserOwnerSID = "owner"
	if runtime.GOOS == "windows" {
		self, err := wp.NewDiscovery().Lookup(uint32(os.Getpid()))
		if err != nil {
			t.Fatal(err)
		}
		c.BrowserOwnerSID, err = wp.ProcessUserSID(self)
		if err != nil {
			t.Fatal(err)
		}
	}
	owner := c.BrowserOwnerSID
	dir := t.TempDir()
	if err := c.SetCustomPath(filepath.Join(dir, "profiles.json")); err != nil {
		t.Fatal(err)
	}
	p := edgeTestProfile()
	p.Rules = []flowpolicy.Rule{{ID: "private", Domains: []string{"private.example"}, Action: flowpolicy.RelayRequired, RelayID: "VPS-01"}}
	c.Profiles.Upsert(p)
	e := c.edgeLocked()
	writes := 0
	e.write = func(sid string, owned []string, next string) error {
		writes++
		if sid != owner {
			t.Fatal("wrong owner hive")
		}
		b, err := os.ReadFile(filepath.Join(dir, "edge-transport.json"))
		if err != nil || !strings.Contains(string(b), "owned_policy") {
			t.Fatal("registry written before durable ownership journal")
		}
		if len(owned) > 2 || owned[len(owned)-1] != next {
			t.Fatal("unbounded/incorrect owned values")
		}
		return nil
	}
	if _, err := edgeCall(c, "edge.policy", map[string]string{"profile_id": p.ID, "operation": "guard"}); err != nil {
		t.Fatal(err)
	}
	if writes != 1 || c.browser.server != nil {
		t.Fatal("guard changed Chrome")
	}
	pac := edgeClosedPAC(p)
	raw, _ := base64.StdEncoding.DecodeString(strings.TrimPrefix(pac, "data:application/x-ns-proxy-autoconfig;base64,"))
	for _, term := range []string{"chatgpt.com", "private.example", "youtube.com", "fail-closed.neexitlag.invalid", "return strict?"} {
		if !strings.Contains(string(raw), term) {
			t.Fatal("guard missing", term)
		}
	}
	if _, err := edgeCall(c, "edge.policy", map[string]string{"profile_id": p.ID, "operation": "remove"}); err == nil {
		t.Fatal("protected guard could be removed")
	}
}
func TestLegacyEdgeProfilesPreserveRelayRequiredUntilExplicitSitesOptIn(t *testing.T) {
	c := New(context.Background())
	defer c.Close()
	p := edgeTestProfile()
	p.Mode = profiles.Auto
	c.Profiles.Upsert(p)
	c.enabled = true
	id := wp.ProcessIdentity{PID: 11, CreationTime: 1, Path: p.Executables[0]}
	d := c.Classify(id, policyTuple("tcp", 443))
	if d.Route.RelayID != "VPS-01" || !d.BlockOnFailure || browserAuto(p) {
		t.Fatal("legacy Edge semantics changed", d)
	}
	p.AppPreset = "edge-sites"
	c.Profiles.Upsert(p)
	d = c.Classify(id, policyTuple("tcp", 53))
	if !d.Route.Direct() || d.Deferred || d.Policy.Source != "browser_dns" {
		t.Fatal("Edge DNS hijacked", d)
	}
	d = wp.ResolveDeferredDecision(c.Classify(id, policyTuple("tcp", 443)), "chatgpt.com", "SNI_FOUND")
	if d.Route.RelayID != "VPS-01" || !d.BlockOnFailure {
		t.Fatal("protected Edge leak", d)
	}
	d = wp.ResolveDeferredDecision(c.Classify(id, policyTuple("tcp", 443)), "ordinary.example", "SNI_FOUND")
	if !d.Route.Direct() || d.Block {
		t.Fatal("ordinary Edge not DIRECT", d)
	}
}
func TestEdgeGuardPublishedAlongsideUnchangedChrome(t *testing.T) {
	c := New(context.Background())
	defer c.Close()
	dir := t.TempDir()
	if err := c.SetCustomPath(filepath.Join(dir, "profiles.json")); err != nil {
		t.Fatal(err)
	}
	edge := edgeTestProfile()
	chrome := profiles.Profile{ID: "chrome", Name: "Chrome", Mode: profiles.Direct, Executables: []string{`C:\Chrome\chrome.exe`}}
	c.Profiles.Upsert(edge)
	c.Profiles.Upsert(chrome)
	if err := c.publishBrowserGuard(false); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(c.browserGuardFile())
	var g browserproxy.RecoveryGuard
	if json.Unmarshal(raw, &g) != nil || len(g.Profiles) != 2 || g.Profiles[edge.ID].Executables[0] != edge.Executables[0] || g.Profiles[chrome.ID].Executables[0] != chrome.Executables[0] {
		t.Fatal("guard identities crossed")
	}
}
func TestEdgeRestoreFailureCannotPreventChromeRestore(t *testing.T) {
	c := New(context.Background())
	defer c.Close()
	dir := t.TempDir()
	if err := c.SetCustomPath(filepath.Join(dir, "profiles.json")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "edge-transport.json"), []byte(`{"address":"8.8.8.8:443"}`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := c.RestoreBrowserTransport(); err != nil {
		t.Fatal("Edge blocked independent Chrome restore", err)
	}
	if c.browser.edge.lastError == "" || c.browser.edge.server != nil {
		t.Fatal("invalid Edge state reported healthy")
	}
}

func TestEdgeGuardOnlyJournalSurvivesRestartBeforePrepare(t *testing.T) {
	c := New(context.Background())
	defer c.Close()
	dir := t.TempDir()
	if err := c.SetCustomPath(filepath.Join(dir, "profiles.json")); err != nil {
		t.Fatal(err)
	}
	c.browser.edge = &edgeRuntime{saved: edgeSaved{Owned: []string{edgePolicyValue(edgeClosedPAC(edgeTestProfile()))}}}
	if err := c.saveEdge(c.browser.edge); err != nil {
		t.Fatal(err)
	}
	c.browser.edge = nil
	c.restoreEdgeTransport()
	if c.browser.edge == nil || c.browser.edge.lastError != "" || c.browser.edge.server != nil || len(c.browser.edge.saved.Owned) != 1 {
		t.Fatal("guard-only ownership lost", c.browser.edge)
	}
}

func TestEdgeProfileCannotBeDeletedBeforeProtectedGuard(t *testing.T) {
	c := New(context.Background())
	defer c.Close()
	c.BrowserOwnerSID = "owner"
	p := edgeTestProfile()
	p.AppPreset = "edge-sites"
	p.Mode = profiles.Auto
	c.localProfiles[p.ID] = p
	c.Profiles.Upsert(p)
	c.browser.edge = &edgeRuntime{write: func(string, []string, string) error { return errors.New("foreign Edge policy") }}
	if _, err := edgeCall(c, "profile.delete", map[string]string{"id": p.ID}); err == nil {
		t.Fatal("profile removed despite failed protected guard")
	}
	if _, ok := c.localProfiles[p.ID]; !ok {
		t.Fatal("failed guard lost profile")
	}
}

func TestEdgeIPCFailureAppearsInStatusWithoutSecrets(t *testing.T) {
	c := New(context.Background())
	defer c.Close()
	c.BrowserOwnerSID = "owner"
	c.Profiles.Upsert(edgeTestProfile())
	c.browser.edge = &edgeRuntime{write: func(string, []string, string) error { return os.ErrPermission }}
	if _, err := edgeCall(c, "edge.policy", map[string]string{"profile_id": "edge", "operation": "guard"}); err == nil || !strings.Contains(err.Error(), "EDGE_POLICY_ACCESS_DENIED") {
		t.Fatal("missing typed policy error", err)
	}
	result, err := edgeCall(c, "edge.status", nil)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(result)
	if !strings.Contains(string(raw), `edge.policy: EDGE_POLICY_ACCESS_DENIED`) {
		t.Fatal("last_error missing")
	}
	if _, err := edgeCall(c, "edge.failure", map[string]string{"profile_id": "edge", "phase": "edge.recovery", "code": "EDGE_RECOVERY_FAILED"}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(c.browser.edge.lastError, "edge.recovery") {
		t.Fatal("GUI phase not retained")
	}
}

func TestEdgeInstallRequiresListenerAndProfileBeforeAnyRegistryWrite(t *testing.T) {
	c := New(context.Background())
	defer c.Close()
	c.BrowserOwnerSID = "owner"
	c.Profiles.Upsert(edgeTestProfile())
	writes := 0
	c.browser.edge = &edgeRuntime{write: func(string, []string, string) error { writes++; return nil }}
	if _, err := edgeCall(c, "edge.policy", map[string]string{"profile_id": "edge", "operation": "install"}); err == nil {
		t.Fatal("unprepared dead proxy installed")
	}
	if writes != 0 {
		t.Fatal("registry touched before preparation")
	}
	result, _ := edgeCall(c, "edge.status", nil)
	raw, _ := json.Marshal(result)
	if !strings.Contains(string(raw), "EDGE_PREPARE_REQUIRED") {
		t.Fatal("readiness error missing", string(raw))
	}
}
func TestEdgeProfilelessRollbackPreservesProtectedDomainsAndForeignPolicy(t *testing.T) {
	c := New(context.Background())
	defer c.Close()
	c.BrowserOwnerSID = "owner"
	p := edgeTestProfile()
	p.Rules = []flowpolicy.Rule{{ID: "custom", Domains: []string{"protected.example"}, Action: flowpolicy.RelayRequired, RelayID: "VPS-01"}}
	guard := edgeClosedPAC(p)
	e := c.edgeLocked()
	e.saved.GuardPAC = guard
	writes := 0
	e.write = func(_ string, owned []string, next string) error {
		writes++
		if next != edgePolicyValue(guard) {
			t.Fatal("custom protection lost")
		}
		return nil
	}
	if _, err := edgeCall(c, "edge.policy", map[string]string{"operation": "guard"}); err != nil {
		t.Fatal(err)
	}
	if writes != 1 || e.server != nil {
		t.Fatal("rollback depended on running listener/profile")
	}
	e.write = func(string, []string, string) error { return errors.New("foreign Edge proxy policy") }
	if _, err := edgeCall(c, "edge.policy", map[string]string{"operation": "guard"}); err == nil || !strings.Contains(err.Error(), "EDGE_POLICY_MANAGED") {
		t.Fatal("foreign policy overwritten or hidden", err)
	}
}
func TestEdgePendingAutoNeverPublishesLegacyProcessWideRelayOrDirectLeak(t *testing.T) {
	c := New(context.Background())
	defer c.Close()
	c.enabled = true
	p := edgeTestProfile()
	p.Mode = profiles.Auto
	p.AppPreset = "edge-sites-pending"
	c.Profiles.Upsert(p)
	d := c.Classify(wp.ProcessIdentity{PID: 11, CreationTime: 1, Path: p.Executables[0]}, policyTuple("tcp", 443))
	if !d.Block || d.Policy.Source != "edge_activation_pending" {
		t.Fatal("unverified AUTO routed traffic", d)
	}
	d = c.Classify(wp.ProcessIdentity{PID: 11, CreationTime: 1, Path: p.Executables[0]}, policyTuple("udp", 53))
	if d.Block || !d.Route.Direct() {
		t.Fatal("system DNS altered", d)
	}
}

func TestFailedEdgePolicyWriteDoesNotLosePreviousOwnership(t *testing.T) {
	c := New(context.Background())
	defer c.Close()
	c.BrowserOwnerSID = "owner"
	c.Profiles.Upsert(edgeTestProfile())
	e := c.edgeLocked()
	old := edgePolicyValue("data:old-owned")
	e.saved.Owned = []string{old}
	e.write = func(string, []string, string) error { return os.ErrPermission }
	edgeCall(c, "edge.policy", map[string]string{"profile_id": "edge", "operation": "guard"})
	e.write = func(_ string, owned []string, _ string) error {
		for _, value := range owned {
			if value == old {
				return nil
			}
		}
		return errors.New("ownership lost")
	}
	if _, err := edgeCall(c, "edge.policy", map[string]string{"profile_id": "edge", "operation": "guard"}); err != nil {
		t.Fatal(err)
	}
}

func TestEdgePendingAutoCreationViaIPCRetainsExplicitPendingMarker(t *testing.T) {
	c := New(context.Background())
	defer c.Close()
	c.BrowserOwnerSID = "owner"
	p := edgeTestProfile()
	p.Mode = profiles.Auto
	p.AppPreset = "edge-sites-pending"
	if _, err := edgeCall(c, "profile.set", p); err != nil {
		t.Fatal("new pending AUTO cannot be persisted", err)
	}
	for _, saved := range c.Profiles.List() {
		if saved.ID == p.ID && saved.AppPreset == p.AppPreset && saved.Mode == profiles.Auto {
			return
		}
	}
	t.Fatal("AUTO marker rewritten into legacy Edge preset")
}

func TestLegacyEdgeRollbackWithoutProfilePreservesCustomProtectedDomains(t *testing.T) {
	args, err := browserproxy.ChromeArgumentsWithRecovery("127.0.0.1:17776", "user-dir", []string{"private.example"}, false, "127.0.0.1:17777")
	if err != nil {
		t.Fatal(err)
	}
	legacy := edgeSaved{ExpectedPAC: strings.TrimPrefix(args[1], "--proxy-pac-url=")}
	guard := edgeLegacyGuard(legacy)
	raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(guard, "data:application/x-ns-proxy-autoconfig;base64,"))
	if err != nil || !strings.Contains(string(raw), "private.example") {
		t.Fatal("legacy custom protection lost", err)
	}
	strict := edgeLegacyGuard(edgeSaved{Owned: []string{"invalid owned state"}})
	raw, _ = base64.StdEncoding.DecodeString(strings.TrimPrefix(strict, "data:application/x-ns-proxy-autoconfig;base64,"))
	if !strings.Contains(string(raw), "var strict=true") {
		t.Fatal("corrupt legacy state granted ordinary DIRECT")
	}
}

func TestEdgeGuardPublicationFailureBeforeListenerStillAppearsInStatus(t *testing.T) {
	c := New(context.Background())
	defer c.Close()
	c.BrowserOwnerSID = "owner"
	c.Profiles.Upsert(edgeTestProfile())
	file := filepath.Join(t.TempDir(), "not-a-directory")
	if err := os.WriteFile(file, []byte("not secret"), 0600); err != nil {
		t.Fatal(err)
	}
	c.customPath = filepath.Join(file, "profiles.json")
	if _, err := edgeCall(c, "edge.prepare", map[string]string{"profile_id": "edge", "directory": t.TempDir(), "recovery_address": "127.0.0.1:17777"}); err == nil {
		t.Fatal("guard write error hidden")
	}
	status, err := edgeCall(c, "edge.status", nil)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(status)
	if !strings.Contains(string(raw), "edge.prepare: EDGE_GUARD_STATE_WRITE_FAILED") || strings.Contains(string(raw), file) {
		t.Fatal("missing safe pre-listener error", string(raw))
	}
}

func TestEdgeCapabilityVersionDoesNotCertifyListenerOrPACReadiness(t *testing.T) {
	c := New(context.Background())
	defer c.Close()
	result, err := edgeCall(c, "edge.status", nil)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(result)
	var status struct {
		Version   int      `json:"activation_version"`
		Listening bool     `json:"listening"`
		Ready     bool     `json:"policy_ready"`
		Profiles  []string `json:"ready_profiles"`
	}
	if json.Unmarshal(raw, &status) != nil || status.Version != 3 || status.Listening || status.Ready || len(status.Profiles) != 0 {
		t.Fatal("capability advertised as synthetic readiness", string(raw))
	}
}

// Exercise the GUI order that the native fixture originally omitted: prepare,
// guard (invalidates challenge), prepare afresh, install, real owner GET, confirm.
func TestEdgeGuardRequiresFreshNonceAndNoBrowserCannotConfirm(t *testing.T) {
	c := New(context.Background())
	defer c.Close()
	c.BrowserOwnerSID = "owner"
	p := edgeTestProfile()
	c.Profiles.Upsert(p)
	server, err := browserproxy.Listen(context.Background(), browserproxy.Config{
		Authorize: func(context.Context, netip.AddrPort, netip.AddrPort) (browserproxy.Owner, error) {
			return browserproxy.Owner{Profile: p.ID}, nil
		},
		Plan: func(context.Context, browserproxy.Request) (browserproxy.Plan, error) {
			t.Error("health must not plan an origin")
			return browserproxy.Plan{}, errors.New("unexpected")
		},
		Open: func(context.Context, browserproxy.Request, browserproxy.Plan) (net.Conn, error) {
			t.Error("health must not open origin")
			return nil, errors.New("unexpected")
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	e := c.edgeLocked()
	e.server = server
	e.saved.Address = server.Address()
	e.write = func(string, []string, string) error { return nil }
	e.active = func(string, string) bool { return true }
	guardWrites := 0
	e.write = func(_ string, _ []string, next string) error {
		if next == edgePolicyValue(edgeClosedPAC(p)) {
			guardWrites++
		}
		return nil
	}
	prepare := func() string {
		r, err := edgeCall(c, "edge.prepare", map[string]string{"profile_id": p.ID, "directory": t.TempDir(), "recovery_address": "127.0.0.1:17777"})
		if err != nil {
			t.Fatal(err)
		}
		return r.(map[string]any)["health_url"].(string)
	}
	old := prepare()
	if _, err := edgeCall(c, "edge.policy", map[string]string{"profile_id": p.ID, "operation": "guard"}); err != nil {
		t.Fatal(err)
	}
	if got := server.ReadinessState(p.ID, old); got != "NONCE_INVALIDATED" {
		t.Fatal(got)
	}
	fresh := prepare()
	if fresh == old {
		t.Fatal("challenge reused")
	}
	if _, err := edgeCall(c, "edge.policy", map[string]string{"profile_id": p.ID, "operation": "install"}); err != nil {
		t.Fatal(err)
	}
	if got := server.ReadinessState(p.ID, fresh); got != "WAITING_FOR_BROWSER_REQUEST" {
		t.Fatal(got)
	}
	if _, err := edgeCall(c, "edge.confirm", map[string]string{"profile_id": p.ID, "health_url": fresh}); err == nil {
		t.Fatal("no browser contacted proxy, but ready")
	}
	if guardWrites != 2 || server.Confirmed(p.ID) {
		t.Fatal("missing browser did not roll policy back")
	}
	fresh = prepare()
	if _, err := edgeCall(c, "edge.policy", map[string]string{"profile_id": p.ID, "operation": "install"}); err != nil {
		t.Fatal(err)
	}
	conn, err := net.Dial("tcp", server.Address())
	if err != nil {
		t.Fatal(err)
	}
	fmt.Fprintf(conn, "GET %s HTTP/1.1\r\nHost: neexitlag-health.invalid\r\n\r\n", fresh)
	response, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, response.Body)
	response.Body.Close()
	conn.Close()
	if response.StatusCode != 200 {
		t.Fatal(response.StatusCode)
	}
	if _, err := edgeCall(c, "edge.confirm", map[string]string{"profile_id": p.ID, "health_url": fresh}); err != nil {
		t.Fatal(err)
	}
}
