//go:build windows

package clientservice

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/buzzmean/neexitlag/core/browserproxy"
	"github.com/buzzmean/neexitlag/core/flowpolicy"
	"github.com/buzzmean/neexitlag/core/profiles"
	"github.com/buzzmean/neexitlag/core/security"
	"github.com/buzzmean/neexitlag/core/transport"
	"github.com/buzzmean/neexitlag/internal/browserfixture"
	wp "github.com/buzzmean/neexitlag/platform/windows"
	"github.com/buzzmean/neexitlag/services/relay"
	"github.com/buzzmean/neexitlag/tools/labcert"
	"golang.org/x/sys/windows/registry"
)

// Actual Edge + its Microsoft policy + owner/PID/SID + authenticated QUIC relay.
// No production targets/credentials, global proxy, user browser directory, MITM,
// or native DIRECT+ claim. The fixture browser pins only its ephemeral TLS key.
func TestEdgeActualPolicyHTTPSOutageRestart(t *testing.T) {
	if os.Getenv("NEEXITLAG_TEST_EDGE_POLICY") != "1" {
		t.Skip("explicit disposable Windows acceptance only")
	}
	edge := ""
	for _, root := range []string{os.Getenv("ProgramFiles(x86)"), os.Getenv("ProgramFiles")} {
		p := filepath.Join(root, "Microsoft", "Edge", "Application", "msedge.exe")
		if _, err := os.Stat(p); err == nil {
			edge = p
			break
		}
	}
	if edge == "" {
		t.Fatal("real Edge required")
	}
	helperPath := os.Getenv("NEEXITLAG_TEST_BROWSER_RECOVERY")
	if helperPath == "" {
		t.Fatal("real recovery helper required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Second)
	defer cancel()
	fixture, err := browserfixture.New()
	if err != nil {
		t.Fatal(err)
	}
	defer fixture.Close()
	self, err := wp.NewDiscovery().Lookup(uint32(os.Getpid()))
	if err != nil {
		t.Fatal(err)
	}
	sid, err := wp.ProcessUserSID(self)
	if err != nil {
		t.Fatal(err)
	}
	key, _, err := registry.CreateKey(registry.CURRENT_USER, `Software\Policies\Microsoft\Edge`, registry.QUERY_VALUE|registry.SET_VALUE)
	if err != nil {
		t.Fatal(err)
	}
	defer key.Close()
	for _, name := range []string{"ProxySettings", "ProxyMode", "ProxyPacUrl", "ProxyServer", "ProxyBypassList", "ProxyPacMandatory"} {
		if _, _, err := key.GetValue(name, nil); !errors.Is(err, registry.ErrNotExist) {
			t.Fatal("refusing existing Edge policy", name)
		}
	}
	// Observe Chrome without mutating its hive; Edge must not change any of it.
	readChrome := func() string {
		k, err := registry.OpenKey(registry.CURRENT_USER, `Software\Policies\Google\Chrome`, registry.QUERY_VALUE)
		if err != nil {
			return ""
		}
		defer k.Close()
		s, _, _ := k.GetStringValue("ProxySettings")
		return s
	}
	chromeBefore := readChrome()
	defer func() {
		_ = key.DeleteValue("ProxySettings")
		if readChrome() != chromeBefore {
			t.Error("Edge changed Chrome policy")
		}
	}()
	statePath := filepath.Join(t.TempDir(), "profiles.json")
	configure := func() *Controller {
		c := New(ctx)
		c.Demo = true
		c.BrowserOwnerSID = sid
		c.BrowserRecoveryExecutable = helperPath
		c.BrowserResolver = fixture.Resolver
		c.BrowserProbeRoots = fixture.Roots
		if err := c.SetCustomPath(statePath); err != nil {
			t.Fatal(err)
		}
		c.network.Store(&wp.NetworkContext{Fingerprint: "isolated-edge", ObservedAt: time.Now()})
		return c
	}
	c := configure()
	defer func() { c.Close() }()
	p := profiles.Profile{ID: "edge-acceptance", Name: "Edge acceptance", Executables: []string{edge}, Mode: profiles.Direct, Custom: true}
	if _, err = edgeCall(c, "profile.set", p); err != nil {
		t.Fatal(err)
	}
	// Fresh one-shot ticket and ephemeral mTLS identity; relay egress is 127.0.0.2.
	st, ct, err := labcert.Pair()
	if err != nil {
		t.Fatal(err)
	}
	pub, private, _ := ed25519.GenerateKey(rand.Reader)
	relayServer, err := relay.Listen("127.0.0.1:0", relay.Config{TLS: st, TicketVerifier: security.NewTicketVerifier(map[string]ed25519.PublicKey{"test": pub}, "VPS-01"), Allow: []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}, Acceptance: &relay.AcceptanceConfig{LeaseDuration: 2 * time.Minute, OutboundSource: netip.MustParseAddr("127.0.0.2")}})
	if err != nil {
		t.Fatal(err)
	}
	defer relayServer.Close()
	peer := ct.Certificates[0].PrivateKey.(ed25519.PrivateKey).Public().(ed25519.PublicKey)
	pool, err := transport.NewPool(ctx, transport.DefaultPoolConfig(), func(ctx context.Context) (*transport.Client, error) {
		id, _ := security.NewID()
		now := time.Now()
		ticket, err := security.Sign("ticket", "test", private, security.Ticket{ID: id, DeviceID: "edge-fixture", DeviceKey: security.Fingerprint(peer), RelayID: "VPS-01", IssuedAt: now, ExpiresAt: now.Add(time.Minute)})
		if err != nil {
			return nil, err
		}
		return transport.DialWithTicket(ctx, relayServer.Addr().String(), ct, ticket)
	})
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	c.Engine.SetRelay("VPS-01", pool)
	helper := exec.CommandContext(ctx, helperPath, "-test.run=^TestChromeRecoveryChildProcess$", "-test.v=false")
	helper.Env = append(os.Environ(), "NEEXITLAG_TEST_RECOVERY_CHILD=1")
	stdin, err := helper.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := helper.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	var helperErrors bytes.Buffer
	helper.Stderr = &helperErrors
	if err = helper.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { stdin.Close(); _ = helper.Process.Kill(); _ = helper.Wait() }()
	reader := bufio.NewScanner(stdout)
	reader.Buffer(make([]byte, 4096), 65536)
	if !reader.Scan() {
		t.Fatal("recovery greeting", reader.Err())
	}
	var greeting struct {
		Address string `json:"address"`
	}
	if json.Unmarshal(reader.Bytes(), &greeting) != nil || greeting.Address == "" {
		t.Fatal("invalid recovery greeting")
	}
	result, err := edgeCall(c, "edge.prepare", map[string]string{"profile_id": p.ID, "directory": t.TempDir(), "recovery_address": greeting.Address})
	if err != nil {
		t.Fatal(err)
	}
	launch := result.(map[string]any)
	settings := launch["recovery_settings"].(browserproxy.RecoverySettings)
	settings.Executable = edge
	if err = json.NewEncoder(stdin).Encode(settings); err != nil {
		t.Fatal(err)
	}
	if !reader.Scan() || !strings.Contains(reader.Text(), `"ready":true`) {
		t.Fatal("recovery not ready")
	}
	// Reproduce the actual GUI transaction; the previous fixture skipped guard,
	// hiding its invalidation of prepare's nonce.
	if _, err = edgeCall(c, "edge.policy", map[string]string{"profile_id": p.ID, "operation": "guard"}); err != nil {
		t.Fatal(err)
	}
	result, err = edgeCall(c, "edge.prepare", map[string]string{"profile_id": p.ID, "directory": t.TempDir(), "recovery_address": greeting.Address})
	if err != nil {
		t.Fatal(err)
	}
	launch = result.(map[string]any)
	if _, err = edgeCall(c, "edge.policy", map[string]string{"profile_id": p.ID, "operation": "install"}); err != nil {
		t.Fatal(err)
	}
	args := []string{}
	for _, arg := range launch["arguments"].([]string) {
		if !strings.HasPrefix(arg, "--proxy-") {
			args = append(args, arg)
		}
	}
	fixture.HealthURL = launch["health_url"].(string)
	fixture.BeforeRequests = func() error {
		if _, err := edgeCall(c, "edge.confirm", map[string]string{"profile_id": p.ID, "health_url": fixture.HealthURL}); err != nil {
			return fmt.Errorf("initial edge.confirm: %w", err)
		}
		p.Mode = profiles.Auto
		p.AppPreset = "edge-sites"
		if _, err := edgeCall(c, "profile.set", p); err != nil {
			return fmt.Errorf("initial profile.set: %w", err)
		}
		_, err := edgeCall(c, "optimize", map[string]bool{"enabled": true})
		if err != nil {
			c.browser.mu.Lock()
			e := c.edgeLocked()
			confirmed := e.server != nil && e.server.Confirmed(p.ID)
			active := e.policyActive(c.BrowserOwnerSID)
			c.browser.mu.Unlock()
			return fmt.Errorf("initial optimize: confirmed=%t policy_active=%t: %w", confirmed, active, err)
		}
		return nil
	}
	fixture.ExpectedFailures = map[int][]string{2: {"chatgpt.com", "www.youtube.com", "blocked.example"}}
	var records []browserproxy.Record
	output, err := fixture.RunChrome(ctx, edge, args, func() error {
		before := c.browser.edge.server.Snapshot()
		if before.Lost != 0 || before.Truncated {
			return errors.New("incomplete Edge evidence before outage")
		}
		records = append(records, before.Records...)
		c.Close()
		fixture.HealthURL = ""
		return nil
	}, func() error {
		c = configure()
		c.Engine.SetRelay("VPS-01", pool)
		if err := c.RestoreBrowserTransport(); err != nil {
			return fmt.Errorf("restart RestoreBrowserTransport: %w", err)
		}
		_, err := edgeCall(c, "optimize", map[string]bool{"enabled": true})
		if err != nil {
			return fmt.Errorf("restart optimize: %w", err)
		}
		return nil
	})
	if err != nil {
		t.Fatal("actual Edge policy/site/outage/restart", err, output)
	}
	after := c.browser.edge.server.Snapshot()
	if after.Lost != 0 || after.Truncated {
		t.Fatal("incomplete Edge evidence after restart")
	}
	records = append(records, after.Records...)
	seen := map[string]bool{}
	for _, record := range records {
		if record.Sent == 0 || record.Received == 0 {
			continue
		}
		seen[record.Domain] = true
		if !strings.EqualFold(record.Owner.Exe, edge) || record.Owner.PID == 0 || record.Owner.Birth == 0 || record.Owner.Profile != p.ID {
			t.Fatal("missing real Edge identity", record.Owner)
		}
		if record.Domain == "chatgpt.com" && (record.Plan.Policy.Action != flowpolicy.RelayRequired || record.Plan.Policy.Fallback != flowpolicy.Required) {
			t.Fatal("protected route downgrade", record)
		}
		if record.Domain == "ordinary.example" && record.Plan.Policy.Action != flowpolicy.Direct {
			t.Fatal("ordinary Edge was not DIRECT", record)
		}
	}
	for _, host := range browserfixture.Domains {
		if !seen[host] {
			t.Fatal("missing actual HTTP(S) evidence", host)
		}
	}
	if fixture.ProtectedDirectAttempts.Load() != 0 {
		t.Fatal("protected DIRECT leak")
	}
	if relayServer.Metrics.TCPConnections.Load() == 0 {
		t.Fatal("no authenticated relay")
	}
	if c.browser.server != nil || c.browser.expectedPAC != "" {
		t.Fatal("Edge created/modified Chrome runtime")
	}
	t.Log("real Edge policy: nine simultaneous fixture sites, HTTPS+HTTP/2, mTLS relay, protected no-DIRECT, ordinary recovery and service restart; production Internet and native Edge DIRECT+ not claimed")
}
