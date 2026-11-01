//go:build windows

package clientservice

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
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
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

// A routing gate, not a test that blesses a reproduced leak. TLS is end-to-end
// and verified by Chrome using a unique disposable root. The native path uses
// the pinned signed driver, normal filters and real PID/birth/SID ownership.
func TestWindowsBrowserOriginReuse(t *testing.T) {
	if os.Getenv("NEEXITLAG_TEST_ORIGIN_REUSE") != "1" {
		t.Skip("explicit disposable Chromium origin reuse fixture")
	}
	if os.Getenv("GITHUB_ACTIONS") != "true" || os.Getenv("NEEXITLAG_TEST_DRIVER_DIR") == "" {
		t.Fatal("disposable Actions Windows VM and pinned driver required")
	}
	if os.Getenv("NEEXITLAG_ORIGIN_REUSE_CHILD") != "1" {
		own, err := os.Executable()
		if err != nil {
			t.Fatal(err)
		}
		raw, err := os.ReadFile(own)
		if err != nil {
			t.Fatal(err)
		}
		child := filepath.Join(t.TempDir(), "veliq-service.exe")
		if err = os.WriteFile(child, raw, 0700); err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 180*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, child, "-test.run=^TestWindowsBrowserOriginReuse$", "-test.v")
		cmd.Env = append(os.Environ(), "NEEXITLAG_ORIGIN_REUSE_CHILD=1")
		out, err := cmd.CombinedOutput()
		t.Log(string(out))
		if err != nil {
			t.Fatal("origin routing gate failed", err)
		}
		return
	}
	preflight := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-Command", "$ErrorActionPreference='Stop';if((Get-Service VELIQ -ErrorAction SilentlyContinue) -or (Get-Service neexitlag -ErrorAction SilentlyContinue)){throw 'DISPOSABLE_VM_REQUIRED'}")
	if err := preflight.Run(); err != nil {
		t.Fatal("installed service must not be touched", err)
	}
	for _, hive := range []registry.Key{registry.CURRENT_USER, registry.LOCAL_MACHINE} {
		k, err := registry.OpenKey(hive, `Software\Policies\Google\Chrome`, registry.QUERY_VALUE)
		if err == registry.ErrNotExist {
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		for _, name := range []string{"ProxySettings", "ProxyMode", "ProxyServer", "ProxyPacUrl", "ProxyBypassList"} {
			if _, _, err := k.GetValue(name, nil); err != registry.ErrNotExist {
				k.Close()
				t.Fatal("existing proxy policy preserved", name)
			}
		}
		k.Close()
	}
	chrome := browserfixture.ChromePath()
	if chrome == "" {
		t.Fatal("real Chrome required")
	}
	// Reuse the production app-scoped admission helper, never disable the firewall.
	helper, err := filepath.Abs(filepath.Join("..", "..", "tools", "windows", "native-tcp-firewall.ps1"))
	if err != nil {
		t.Fatal(err)
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	quote := func(s string) string { return "'" + strings.ReplaceAll(s, "'", "''") + "'" }
	firewall := func(op string) ([]byte, error) {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		return exec.CommandContext(ctx, "powershell.exe", "-NoProfile", "-NonInteractive", "-Command", "$ErrorActionPreference='Stop';. "+quote(helper)+";"+op+" "+quote(exe)).CombinedOutput()
	}
	out, err := firewall("Add-NativeTcpFirewallAdmission")
	if err != nil || strings.TrimSpace(string(out)) != "True" {
		t.Fatal("owned disposable firewall rule required", err)
	}
	defer func() {
		if _, err := firewall("Remove-NativeTcpFirewallAdmission"); err != nil {
			t.Error("owned firewall cleanup", err)
		}
	}()
	for _, tc := range []struct {
		name                  string
		native, requiredFirst bool
	}{
		{"PAC", false, false}, {"NativeRequiredFirst", true, true}, {"NativeLocalFirst", true, false},
	} {
		t.Run(tc.name, func(t *testing.T) { runOriginReuseController(t, chrome, tc.native, tc.requiredFirst) })
	}
}

func runOriginReuseController(t *testing.T, chrome string, native, requiredFirst bool) {
	f := browserfixture.NewOriginReuse(t)
	c := New(context.Background())
	t.Cleanup(c.Close)
	token, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	c.BrowserOwnerSID = token.User.Sid.String()
	c.customPath = filepath.Join(t.TempDir(), "profiles.json")
	c.BrowserResolver = continuityResolver(t, [4]byte{127, 0, 0, 1})
	c.BrowserProbeRoots = f.Roots
	c.network.Store(&wp.NetworkContext{Fingerprint: "isolated-origin-reuse", ObservedAt: time.Now()})
	c.mu.Lock()
	c.enabled = true
	c.settings.Automatic = true
	c.mu.Unlock()
	// This isolates authority reuse after a locally admitted connection. It does
	// not fake a successful DPI transform or claim LOCAL selection/ISP acceptance.
	p := profiles.Profile{ID: "origin-reuse", Name: "Origin reuse", Executables: []string{chrome}, Mode: profiles.Auto, Custom: true, Rules: []flowpolicy.Rule{{ID: "controlled-local", Protocol: "tcp", Domains: []string{browserfixture.ReuseLocalHost, browserfixture.ReuseSiblingHost}, Action: flowpolicy.Direct, Fallback: flowpolicy.FailBlock}}}
	if native {
		p.BrowserTransport = "native"
	}
	if err = c.Profiles.Upsert(p); err != nil {
		t.Fatal(err)
	}
	st, ct, err := labcert.Pair()
	if err != nil {
		t.Fatal(err)
	}
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	r, err := relay.Listen("127.0.0.1:0", relay.Config{TLS: st, TicketVerifier: security.NewTicketVerifier(map[string]ed25519.PublicKey{"test": pub}, "VPS-01"), Allow: []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}, Acceptance: &relay.AcceptanceConfig{LeaseDuration: 2 * time.Minute, OutboundSource: netip.MustParseAddr("127.0.0.2")}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { r.Close() })
	peer := ct.Certificates[0].PrivateKey.(ed25519.PrivateKey).Public().(ed25519.PublicKey)
	pool, err := transport.NewPool(c.ctx, transport.DefaultPoolConfig(), func(ctx context.Context) (*transport.Client, error) {
		id, err := security.NewID()
		if err != nil {
			return nil, err
		}
		now := time.Now()
		ticket, err := security.Sign("ticket", "test", key, security.Ticket{ID: id, DeviceID: "origin-reuse", DeviceKey: security.Fingerprint(peer), RelayID: "VPS-01", IssuedAt: now, ExpiresAt: now.Add(time.Minute)})
		if err != nil {
			return nil, err
		}
		return transport.DialWithTicket(ctx, r.Addr().String(), ct, ticket)
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pool.Close() })
	c.Engine.SetRelay("VPS-01", pool)
	address := "127.0.0.1"
	args := []string{"--no-proxy-server"}
	var proxy *browserproxy.Server
	if native {
		raw, err := os.ReadFile(filepath.Join(os.Getenv("NEEXITLAG_TEST_DRIVER_DIR"), "pins.json"))
		if err != nil {
			t.Fatal(err)
		}
		var files wp.DriverFiles
		if err = json.Unmarshal(raw, &files); err != nil {
			t.Fatal(err)
		}
		files.Directory = os.Getenv("NEEXITLAG_TEST_DRIVER_DIR")
		backend := wp.NewWinDivert(files, c.Engine)
		c.Backend = backend
		if err = backend.Start(c.ctx, c.Classify); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { backend.Stop() })
		address = "192.0.2.254"
	} else {
		proxy, err = browserproxy.Listen(c.ctx, browserproxy.Config{TransportCheck: c.transportCheckSettings, RequireClientHelloReplay: true, Authorize: c.browserOwner, AuthorizeForwarded: c.browserRecoveryOwner, Plan: c.browserPlan, Open: c.browserOpen, OpenPlan: c.browserOpenPlan, TransformApplied: c.browserTransform, OnStall: c.browserStall, OnDirectAnswered: c.browserDirectAnswered})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { proxy.Close() })
		// Exact production per-authority PAC, no policy installation/recovery bypass.
		pacArgs, err := browserproxy.ChromeArguments(proxy.Address(), "unused-isolated-profile")
		if err != nil {
			t.Fatal(err)
		}
		args = nil
		for _, arg := range pacArgs {
			if !strings.HasPrefix(arg, "--user-data-dir=") {
				args = append(args, arg)
			}
		}
	}
	bootstrap := browserfixture.ReuseLocalHost
	if requiredFirst {
		bootstrap = browserfixture.ReuseRequiredHost
	}
	f.Run(t, chrome, address, bootstrap, args)
	requests := f.Requests(t)
	for _, q := range requests {
		t.Logf("ORIGIN_REUSE_REQUEST native=%t %+v", native, q)
	}
	if !requiredFirst && (requests[0].Source != "127.0.0.1" || requests[1].Source != "127.0.0.1") {
		t.Fatal("local first-route precondition missing")
	}
	requiredDirect := 0
	for _, q := range requests[2:] {
		if q.Source != "127.0.0.2" {
			requiredDirect++
		}
	}
	if native {
		snap := c.nativeSnapshot()
		if snap.Lost != 0 || snap.Truncated || snap.NativeOnly.Opened == 0 || snap.NativeOnly.Exchanges == 0 || snap.PACUpstream.Accepted != 0 || snap.CaptureIngress == nil || snap.CaptureIngress.NativeDeferredSYN == 0 || snap.CaptureIngress.ReflectedAccepts == 0 {
			t.Fatal("actual native capture evidence incomplete")
		}
		for _, record := range snap.Records {
			if record.Domain == browserfixture.ReuseLocalHost || record.Domain == browserfixture.ReuseRequiredHost || record.Domain == browserfixture.ReuseSiblingHost {
				t.Logf("ORIGIN_REUSE_NATIVE domain=%s action=%s sent=%d received=%d", record.Domain, record.Policy.Action, record.Sent, record.Received)
			}
		}
	} else {
		snap := proxy.Snapshot()
		if snap.Lost != 0 || snap.Truncated {
			t.Fatal("PAC evidence incomplete")
		}
		required := false
		for _, record := range snap.Records {
			t.Logf("ORIGIN_REUSE_CONNECT domain=%s action=%s sent=%d received=%d", record.Domain, record.Plan.Policy.Action, record.Sent, record.Received)
			if record.Domain == browserfixture.ReuseRequiredHost && record.Plan.Policy.Action == flowpolicy.RelayRequired && record.Sent > 0 && record.Received > 0 {
				required = true
			}
		}
		if !required {
			t.Error("required CONNECT with relay bytes missing")
		}
	}
	t.Logf("ORIGIN_REUSE_ACCOUNTING native=%t required_direct_requests=%d relay_tcp=%d relay_rx=%d", native, requiredDirect, r.Metrics.TCPConnections.Load(), r.Metrics.RXBytes.Load())
	if requiredDirect != 0 {
		t.Error("ORIGIN_ISOLATION_VIOLATION: REQUIRED authority reached LOCAL egress; this is a controlled common-SAN endpoint, not evidence of a public-site leak")
	}
	if requiredDirect == 0 && (r.Metrics.TCPConnections.Load() == 0 || r.Metrics.RXBytes.Load() == 0) {
		t.Error("authenticated relay accounting missing")
	}
}
