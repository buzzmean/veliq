//go:build windows

package clientservice

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
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
		name, mode    string
		requiredFirst bool
	}{
		{"PAC", "pac", false},
		{"PACNativeLocalFirst", "pac-native", false},
		{"PACNativeRequiredThenLocal", "pac-native", true},
		{"NativeRequiredThenLocal", "native", true},
		{"NativeLocalFirst", "native", false},
	} {
		t.Run(tc.name, func(t *testing.T) { runOriginReuseController(t, chrome, tc.mode, tc.requiredFirst) })
	}
}

func runOriginReuseController(t *testing.T, chrome, mode string, requiredFirst bool) {
	native := mode == "native" || mode == "pac-native"
	usePAC := mode == "pac" || mode == "pac-native"
	if !native && !usePAC {
		t.Fatal("unknown fixture transport")
	}
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
	var delegated *originReuseDelegatedBackend
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
		if usePAC {
			delegated = &originReuseDelegatedBackend{WinDivertBackend: backend, origin: f.Destination()}
			c.Backend = delegated
		}
		controlled := netip.AddrPortFrom(netip.MustParseAddr("192.0.2.254"), f.Port())
		classify := func(id wp.ProcessIdentity, tuple wp.Tuple) wp.Decision {
			// Contain unrelated browser bootstrap traffic in this disposable
			// VM. The tested endpoint still uses the unmodified classifier.
			if strings.EqualFold(id.Path, chrome) && (tuple.Protocol != "tcp" || tuple.Destination != controlled) {
				return wp.Decision{Block: true, BlockOnFailure: true, Policy: flowpolicy.Result{Action: flowpolicy.Block, Fallback: flowpolicy.FailBlock}}
			}
			return c.Classify(id, tuple)
		}
		if err = backend.Start(c.ctx, classify); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { backend.Stop() })
		if !usePAC {
			address = "192.0.2.254"
		}
	}
	if usePAC {
		plan := func(ctx context.Context, q browserproxy.Request) (browserproxy.Plan, error) {
			if !q.Secure || q.Port != f.Port() || (q.Host != browserfixture.ReuseLocalHost && q.Host != browserfixture.ReuseSiblingHost && q.Host != browserfixture.ReuseRequiredHost) {
				return browserproxy.Plan{}, errors.New("outside controlled origin reuse endpoint")
			}
			return c.browserPlan(ctx, q)
		}
		proxy, err = browserproxy.Listen(c.ctx, browserproxy.Config{TransportCheck: c.transportCheckSettings, RequireClientHelloReplay: true, Authorize: c.browserOwner, AuthorizeForwarded: c.browserRecoveryOwner, Plan: plan, Open: c.browserOpen, OpenPlan: c.browserOpenPlan, TransformApplied: c.browserTransform, OnStall: c.browserStall, OnDirectAnswered: c.browserDirectAnswered})
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
	if native && usePAC {
		t.Cleanup(func() {
			if !t.Failed() {
				return
			}
			snap := c.nativeSnapshot()
			t.Logf("ORIGIN_REUSE_HYBRID_FAILURE attempted=%d connected=%d native=%+v pac=%+v", delegated.attempted.Load(), delegated.connected.Load(), snap.NativeOnly, snap.PACUpstream)
			if snap.CaptureIngress != nil {
				t.Logf("ORIGIN_REUSE_HYBRID_CAPTURE tcp=%d reflected=%d lost=%d", snap.CaptureIngress.TCPPackets, snap.CaptureIngress.ReflectedAccepts, snap.CaptureIngress.Lost)
			}
			for _, r := range proxy.Snapshot().Records {
				if r.Domain == browserfixture.ReuseLocalHost || r.Domain == browserfixture.ReuseSiblingHost || r.Domain == browserfixture.ReuseRequiredHost {
					t.Logf("ORIGIN_REUSE_HYBRID_OPEN host=%s result=%s failure=%s", r.Domain, r.Result, r.OpenFailure)
				}
			}
		})
	}
	bootstrap := browserfixture.ReuseLocalHost
	if requiredFirst {
		bootstrap = browserfixture.ReuseRequiredHost
	}
	f.Run(t, chrome, address, bootstrap, args)
	first := f.Bootstrap(t)
	t.Logf("ORIGIN_REUSE_BOOTSTRAP transport=%s %+v", mode, first)
	firstSource := "127.0.0.1"
	if requiredFirst {
		firstSource = "127.0.0.2"
	}
	if first.Host != bootstrap || first.SNI != bootstrap || first.Source != firstSource {
		t.Fatal("fresh bootstrap route not proved", first)
	}
	requests := f.Requests(t)
	for _, q := range requests {
		t.Logf("ORIGIN_REUSE_REQUEST transport=%s %+v", mode, q)
	}
	if (usePAC || !requiredFirst) && (requests[0].Source != "127.0.0.1" || requests[1].Source != "127.0.0.1") {
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
		// CaptureIngress.Lost counts evicted metadata samples in a 24-record
		// ring, not lost packets or the native application ledger. We use its
		// lifetime atomic totals; the separate ledger must remain complete.
		if snap.Lost != 0 || snap.Truncated || snap.CaptureIngress == nil || snap.CaptureIngress.TCPPackets == 0 || snap.CaptureIngress.ReflectedAccepts == 0 {
			t.Fatal("actual capture evidence incomplete")
		}
		if usePAC {
			if snap.NativeOnly.Accepted != 0 || snap.PACUpstream.Opened == 0 || snap.PACUpstream.Exchanges == 0 || delegated.connected.Load() == 0 || snap.CaptureIngress.ReflectedAccepts < delegated.connected.Load() {
				t.Fatal("PAC_NATIVE_UPSTREAM proof missing or contaminated by native-only ingress")
			}
			t.Logf("ORIGIN_REUSE_HYBRID_PROOF delegated=%d connected=%d reflected=%d pac_opened=%d pac_exchanges=%d native_accepted=%d metadata_evicted=%d", delegated.attempted.Load(), delegated.connected.Load(), snap.CaptureIngress.ReflectedAccepts, snap.PACUpstream.Opened, snap.PACUpstream.Exchanges, snap.NativeOnly.Accepted, snap.CaptureIngress.Lost)
		} else if snap.NativeOnly.Opened == 0 || snap.NativeOnly.Exchanges == 0 || snap.PACUpstream.Accepted != 0 || snap.CaptureIngress.NativeDeferredSYN == 0 {
			t.Fatal("native-only ingress proof missing")
		}
		witnessed := map[string]bool{}
		for _, record := range snap.Records {
			if record.Domain == browserfixture.ReuseLocalHost || record.Domain == browserfixture.ReuseRequiredHost || record.Domain == browserfixture.ReuseSiblingHost {
				t.Logf("ORIGIN_REUSE_NATIVE ingress=%s domain=%s action=%s sent=%d received=%d", record.Ingress, record.Domain, record.Policy.Action, record.Sent, record.Received)
				if usePAC && record.Sent > 0 && record.Received > 0 {
					expected := flowpolicy.Direct
					if record.Domain == browserfixture.ReuseRequiredHost {
						expected = flowpolicy.RelayRequired
					}
					if record.Ingress != "PAC_NATIVE_UPSTREAM" || record.Owner.Profile != p.ID || record.Owner.PID == 0 || record.Owner.Birth == 0 || record.Policy.Action != expected {
						t.Fatal("hybrid origin/owner/route mismatch", record.Domain, record.Policy.Action, record.Ingress)
					}
					witnessed[record.Domain] = true
				}
			}
		}
		if usePAC && len(witnessed) != 3 {
			t.Fatal("hybrid did not witness three separate authorities", witnessed)
		}
	}
	if usePAC {
		snap := proxy.Snapshot()
		if snap.Lost != 0 || snap.Truncated {
			t.Fatal("PAC evidence incomplete")
		}
		required := false
		for _, record := range snap.Records {
			if record.Domain == browserfixture.ReuseLocalHost || record.Domain == browserfixture.ReuseSiblingHost || record.Domain == browserfixture.ReuseRequiredHost {
				t.Logf("ORIGIN_REUSE_CONNECT domain=%s action=%s sent=%d received=%d", record.Domain, record.Plan.Policy.Action, record.Sent, record.Received)
			}
			if record.Domain == browserfixture.ReuseRequiredHost && record.Plan.Policy.Action == flowpolicy.RelayRequired && record.Sent > 0 && record.Received > 0 {
				required = true
			}
		}
		if !required {
			t.Error("required CONNECT with relay bytes missing")
		}
	}
	t.Logf("ORIGIN_REUSE_ACCOUNTING transport=%s required_direct_requests=%d relay_tcp=%d relay_rx=%d", mode, requiredDirect, r.Metrics.TCPConnections.Load(), r.Metrics.RXBytes.Load())
	if requiredDirect != 0 {
		t.Error("ORIGIN_ISOLATION_VIOLATION: REQUIRED authority reached LOCAL egress; this is a controlled common-SAN endpoint, not evidence of a public-site leak")
	}
	if requiredDirect == 0 && (r.Metrics.TCPConnections.Load() == 0 || r.Metrics.RXBytes.Load() == 0) {
		t.Error("authenticated relay accounting missing")
	}
}

// Test-only network seam: an ordinary Windows loopback SYN never traverses the
// production NETWORK filter. Only the reserved service-owned interception socket
// targets TEST-NET; the immutable controller callback keeps the real loopback
// origin/relay. No fake writer, injected packet, owner or OPEN callback is used.
// This mirrors nativeDelegationDestination in the existing Windows test helper
// without exposing a production switch or importing that package's _test API.
type originReuseDelegatedBackend struct {
	*wp.WinDivertBackend
	origin               netip.AddrPort
	attempted, connected atomic.Uint64
}

func (b *originReuseDelegatedBackend) OpenBrowserNativeTCP(ctx context.Context, id wp.ProcessIdentity, source, dest netip.AddrPort, decision wp.Decision) (net.Conn, error) {
	if dest != b.origin {
		return nil, errors.New("outside controlled delegation destination")
	}
	b.attempted.Add(1)
	wire := netip.AddrPortFrom(netip.MustParseAddr("192.0.2.254"), dest.Port())
	conn, err := b.WinDivertBackend.OpenBrowserNativeTCP(ctx, id, source, wire, decision)
	if err == nil {
		b.connected.Add(1)
	}
	return conn, err
}
