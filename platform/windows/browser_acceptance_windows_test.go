//go:build windows

package windowsplatform_test

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/buzzmean/veliq/core/browserproxy"
	"github.com/buzzmean/veliq/core/flowpolicy"
	"github.com/buzzmean/veliq/core/localstrategy"
	"github.com/buzzmean/veliq/core/profiles"
	"github.com/buzzmean/veliq/core/security"
	"github.com/buzzmean/veliq/core/transport"
	"github.com/buzzmean/veliq/internal/browserfixture"
	wp "github.com/buzzmean/veliq/platform/windows"
	cs "github.com/buzzmean/veliq/services/client-service"
	"github.com/buzzmean/veliq/services/relay"
	"github.com/buzzmean/veliq/tools/labcert"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
	"unsafe"
)

// This test uses real Chrome, real HTTP/2+TLS, real authenticated relay and real
// signed WinDivert packet reinjection on an isolated loopback target. It is not
// a measurement of public YouTube/OpenAI or the production VPS.
func TestChromeSitesNativeAcceptance(t *testing.T) {
	dir := os.Getenv("NEEXITLAG_TEST_DRIVER_DIR")
	if dir == "" {
		t.Skip("signed driver required; enabled explicitly on native Windows CI")
	}
	chrome := browserfixture.ChromePath()
	if chrome == "" {
		t.Fatal("native Chrome required, cannot report PASS without a browser")
	}
	raw, err := os.ReadFile(filepath.Join(dir, "pins.json"))
	if err != nil {
		t.Fatal(err)
	}
	var files wp.DriverFiles
	if err = json.Unmarshal(raw, &files); err != nil {
		t.Fatal(err)
	}
	files.Directory = dir
	f, err := browserfixture.New()
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	f.PoisonTelegramDNS.Store(true)
	alternativeDNS := func(ctx context.Context, host string, open browserproxy.DNSOpen) (browserproxy.DNSAnswer, error) {
		addresses, ttl, err := f.AlternativeDNS(ctx, host, open)
		return browserproxy.DNSAnswer{Addresses: addresses, TTL: ttl, Source: "ISOLATED_RELAY_DOH", ObtainedAt: time.Now()}, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Second)
	defer cancel()
	c := cs.New(ctx)
	self, err := wp.NewDiscovery().Lookup(uint32(os.Getpid()))
	if err != nil {
		t.Fatal(err)
	}
	c.BrowserOwnerSID, err = wp.ProcessUserSID(self)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { c.Close() }()
	backend := wp.NewBrowserLoopbackFixture(files, c.Engine)
	c.Backend = browserMTUFixture{backend}
	c.BrowserResolver = f.Resolver
	c.BrowserAlternativeDNS = alternativeDNS
	c.BrowserProbeRoots = f.Roots
	statePath := filepath.Join(t.TempDir(), "profiles.json")
	if err = c.SetCustomPath(statePath); err != nil {
		t.Fatal(err)
	}
	c.Start()
	// IPC success only means a snapshot exists. A failed background inspection
	// has no fingerprint/time and must never be adopted as a ready network.
	// Allow one real 30-second producer cycle plus its 8-second query budget.
	waitNetwork := func() error {
		until := time.Now().Add(45 * time.Second)
		var last any
		for {
			value, e := c.Handle(ctx, "local.network", nil)
			last = value
			if e == nil {
				if n, ok := value.(*wp.NetworkContext); ok && n.Error == "" && n.Fingerprint != "" && !n.ObservedAt.IsZero() && time.Since(n.ObservedAt) <= 45*time.Second && len(n.VPN) == 0 && len(n.Conflicts) == 0 {
					return nil
				}
			}
			if time.Now().After(until) {
				return fmt.Errorf("network readiness: snapshot=%+v error=%v", last, e)
			}
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(100 * time.Millisecond):
			}
		}
	}
	if err = waitNetwork(); err != nil {
		t.Fatal(err)
	}
	st, ct, err := labcert.Pair()
	if err != nil {
		t.Fatal(err)
	}
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	server, err := relay.Listen("127.0.0.1:0", relay.Config{TLS: st, TicketVerifier: security.NewTicketVerifier(map[string]ed25519.PublicKey{"test": pub}, "VPS-01"), Allow: []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}, Acceptance: &relay.AcceptanceConfig{LeaseDuration: 2 * time.Minute, OutboundSource: netip.MustParseAddr("127.0.0.2")}})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	peer := ct.Certificates[0].PrivateKey.(ed25519.PrivateKey).Public().(ed25519.PublicKey)
	pool, err := transport.NewPool(ctx, transport.DefaultPoolConfig(), func(ctx context.Context) (*transport.Client, error) {
		id, _ := security.NewID()
		now := time.Now()
		ticket, e := security.Sign("ticket", "test", key, security.Ticket{ID: id, DeviceID: "fixture", DeviceKey: security.Fingerprint(peer), RelayID: "VPS-01", IssuedAt: now, ExpiresAt: now.Add(time.Minute)})
		if e != nil {
			return nil, e
		}
		return transport.DialWithTicket(ctx, server.Addr().String(), ct, ticket)
	})
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	c.Engine.SetRelay("VPS-01", pool)
	entries, _, err := localstrategy.PresetProfiles("youtube", chrome, false)
	if err != nil {
		t.Fatal(err)
	}
	selected := ""
	for i := range entries {
		entries[i].Ports = []uint16{f.Port()}
		if strings.HasSuffix(entries[i].ID, "-disorder") && !strings.HasSuffix(entries[i].ID, "-fake8-disorder") {
			selected = entries[i].ID
		}
	}
	if err = c.Local.Reload(localstrategy.Config{Version: 1, Enabled: true, User: entries}); err != nil {
		t.Fatal(err)
	}
	p := profiles.Profile{ID: "native-chrome-sites", Name: "Chrome isolated acceptance", Executables: []string{chrome}, Mode: profiles.DirectPlus, LocalStrategyID: selected, Custom: true}
	put := func() {
		raw, _ := json.Marshal(p)
		if _, e := c.Handle(ctx, "profile.set", raw); e != nil {
			t.Fatal(e)
		}
	}
	put()
	p.Mode = profiles.Auto
	if _, err = c.Handle(ctx, "optimize", []byte(`{"enabled":true}`)); err != nil {
		t.Fatal(err)
	}
	helperPath := os.Getenv("NEEXITLAG_TEST_BROWSER_RECOVERY")
	if helperPath == "" {
		helperPath = filepath.Join("..", "..", "bin", "windows-e2e", "browser-recovery-acceptance.exe")
	}
	helperPath, err = filepath.Abs(helperPath)
	if err != nil {
		t.Fatal(err)
	}
	c.BrowserRecoveryExecutable = helperPath
	helper := exec.CommandContext(ctx, helperPath, "-test.run=^TestChromeRecoveryChildProcess$", "-test.v=false")
	helper.Env = append(os.Environ(), "NEEXITLAG_TEST_RECOVERY_CHILD=1")
	helperToken := restrictedRecoveryToken(t)
	defer helperToken.Close()
	helper.SysProcAttr = &syscall.SysProcAttr{Token: syscall.Token(helperToken)}
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
		t.Fatal("restricted recovery helper", err)
	}
	defer func() {
		stdin.Close()
		done := make(chan error, 1)
		go func() { done <- helper.Wait() }()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			helper.Process.Kill()
			<-done
		}
	}()
	reader := bufio.NewScanner(stdout)
	reader.Buffer(make([]byte, 4096), 65536)
	if !reader.Scan() {
		t.Fatal("helper listener", reader.Err(), helperErrors.String())
	}
	var greeting struct {
		Address string `json:"address"`
	}
	if json.Unmarshal(reader.Bytes(), &greeting) != nil || greeting.Address == "" {
		t.Fatal("invalid helper greeting")
	}
	helperID, err := wp.NewDiscovery().Lookup(uint32(helper.Process.Pid))
	if err != nil {
		t.Fatal(err)
	}
	userData := t.TempDir()
	raw, _ = json.Marshal(map[string]string{"profile_id": p.ID, "directory": userData, "recovery_address": greeting.Address})
	result, err := c.Handle(ctx, "browser.prepare", raw)
	if err != nil {
		t.Fatal(err)
	}
	pre := startBrowserEvidencePoll(ctx, c)
	var post *browserEvidencePoll
	recoverySettings := result.(map[string]any)["recovery_settings"].(browserproxy.RecoverySettings)
	recoverySettings.Executable = chrome
	if err = json.NewEncoder(stdin).Encode(recoverySettings); err != nil {
		t.Fatal(err)
	}
	if !reader.Scan() {
		t.Fatal("helper configuration", reader.Err(), helperErrors.String())
	}
	var ack struct {
		Ready bool `json:"ready"`
	}
	if json.Unmarshal(reader.Bytes(), &ack) != nil || !ack.Ready {
		t.Fatal("helper not ready")
	}

	args := result.(map[string]any)["arguments"].([]string)
	healthURL := result.(map[string]any)["health_url"].(string)

	// Exercise the actual current-user Chrome platform policy, not just launch
	// flags. This key is confined to the disposable Windows CI user; no WinINET,
	// WinHTTP or machine proxy value is read/written. Refuse any foreign policy.
	policy, _, e := registry.CreateKey(registry.CURRENT_USER, `Software\Policies\Google\Chrome`, registry.QUERY_VALUE|registry.SET_VALUE)
	if e != nil {
		t.Fatal(e)
	}
	defer policy.Close()
	if _, _, e = policy.GetStringValue("ProxySettings"); !errors.Is(e, registry.ErrNotExist) {
		t.Fatal("refusing foreign Chrome proxy policy", e)
	}
	pac := ""
	clean := []string{}
	for _, a := range args {
		if strings.HasPrefix(a, "--proxy-pac-url=") {
			pac = strings.TrimPrefix(a, "--proxy-pac-url=")
			continue
		}
		if strings.HasPrefix(a, "--proxy-bypass-list=") {
			continue
		}
		clean = append(clean, a)
	}
	if pac == "" {
		t.Fatal("missing real PAC")
	}
	// No policy must fail before publishing AUTO; a successful Chrome process
	// exit or a bound listener is not sufficient activation evidence.
	if err := browserfixture.RunPolicyHealthProbe(ctx, chrome, healthURL, t.TempDir()); err == nil {
		t.Fatal("Chrome activated without actual policy")
	}
	proof, _ := json.Marshal(map[string]string{"profile_id": p.ID, "health_url": healthURL})
	if _, err := c.Handle(ctx, "browser.confirm", proof); err == nil {
		t.Fatal("failed policy probe falsely confirmed readiness")
	}
	policyJSON, _ := json.Marshal(map[string]any{"ProxyMode": "pac_script", "ProxyPacUrl": pac, "ProxyPacMandatory": true})
	if e = policy.SetStringValue("ProxySettings", string(policyJSON)); e != nil {
		t.Fatal(e)
	}
	defer policy.DeleteValue("ProxySettings")
	args = clean

	rules := []string{}
	for _, host := range browserfixture.Domains {
		rules = append(rules, "MAP "+host+" 127.0.0.1")
	}
	args = append(args, "--host-resolver-rules="+strings.Join(rules, ", "))
	f.ExpectedFailures = map[int][]string{3: {"chatgpt.com", "www.youtube.com", "blocked.example", "web.telegram.org"}}
	// Actual policy, normal sandbox, a disposable health profile. Commit AUTO
	// before starting/restoring the real multi-origin Chrome process.
	if err := browserfixture.RunPolicyHealthProbe(ctx, chrome, healthURL, t.TempDir()); err != nil {
		t.Fatal(err)
	}
	if err = waitNetwork(); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Handle(ctx, "browser.confirm", proof); err != nil {
		t.Fatal(err)
	}
	put()
	f.DirectProbe = func(source netip.AddrPort) bool {
		id, e := wp.LookupTCPPeer(source, f.Destination())
		if e != nil || id.PID != helperID.PID || id.CreationTime != helperID.CreationTime {
			return false
		}
		sid, e := wp.ProcessUserSID(id)
		return e == nil && sid == c.BrowserOwnerSID
	}
	// A distinct controlled port forces a genuinely NEW connection without
	// restarting Chrome, clearing user sockets or pretending H2 reuse is native.
	freshOrigin := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		f.Server.Config.Handler.ServeHTTP(w, r)
	}))
	freshOrigin.EnableHTTP2 = true
	freshOrigin.TLS = f.Server.TLS.Clone()
	freshOrigin.StartTLS()
	defer freshOrigin.Close()
	var traceMu sync.Mutex
	trace := []map[string]any{}
	observer := func(phase string, tuple wp.Tuple, flags, addr byte) {
		traceMu.Lock()
		defer traceMu.Unlock()
		if len(trace) < 256 {
			trace = append(trace, map[string]any{"phase": phase, "source": tuple.Source.String(), "destination": tuple.Destination.String(), "tcp_flags": flags, "address_flags": addr})
		}
	}
	admitted := map[uint16]bool{}
	var nativeMain wp.ProcessIdentity
	f.StageReady = func(stage int, call func(string, any) (json.RawMessage, error)) error {
		if stage != 3 {
			backend.TraceNativeFixture(observer)
			if port := backend.NativeFixtureListenerPort(); !admitted[port] {
				backend.AdmitNativeFixtureListener(t)
				admitted[port] = true
			}
		}
		if stage == 2 {
			port := freshOrigin.Listener.Addr().(*net.TCPAddr).Port
			url := fmt.Sprintf("https://ordinary.example:%d/policy-probe?nonce=%s", port, f.Nonce)
			quoted, _ := json.Marshal(url)
			raw, err := call("Runtime.evaluate", map[string]any{"expression": "fetch(" + string(quoted) + ",{cache:'no-store'}).then(r=>r.text())", "awaitPromise": true, "returnByValue": true})
			if err != nil {
				return err
			}
			var result struct {
				Result struct {
					Value string `json:"value"`
				} `json:"result"`
			}
			json.Unmarshal(raw, &result)
			if result.Result.Value != f.Nonce+":PROXY" {
				return fmt.Errorf("native PAC fresh HTTPS failed: %s", raw)
			}
			value, err := c.Handle(ctx, "browser.native.status", nil)
			if err != nil {
				return err
			}
			encoded, _ := json.Marshal(value)
			var native struct {
				Profiles []struct {
					Opened uint64 `json:"opened"`
					First  int64  `json:"enable_to_first_open_ms"`
				} `json:"profiles"`
				Records []struct {
					Ingress  string `json:"ingress"`
					Sent     uint64 `json:"sent_bytes"`
					Received uint64 `json:"received_bytes"`
				} `json:"records"`
			}
			json.Unmarshal(encoded, &native)
			found := false
			for _, r := range native.Records {
				if r.Ingress == "PAC_NATIVE_UPSTREAM" && r.Sent > 0 && r.Received > 0 {
					found = true
				}
			}
			if !found || len(native.Profiles) != 1 || native.Profiles[0].Opened == 0 || native.Profiles[0].First < 0 {
				return fmt.Errorf("HTTPS succeeded without native WinDivert upstream evidence: %s", encoded)
			}
			if nativeMain.PID == 0 || !wp.IsCurrent(nativeMain) {
				return errors.New("running Chrome main PID/creation changed before native HTTPS proof")
			}
			t.Log("PAC_NATIVE_UPSTREAM: same running Chrome, new controlled HTTPS connection, actual native OPEN+bidirectional bytes; PAC guard unchanged")
		}
		if stage != 3 {
			return nil
		}
		// The primary controller is closed. Verify an actual nonce GET over the
		// independent recovery process running with a restricted owner token.
		// No registry flip, Chrome restart or primary connection is possible.
		url := fmt.Sprintf("https://ordinary.example:%d/policy-probe?nonce=%s", f.Port(), f.Nonce)
		quoted, _ := json.Marshal(url)
		expression := "fetch(" + string(quoted) + ",{cache:'no-store'}).then(r=>r.text()).catch(()=> 'POLICY_PENDING')"
		until := time.Now().Add(12 * time.Second)
		for {
			raw, e := call("Runtime.evaluate", map[string]any{"expression": expression, "awaitPromise": true, "returnByValue": true})
			if e != nil {
				return e
			}
			var result struct {
				Result struct {
					Value string `json:"value"`
				} `json:"result"`
			}
			json.Unmarshal(raw, &result)
			if result.Result.Value == f.Nonce+":DIRECT" {
				if err := json.NewEncoder(stdin).Encode(map[string]string{"op": "status"}); err != nil {
					return err
				}
				if !reader.Scan() {
					return errors.New("recovery metadata pipe closed")
				}
				var proof browserproxy.Snapshot
				if err := json.Unmarshal(reader.Bytes(), &proof); err != nil {
					return err
				}
				if proof.Truncated || proof.Lost != 0 {
					return errors.New("recovery evidence incomplete")
				}
				found := false
				for _, record := range proof.Records {
					if record.EvidenceSource == "RECOVERY_DIRECT" && record.Plan.Policy.Action == flowpolicy.Direct && record.Owner.Profile == p.ID && record.Sent > 0 {
						found = true
					}
				}
				if !found {
					return errors.New("independent recovery actual socket evidence missing")
				}
				return nil
			}
			if time.Now().After(until) {
				return fmt.Errorf("independent recovery CONNECT did not deliver DIRECT nonce: %s", raw)
			}
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(100 * time.Millisecond):
			}
		}
	}
	var earlier []browserproxy.Record
	out, err := f.RunChrome(ctx, chrome, args, func() error {
		if e := pre.check(); e != nil {
			return e
		}
		// The REAL Chrome is already serving HTTP/2 here. Arm native new-flow
		// routing through production IPC with its ACTUAL owned mandatory policy.
		// Keep PAC/recovery unchanged: this also tests the independent crash guard.
		live, err := wp.NewDiscovery().List()
		if err != nil {
			return err
		}
		var before []wp.ProcessIdentity
		for _, id := range live {
			if strings.EqualFold(id.Path, chrome) {
				before = append(before, id)
			}
		}
		for _, id := range before {
			if nativeMain.PID == 0 || id.CreationTime < nativeMain.CreationTime {
				nativeMain = id
			}
		}
		if len(before) == 0 {
			return errors.New("already-running Chrome identity missing")
		}
		enable, _ := json.Marshal(map[string]string{"profile_id": p.ID})
		if _, err = c.Handle(ctx, "browser.native.enable", enable); err != nil {
			return err
		}
		// Renderer and utility processes come and go on their own; only the
		// browser main process proves Chrome was not restarted.
		if !wp.IsCurrent(nativeMain) {
			return errors.New("Chrome PID/creation changed during native enable")
		}
		t.Log("NATIVE_ENABLE_RUNNING_CHROME: PID/creation unchanged; owned PAC retained; native worker independently covered by TCP burst")

		for _, enabled := range []string{`{"enabled":false}`, `{"enabled":true}`} {
			if _, e := c.Handle(ctx, "optimize", []byte(enabled)); e != nil {
				return e
			}
		}
		return nil
	}, func() error {
		var e error
		if earlier, e = pre.finish(); e != nil {
			return e
		}
		// PAC stays unchanged; recovery listener is independent of controller.
		c.Close()
		return nil
	}, func() error {
		c = cs.New(ctx)
		c.BrowserRecoveryExecutable = helperPath
		c.BrowserOwnerSID, err = wp.ProcessUserSID(self)
		if err != nil {
			return err
		}
		backend = wp.NewBrowserLoopbackFixture(files, c.Engine)
		c.Backend = browserMTUFixture{backend}
		c.BrowserResolver = f.Resolver
		c.BrowserAlternativeDNS = alternativeDNS
		c.BrowserProbeRoots = f.Roots
		if err = c.SetCustomPath(statePath); err != nil {
			return err
		}
		if err = c.Local.Reload(localstrategy.Config{Version: 1, Enabled: true, User: entries}); err != nil {
			return err
		}
		c.Engine.SetRelay("VPS-01", pool)
		c.Start()
		if err = waitNetwork(); err != nil {
			return err
		}
		if err = c.RestoreBrowserTransport(); err != nil {
			return err
		}
		post = startBrowserEvidencePoll(ctx, c)
		fresh, e := c.Handle(ctx, "browser.prepare", raw)
		if e != nil {
			return e
		}
		f.HealthURL = fresh.(map[string]any)["health_url"].(string)
		_, err = c.Handle(ctx, "optimize", []byte(`{"enabled":true}`))
		return err
	})
	if err != nil {
		view, _ := c.Handle(ctx, "browser.status", nil)
		captured, _ := backend.DiagnosticsScoped(wp.EvidenceQuery{Destination: f.Destination().String(), Domain: "www.youtube.com"})
		captureRaw, _ := json.Marshal(captured)
		native, _ := c.Handle(ctx, "browser.native.status", nil)
		nativeRaw, _ := json.Marshal(native)
		traceMu.Lock()
		traceRaw, _ := json.Marshal(trace)
		traceMu.Unlock()
		t.Fatal("controlled Chrome HTTP(S) failed", err, out, view, "native status", string(nativeRaw), "native packet trace", string(traceRaw), "YouTube capture", string(captureRaw))
	}
	// Wait for actual Chrome sockets to close so forwarded byte counters are final.
	var snap browserproxy.Snapshot
	until := time.Now().Add(3 * time.Second)
	for {
		view, e := c.Handle(ctx, "browser.status", nil)
		if e != nil {
			t.Fatal(e)
		}
		raw, err := json.Marshal(view)
		if err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(raw, &snap); err != nil {
			t.Fatal(err)
		}
		active := false
		for _, r := range snap.Records {
			active = active || r.Active
		}
		if !active || time.Now().After(until) {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if f.PoisonedDNSAnswers.Load() == 0 || f.AlternativeDNSQueries.Load() == 0 {
		t.Fatal("missing poisoned system DNS/real relay DNS recovery coverage")
	}
	if f.ECHClientHellos.Load() == 0 {
		t.Fatal("real sandboxed Chrome ECH/GREASE coverage missing")
	}
	if f.ProtectedDirectAttempts.Load() != 0 {
		t.Fatal("protected TLS attempted DIRECT during activation/outage/restart", f.ProtectedDirectAttempts.Load())
	}
	later, err := post.finish()
	if err != nil {
		t.Fatal("incomplete browser proof", err)
	}
	found := map[string]bool{}
	for _, r := range append(earlier, later...) {
		switch r.Domain {
		case "web.telegram.org":
			if r.Plan.Policy.Action != flowpolicy.RelayRequired || r.Plan.Policy.Fallback != flowpolicy.Required || r.Plan.Probe != "DNS_RELAY_HTTP_VERIFIED" || r.Plan.DNSRecovery == nil || !r.Plan.DNSRecovery.Verified || r.Plan.Destination != f.Destination() || r.Sent == 0 || r.Received == 0 {
				t.Fatal("poisoned DNS recovery not proved", r)
			}
			found[r.Domain] = true
		case "blocked.example":
			// Unknown AUTO must be allowed to try DIRECT first. Speculative
			// unconfirmed local attempts are NOT an OpenAI leak or HTTP PASS:
			// the target rejects their TLS before any HTTP, and every stage's
			// browser nonce already requires a relay-source HTTP response.
			if r.Plan.Policy.Action != flowpolicy.RelayRequired {
				if r.Plan.HTTPStatus >= 200 && r.Plan.HTTPStatus < 400 {
					t.Fatal("blocked origin falsely confirmed local", r)
				}
				continue
			}
			if r.Plan.Policy.Fallback != flowpolicy.Required || r.Sent == 0 || r.Received == 0 {
				t.Fatal("learned relay response missing", r)
			}
			found[r.Domain] = true
		case "chatgpt.com":
			if r.Plan.Policy.Action != flowpolicy.RelayRequired || r.Plan.Policy.Fallback != flowpolicy.Required || r.Sent == 0 || r.Received == 0 {
				t.Fatal("protected route or response missing", r)
			}
			found[r.Domain] = true
		case "www.youtube.com":
			if r.Plan.Policy.Action != flowpolicy.DirectPlus || !r.DirectPlusApplied || r.Sent == 0 || r.Received == 0 {
				proof, _ := backend.DiagnosticsScoped(wp.EvidenceQuery{Destination: f.Destination().String()})
				rawProof, _ := json.Marshal(proof)
				t.Fatal("YouTube local route missing", r, string(rawProof))
			}
			found[r.Domain] = true
		case "ordinary.example", "vk.com", "music.yandex.ru", "langame.ru", "www.twitch.tv":
			if r.Plan.Policy.Action != flowpolicy.Direct || r.Sent == 0 || r.Received == 0 {
				t.Fatal("ordinary origin borrowed another route", r)
			}
			found[r.Domain] = true
		}
	}
	if len(found) != len(browserfixture.Domains) {
		t.Fatal("missing CONNECT origins; possible HTTP/2 pooling", found)
	}
	evidence, err := backend.DiagnosticsScoped(wp.EvidenceQuery{Destination: f.Destination().String()})
	if err != nil {
		t.Fatal(err)
	}
	if evidence.EvidenceLost || evidence.Truncated {
		t.Fatal("incomplete native transform proof")
	}
	applied := false
	for _, flow := range evidence.Flows {
		if flow.Domain == "www.youtube.com" && flow.Counters.DirectPlus > 0 && flow.Counters.DirectPlusBytes > 0 && flow.Counters.RelayedBytes == 0 {
			applied = true
		}
		if protected := flow.Domain == "chatgpt.com"; protected && flow.Counters.DirectBytes > 0 {
			t.Fatal("protected native DIRECT leak", flow)
		}
	}
	if !applied {
		t.Fatal("Chrome HTTP success without actual native DIRECT+ transform is NOT a PASS", evidence)
	}
	if server.Metrics.TCPConnections.Load() < 2 || server.Metrics.RXBytes.Load() == 0 {
		t.Fatal("real authenticated relay not used")
	}
	t.Log("PASS: same Chrome simultaneous controlled HTTPS+HTTP2: protected RELAY_REQUIRED, YouTube native disorder with modified packets, ordinary DIRECT, blocked unknown -> real relay; no production VPS touched")
}

// Loopback's jumbo MSS can emit a complete modern Chrome ClientHello in one
// >1500-byte packet, outside the production engine's explicit packet bound.
// This fixture models ordinary Internet MTU using actual bounded socket writes;
// the unchanged WinDivert engine still captures/reassembles/transforms every
// packet, and acceptance requires its real modified-packet counters. No TLS
// feature or cipher is disabled, and no production MTU/route is modified.
type browserMTUFixture struct{ *wp.WinDivertBackend }

func (b browserMTUFixture) OpenBrowserLocalTCP(ctx context.Context, id wp.ProcessIdentity, src, dst netip.AddrPort, d wp.Decision) (net.Conn, error) {
	c, e := b.WinDivertBackend.OpenBrowserLocalTCP(ctx, id, src, dst, d)
	if e != nil {
		return nil, e
	}
	return browserMTUConn{c}, nil
}

type browserMTUConn struct{ net.Conn }

func (c browserMTUConn) Write(p []byte) (int, error) {
	total := 0
	for len(p) > 0 {
		size := len(p)
		if size > 1000 {
			size = 1000
		}
		n, e := c.Conn.Write(p[:size])
		total += n
		if e != nil {
			return total, e
		}
		if n != size {
			return total, io.ErrShortWrite
		}
		p = p[size:]
	}
	return total, nil
}
func (c browserMTUConn) CloseWrite() error {
	if v, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return v.CloseWrite()
	}
	return nil
}

// Exercise the helper without Administrator membership or optional privileges;
// only the parent requires elevation to load the signed capture driver.
func restrictedRecoveryToken(t *testing.T) windows.Token {
	t.Helper()
	var token windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_QUERY|windows.TOKEN_DUPLICATE|windows.TOKEN_ASSIGN_PRIMARY, &token); err != nil {
		t.Fatal(err)
	}
	defer token.Close()
	admin, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		t.Fatal(err)
	}
	disabled := windows.SIDAndAttributes{Sid: admin}
	var restricted windows.Token
	result, _, callErr := windows.NewLazySystemDLL("advapi32.dll").NewProc("CreateRestrictedToken").Call(uintptr(token), 1, 1, uintptr(unsafe.Pointer(&disabled)), 0, 0, 0, 0, uintptr(unsafe.Pointer(&restricted)))
	if result == 0 {
		t.Fatal("restricted owner token", callErr)
	}
	return restricted
}

// browser.status stays below 64 KiB and drops the oldest records first, so
// unrelated Chrome background requests can push controlled evidence out of any
// single snapshot. The poll reads the public IPC continuously and requires an
// unbroken record ID sequence instead of one untruncated snapshot.
type browserEvidencePoll struct {
	ctx     context.Context
	c       *cs.Controller
	mu      sync.Mutex
	records map[uint64]browserproxy.Record
	newest  uint64
	err     error
	stop    chan struct{}
	done    chan struct{}
}

func startBrowserEvidencePoll(ctx context.Context, c *cs.Controller) *browserEvidencePoll {
	p := &browserEvidencePoll{ctx: ctx, c: c, records: map[uint64]browserproxy.Record{}, stop: make(chan struct{}), done: make(chan struct{})}
	go func() {
		defer close(p.done)
		for p.collect() == nil {
			select {
			case <-p.stop:
				return
			case <-ctx.Done():
				return
			case <-time.After(100 * time.Millisecond):
			}
		}
	}()
	return p
}

func (p *browserEvidencePoll) collect() error {
	view, e := p.c.Handle(p.ctx, "browser.status", nil)
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.err != nil {
		return p.err
	}
	if e == nil {
		e = p.mergeLocked(view)
	}
	p.err = e
	return e
}

func (p *browserEvidencePoll) mergeLocked(view any) error {
	// Exercise the public IPC JSON contract, not the controller's private Go
	// wrapper type (status now also contains bounded cache/usage diagnostics).
	raw, err := json.Marshal(view)
	if err != nil {
		return err
	}
	var snapshot browserproxy.Snapshot
	if err = json.Unmarshal(raw, &snapshot); err != nil {
		return err
	}
	if snapshot.Lost != 0 {
		return fmt.Errorf("browser evidence evicted: lost=%d", snapshot.Lost)
	}
	oldest := uint64(0)
	for _, r := range snapshot.Records {
		if oldest == 0 || r.ID < oldest {
			oldest = r.ID
		}
	}
	if oldest > p.newest+1 {
		return fmt.Errorf("browser evidence gap: records %d..%d never observed", p.newest+1, oldest-1)
	}
	for _, r := range snapshot.Records {
		p.records[r.ID] = r
		if r.ID > p.newest {
			p.newest = r.ID
		}
	}
	return nil
}

// check reports the first gap or loss without stopping the poll.
func (p *browserEvidencePoll) check() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.err
}

// finish stops polling, merges one final snapshot and returns the latest state
// of every record observed.
func (p *browserEvidencePoll) finish() ([]browserproxy.Record, error) {
	select {
	case <-p.stop:
	default:
		close(p.stop)
	}
	<-p.done
	if e := p.collect(); e != nil {
		return nil, e
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	out := make([]browserproxy.Record, 0, len(p.records))
	for _, r := range p.records {
		out = append(out, r)
	}
	return out, nil
}
