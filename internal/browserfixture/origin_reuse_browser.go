package browserfixture

import (
	"context"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/websocket"
)

// Explicit opt-in, isolated process/profile and a short-lived root. There are no
// certificate-error flags, browser key exports or changes to user profiles.
// Windows trust changes are allowed ONLY on a disposable Actions runner.
func (f *OriginReuse) Run(t testing.TB, chrome, address, bootstrapHost string, args []string) {
	t.Helper()
	if os.Getenv("NEEXITLAG_TEST_ORIGIN_REUSE") != "1" {
		t.Fatal("explicit origin reuse fixture opt-in required")
	}
	if bootstrapHost != ReuseLocalHost && bootstrapHost != ReuseRequiredHost {
		t.Fatal("invalid controlled bootstrap host")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Second)
	defer cancel()
	home := t.TempDir()
	rootPath := filepath.Join(home, "root.cer")
	if err := os.WriteFile(rootPath, f.RootDER, 0600); err != nil {
		t.Fatal(err)
	}
	run := func(name string, argv ...string) {
		t.Helper()
		if err := exec.CommandContext(ctx, name, argv...).Run(); err != nil {
			t.Fatalf("ephemeral trust setup %s: %v deadline=%v", name, err, ctx.Err())
		}
	}
	env := os.Environ()
	switch runtime.GOOS {
	case "windows":
		if os.Getenv("GITHUB_ACTIONS") != "true" {
			t.Fatal("trust fixture requires disposable Actions Windows VM")
		}
		// Unique generated root; delete exactly this thumbprint, never a shared CA.
		thumb := sha1.Sum(f.RootDER)
		// Current-user root import can open an interactive trust prompt. This
		// machine store exists only on the disposable Actions VM; no user PC
		// or shared trust store is supported by this explicit fixture.
		t.Log("ORIGIN_REUSE_TRUST store=disposable-machine-root begin")
		run("certutil.exe", "-addstore", "Root", rootPath)
		t.Log("ORIGIN_REUSE_TRUST store=disposable-machine-root ready")
		defer func() {
			cleanup, stop := context.WithTimeout(context.Background(), 10*time.Second)
			defer stop()
			if err := exec.CommandContext(cleanup, "certutil.exe", "-delstore", "Root", hex.EncodeToString(thumb[:])).Run(); err != nil {
				t.Error("ephemeral trust cleanup", err)
			}
		}()
	case "linux":
		db := filepath.Join(home, ".pki", "nssdb")
		if err := os.MkdirAll(db, 0700); err != nil {
			t.Fatal(err)
		}
		run("certutil", "-N", "--empty-password", "-d", "sql:"+db)
		run("certutil", "-A", "-d", "sql:"+db, "-n", "ephemeral-reuse", "-t", "C,,", "-i", rootPath)
		// Only the child process receives an isolated home/NSS store.
		env = append(env, "HOME="+home, "XDG_CONFIG_HOME="+filepath.Join(home, ".config"))
	default:
		t.Fatal("origin reuse trust fixture supports Linux and disposable Windows")
	}
	directory := filepath.Join(home, "browser")
	if err := os.Mkdir(directory, 0700); err != nil {
		t.Fatal(err)
	}
	// This preference belongs only to the new empty test profile. Chromium no
	// longer honors the old EncryptedClientHello feature flag. The endpoint
	// independently verifies that extension 0xfe0d is absent.
	if err := os.WriteFile(filepath.Join(directory, "Local State"), []byte(`{"ssl":{"ech_enabled":false}}`), 0600); err != nil {
		t.Fatal(err)
	}
	rules := []string{}
	for _, host := range []string{ReuseLocalHost, ReuseSiblingHost, ReuseRequiredHost} {
		rules = append(rules, "MAP "+host+" "+address)
	}
	// All other browser DNS fails locally. No public service/credential is used.
	rules = append(rules, "MAP * ~NOTFOUND", "EXCLUDE localhost", "EXCLUDE *.localhost")
	args = append(args, "--user-data-dir="+directory, "--headless=new", "--no-first-run", "--no-default-browser-check", "--disable-background-networking", "--disable-component-update", "--disable-sync", "--disable-default-apps", "--disable-domain-reliability", "--disable-features=MediaRouter,OptimizationHints", "--disable-dev-shm-usage", "--disable-quic", "--remote-debugging-port=0", "--remote-allow-origins=http://localhost", "--host-resolver-rules="+strings.Join(rules, ", "), "about:blank")
	if runtime.GOOS == "linux" {
		args = append(args, "--no-sandbox")
	}
	cmd := exec.CommandContext(ctx, chrome, args...)
	cmd.Env = env
	cmd.WaitDelay = 2 * time.Second
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cmd.Process.Kill(); _ = cmd.Wait() }()
	client := &http.Client{Transport: &http.Transport{Proxy: nil}, Timeout: time.Second}
	defer client.CloseIdleConnections()
	port := 0
	until := time.Now().Add(15 * time.Second)
	for time.Now().Before(until) {
		raw, err := os.ReadFile(filepath.Join(directory, "DevToolsActivePort"))
		if err == nil {
			port, _ = strconv.Atoi(strings.Split(string(raw), "\n")[0])
			if port > 0 {
				break
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	if port == 0 {
		t.Fatal("CDP readiness missing")
	}
	page, err := waitCDPPage(ctx, client, fmt.Sprintf("http://127.0.0.1:%d/json/list", port))
	if err != nil {
		t.Fatal(err)
	}
	ws, err := websocket.Dial(page, "", "http://localhost")
	if err != nil {
		t.Fatal(err)
	}
	defer ws.Close()
	ws.MaxPayloadBytes = 1 << 20
	seq := 0
	call := func(method string, params any) json.RawMessage {
		t.Helper()
		seq++
		_ = ws.SetDeadline(time.Now().Add(12 * time.Second))
		if err := websocket.JSON.Send(ws, map[string]any{"id": seq, "method": method, "params": params}); err != nil {
			t.Fatal(err)
		}
		for i := 0; i < 1024; i++ {
			var r struct {
				ID     int
				Result json.RawMessage
				Error  json.RawMessage
			}
			if err := websocket.JSON.Receive(ws, &r); err != nil {
				t.Fatal("CDP", method, err)
			}
			if r.ID == seq {
				if len(r.Error) > 0 {
					t.Fatal("CDP rejected", method)
				}
				return r.Result
			}
		}
		t.Fatal("CDP event limit")
		return nil
	}
	var version struct {
		Product         string
		ProtocolVersion string
	}
	if err = json.Unmarshal(call("Browser.getVersion", map[string]any{}), &version); err != nil {
		t.Fatal(err)
	}
	t.Logf("ORIGIN_REUSE_BROWSER product=%s cdp=%s trust=ephemeral_root certificate_errors_disabled=false", version.Product, version.ProtocolVersion)
	raw := call("Page.navigate", map[string]any{"url": f.URL(bootstrapHost, "sequence")})
	var navigation struct{ ErrorText string }
	if json.Unmarshal(raw, &navigation) != nil || navigation.ErrorText != "" {
		t.Fatalf("sequence navigation failed: %s", navigation.ErrorText)
	}
	ready := false
	for i := 0; i < 100; i++ {
		var r struct{ Result struct{ Value string } }
		_ = json.Unmarshal(call("Runtime.evaluate", map[string]any{"expression": "document.title", "returnByValue": true}), &r)
		if r.Result.Value == "ORIGIN_REUSE_READY" {
			ready = true
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if !ready {
		t.Fatal("trusted HTTPS bootstrap not observed")
	}
	for i, host := range []string{ReuseLocalHost, ReuseSiblingHost, ReuseRequiredHost, ReuseRequiredHost} {
		step := []string{"local", "sibling", "required", "required_again"}[i]
		url, _ := json.Marshal(f.URL(host, "payload") + "&step=" + step)
		expression := "fetch(" + string(url) + ",{cache:'no-store',credentials:'omit'}).then(async r=>{if(r.status!==200)throw Error('status '+r.status);return await r.text()})"
		var r struct {
			Result           struct{ Value string }
			ExceptionDetails json.RawMessage
		}
		if err := json.Unmarshal(call("Runtime.evaluate", map[string]any{"expression": expression, "awaitPromise": true, "returnByValue": true}), &r); err != nil {
			t.Fatal(err)
		}
		if len(r.ExceptionDetails) > 0 || r.Result.Value != f.Nonce+":"+step {
			t.Fatalf("browser response missing: step=%s", step)
		}
	}
}
