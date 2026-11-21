//go:build windows

package clientservice

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	wp "github.com/buzzmean/neexitlag/platform/windows"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

// Empirical policy-refresh measurement, not a launch-with-proxy fixture. Browser
// starts BEFORE registry mutation and keeps its exact PID/creation time. Only
// the disposable test profile is terminated at teardown; product never does so.
func TestSilentPACRunningChromeEdgePolicyUptake(t *testing.T) {
	if os.Getenv("NEEXITLAG_TEST_SILENT_POLICY") != "1" {
		t.Skip("disposable Windows CI only")
	}
	for _, edge := range []bool{false, true} {
		name := "Chrome"
		vendor := "Google"
		exeName := "chrome.exe"
		if edge {
			name = "Edge"
			vendor = "Microsoft"
			exeName = "msedge.exe"
		}
		t.Run(name, func(t *testing.T) {
			var executable string
			for _, root := range []string{os.Getenv("ProgramFiles"), os.Getenv("ProgramFiles(x86)"), os.Getenv("LOCALAPPDATA")} {
				p := filepath.Join(root, vendor, name, "Application", exeName)
				if _, err := os.Stat(p); err == nil {
					executable = p
					break
				}
			}
			if executable == "" {
				t.Fatal("real browser required")
			}
			path := `Software\Policies\` + vendor + `\` + name
			key, _, err := registry.CreateKey(registry.CURRENT_USER, path, registry.QUERY_VALUE|registry.SET_VALUE)
			if err != nil {
				t.Fatal(err)
			}
			defer key.Close()
			for _, n := range []string{"ProxySettings", "ProxyMode", "ProxyPacUrl", "ProxyServer", "ProxyBypassList", "ProxyPacMandatory"} {
				if _, _, e := key.GetValue(n, nil); !errors.Is(e, registry.ErrNotExist) {
					t.Fatal("refusing preexisting policy", n)
				}
			}
			defer key.DeleteValue("ProxySettings")
			self, err := wp.NewDiscovery().Lookup(uint32(os.Getpid()))
			if err != nil {
				t.Fatal(err)
			}
			sid, err := wp.ProcessUserSID(self)
			if err != nil {
				t.Fatal(err)
			}
			var requests, firstRequestNS atomic.Int64
			proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				// The fixture records actual browser-owned HTTP proxy ingress, not CDP/GUI.
				if r.URL.Hostname() != "veliq-uptake.invalid" {
					http.Error(w, "unexpected", 403)
					return
				}
				peer, e := netip.ParseAddrPort(r.RemoteAddr)
				if e != nil {
					http.Error(w, "owner", 403)
					return
				}
				local, _ := netip.ParseAddrPort(r.Context().Value(http.LocalAddrContextKey).(interface{ String() string }).String())
				owner, e := wp.LookupTCPPeer(peer, local)
				if e != nil || !strings.EqualFold(owner.Path, executable) {
					http.Error(w, "owner", 403)
					return
				}
				ownerSID, e := wp.ProcessUserSID(owner)
				if e != nil || ownerSID != sid {
					http.Error(w, "sid", 403)
					return
				}
				firstRequestNS.CompareAndSwap(0, time.Now().UnixNano())
				requests.Add(1)
				w.Header().Set("Cache-Control", "no-store")
				fmt.Fprint(w, "VELIQ policy uptake")
			}))
			defer proxy.Close()
			dir := t.TempDir()
			cmd := exec.Command(executable, "--headless=new", "--no-first-run", "--no-default-browser-check", "--disable-background-networking", "--remote-debugging-port=0", "--user-data-dir="+dir, "about:blank")
			if err = cmd.Start(); err != nil {
				t.Fatal(err)
			}
			defer func() { _ = cmd.Process.Kill(); _ = cmd.Wait() }()
			var port int
			until := time.Now().Add(10 * time.Second)
			for time.Now().Before(until) {
				raw, e := os.ReadFile(filepath.Join(dir, "DevToolsActivePort"))
				if e == nil {
					port, _ = strconv.Atoi(strings.Split(string(raw), "\n")[0])
					if port > 0 {
						break
					}
				}
				time.Sleep(100 * time.Millisecond)
			}
			if port == 0 {
				t.Fatal("already-running fixture CDP unavailable")
			}
			before, err := wp.NewDiscovery().Lookup(uint32(cmd.Process.Pid))
			if err != nil {
				t.Fatal(err)
			}
			// Mandatory inline PAC is exactly the production policy shape; no proxy launch
			// flags, no insecure TLS/cert flags, extensions, machine proxy, or restarts.
			pac := edgeClosedPACForTestProxy(strings.TrimPrefix(proxy.URL, "http://"))
			value := edgePolicyValue(pac)
			write := wp.ChromeProxyPolicyWrite
			if edge {
				write = wp.EdgeProxyPolicyWrite
			}
			at := time.Now()
			if err = write(sid, nil, value); err != nil {
				t.Fatal(err)
			}
			refresh, _, _ := windows.NewLazySystemDLL("userenv.dll").NewProc("RefreshPolicy").Call(0)
			client := &http.Client{Timeout: 2 * time.Second}
			state := "POLICY_PENDING_BROWSER_REFRESH"
			delay := int64(-1)
			for attempt := 0; attempt < 15; attempt++ {
				ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
				req, _ := http.NewRequestWithContext(ctx, http.MethodPut, fmt.Sprintf("http://127.0.0.1:%d/json/new?http://veliq-uptake.invalid/check-%d", port, attempt), nil)
				response, e := client.Do(req)
				if e == nil {
					response.Body.Close()
				}
				cancel()
				limit := time.Now().Add(2 * time.Second)
				for time.Now().Before(limit) && requests.Load() == 0 {
					time.Sleep(50 * time.Millisecond)
				}
				if requests.Load() > 0 {
					state = "PAC_REQUEST_OBSERVED"
					delay = time.Unix(0, firstRequestNS.Load()).Sub(at).Milliseconds()
					break
				}
			}
			after, err := wp.NewDiscovery().Lookup(uint32(cmd.Process.Pid))
			if err != nil {
				t.Fatal("browser exited during activation", err)
			}
			if after.PID != before.PID || after.CreationTime != before.CreationTime {
				t.Fatal("browser replaced")
			}
			t.Logf("%s state=%s apply_to_request_ms=%d requests=%d pid_unchanged=true creation_unchanged=true user_refresh_requested=%t; HTTP proxy ingress only, not Internet/TLS PASS", name, state, delay, requests.Load(), refresh != 0)
			// No assertion that a Chromium release MUST refresh live: pending is an
			// explicitly supported product state. The log is the empirical result.
		})
	}
}

func edgeClosedPACForTestProxy(address string) string {
	script := `function FindProxyForURL(url,host){if(host==='veliq-uptake.invalid')return 'PROXY ` + address + `';return 'DIRECT';}`
	return "data:application/x-ns-proxy-autoconfig;base64," + base64.StdEncoding.EncodeToString([]byte(script))
}
