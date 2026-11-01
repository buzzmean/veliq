//go:build windows

package clientservice

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/buzzmean/neexitlag/core/browserproxy"
	"github.com/buzzmean/neexitlag/core/profiles"
	wp "github.com/buzzmean/neexitlag/platform/windows"
	"golang.org/x/net/dns/dnsmessage"
	"golang.org/x/net/websocket"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func continuityResolver(t *testing.T, addresses ...[4]byte) *net.Resolver {
	answer := [4]byte{127, 0, 0, 1}
	if len(addresses) > 0 {
		answer = addresses[0]
	}
	t.Helper()
	dns, e := net.ListenPacket("udp4", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { dns.Close() })
	go func() {
		buffer := make([]byte, 2048)
		for {
			n, peer, e := dns.ReadFrom(buffer)
			if e != nil {
				return
			}
			var q dnsmessage.Message
			if q.Unpack(buffer[:n]) != nil || len(q.Questions) != 1 {
				continue
			}
			question := q.Questions[0]
			response := dnsmessage.Message{Header: dnsmessage.Header{ID: q.Header.ID, Response: true, Authoritative: true, RecursionAvailable: true}, Questions: q.Questions}
			if question.Type == dnsmessage.TypeA {
				response.Answers = []dnsmessage.Resource{{Header: dnsmessage.ResourceHeader{Name: question.Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 30}, Body: &dnsmessage.AResource{A: answer}}}
			}
			raw, e := response.Pack()
			if e == nil {
				dns.WriteTo(raw, peer)
			}
		}
	}()
	return &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "udp4", dns.LocalAddr().String())
	}}
}

func TestWindowsBrowserDisablePolicyContinuity(t *testing.T) {
	if os.Getenv("NEEXITLAG_TEST_BROWSER_DISABLE") != "1" {
		t.Skip("disposable Windows browser VM only")
	}
	for _, edge := range []bool{false, true} {
		t.Run(map[bool]string{false: "Chrome", true: "Edge"}[edge], func(t *testing.T) {
			vendor, name, exeName := "Google", "Chrome", "chrome.exe"
			if edge {
				vendor, name, exeName = "Microsoft", "Edge", "msedge.exe"
			}
			executable := ""
			for _, root := range []string{os.Getenv("ProgramFiles"), os.Getenv("ProgramFiles(x86)"), os.Getenv("LOCALAPPDATA")} {
				p := filepath.Join(root, vendor, name, "Application", exeName)
				if _, e := os.Stat(p); e == nil {
					executable = p
					break
				}
			}
			if executable == "" {
				t.Fatal("real browser required")
			}
			keyPath := `Software\Policies\` + vendor + `\` + name
			key, _, err := registry.CreateKey(registry.CURRENT_USER, keyPath, registry.QUERY_VALUE|registry.SET_VALUE)
			if err != nil {
				t.Fatal(err)
			}
			defer key.Close()
			for _, field := range []string{"ProxySettings", "ProxyMode", "ProxyPacUrl", "ProxyServer", "ProxyBypassList", "ProxyPacMandatory"} {
				if _, _, e := key.GetValue(field, nil); !errors.Is(e, registry.ErrNotExist) {
					t.Fatal("foreign policy preserved; requires disposable VM", field)
				}
			}
			user, err := windows.GetCurrentProcessToken().GetTokenUser()
			if err != nil {
				t.Fatal(err)
			}
			sid := user.User.Sid.String()
			c := New(context.Background())
			defer c.Close()
			c.BrowserOwnerSID = sid
			c.customPath = filepath.Join(t.TempDir(), "profiles.json")
			c.BrowserResolver = continuityResolver(t)
			backend := &continuityBackend{controller: c}
			backend.active.Store(true)
			c.Backend = backend
			c.enabled = true
			c.settings.Automatic = true
			p := profiles.Profile{ID: "browser", Name: name, Executables: []string{executable}, Mode: profiles.Auto, BrowserTransport: "native"}
			if edge {
				p.AppPreset = "edge-sites"
			}
			if err = c.Profiles.Upsert(p); err != nil {
				t.Fatal(err)
			}
			origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Connection", "close")
				w.Header().Set("Cache-Control", "no-store")
				fmt.Fprint(w, "VELIQ continuity "+r.URL.Path)
			}))
			defer origin.Close()
			authorize := c.browserOwner
			if edge {
				authorize = c.edgeOwner
			}
			proxy, err := browserproxy.Listen(c.ctx, browserproxy.Config{Authorize: authorize, Plan: c.browserPlan, Open: c.browserOpen, OpenPlan: c.browserOpenPlan})
			if err != nil {
				t.Fatal(err)
			}
			args, err := browserproxy.ChromeArgumentsWithRecovery(proxy.Address(), t.TempDir(), nil, false, "127.0.0.1:1")
			if err != nil {
				t.Fatal(err)
			}
			pac, err := browserproxy.AvailabilityPAC(strings.TrimPrefix(args[1], "--proxy-pac-url="))
			if err != nil {
				t.Fatal(err)
			}
			value := edgePolicyValue(pac)
			remove := wp.ChromeProxyPolicyRemove
			write := wp.ChromeProxyPolicyWrite
			if edge {
				remove = wp.EdgeProxyPolicyRemove
				write = wp.EdgeProxyPolicyWrite
				e := c.edgeLocked()
				e.server = proxy
				e.saved.Address = proxy.Address()
				e.saved.ExpectedPAC = pac
				e.saved.Owned = []string{value}
			} else {
				c.browser.server = proxy
				c.browser.address = proxy.Address()
				c.browser.expectedPAC = pac
				c.browser.silent.Owned = []string{value}
			}
			defer func() {
				if e := remove(sid, []string{value}); e != nil {
					t.Error(e)
				}
			}()
			if err = write(sid, nil, value); err != nil {
				t.Fatal(err)
			}
			// The disposable browser starts with real policy, then stays running through
			// disable and host stop. No proxy flags, TLS exceptions or manual policy reload.
			dir := t.TempDir()
			cmd := exec.Command(executable, "--headless=new", "--no-first-run", "--no-default-browser-check", "--disable-background-networking", "--remote-debugging-port=0", "--remote-allow-origins=http://localhost", "--host-resolver-rules=MAP veliq-continuity.test 127.0.0.1", "--user-data-dir="+dir, "about:blank")
			if err = cmd.Start(); err != nil {
				t.Fatal(err)
			}
			defer func() { cmd.Process.Kill(); cmd.Wait() }() // fixture process only
			identity, err := wp.NewDiscovery().Lookup(uint32(cmd.Process.Pid))
			if err != nil {
				t.Fatal(err)
			}
			httpClient := &http.Client{Transport: &http.Transport{Proxy: nil}, Timeout: 2 * time.Second}
			defer httpClient.CloseIdleConnections()
			var wsURL string
			until := time.Now().Add(15 * time.Second)
			for time.Now().Before(until) {
				raw, e := os.ReadFile(filepath.Join(dir, "DevToolsActivePort"))
				if e == nil {
					port, _ := strconv.Atoi(strings.Split(string(raw), "\n")[0])
					if port > 0 {
						response, e := httpClient.Get(fmt.Sprintf("http://127.0.0.1:%d/json/list", port))
						if e == nil {
							var pages []struct {
								Type string `json:"type"`
								WS   string `json:"webSocketDebuggerUrl"`
							}
							json.NewDecoder(io.LimitReader(response.Body, 1<<20)).Decode(&pages)
							response.Body.Close()
							for _, page := range pages {
								if page.Type == "page" {
									wsURL = page.WS
									break
								}
							}
						}
					}
				}
				if wsURL != "" {
					break
				}
				time.Sleep(50 * time.Millisecond)
			}
			if wsURL == "" {
				t.Fatal("CDP_INSTRUMENTATION_UNAVAILABLE")
			}
			ws, err := websocket.Dial(wsURL, "", "http://localhost")
			if err != nil {
				t.Fatal(err)
			}
			defer ws.Close()
			ws.MaxPayloadBytes = 1 << 20
			seq := 0
			call := func(method string, params any) json.RawMessage {
				t.Helper()
				seq++
				ws.SetDeadline(time.Now().Add(5 * time.Second))
				if e := websocket.JSON.Send(ws, map[string]any{"id": seq, "method": method, "params": params}); e != nil {
					t.Fatal(e)
				}
				for i := 0; i < 512; i++ {
					var r struct {
						ID     int             `json:"id"`
						Result json.RawMessage `json:"result"`
						Error  json.RawMessage `json:"error"`
					}
					if e := websocket.JSON.Receive(ws, &r); e != nil {
						t.Fatal(e)
					}
					if r.ID == seq {
						if len(r.Error) > 0 {
							t.Fatal("CDP_COMMAND_FAILED", method)
						}
						return r.Result
					}
				}
				t.Fatal("CDP_EVENT_LIMIT")
				return nil
			}
			call("Page.enable", map[string]any{})
			port := origin.Listener.Addr().(*net.TCPAddr).Port
			visit := func(stage string) {
				t.Helper()
				path := "/" + stage
				raw := call("Page.navigate", map[string]any{"url": fmt.Sprintf("http://veliq-continuity.test:%d%s", port, path)})
				var nav struct {
					Error string `json:"errorText"`
				}
				json.Unmarshal(raw, &nav)
				if nav.Error != "" {
					t.Fatal(stage, nav.Error)
				}
				end := time.Now().Add(8 * time.Second)
				observed := false
				for time.Now().Before(end) {
					raw = call("Runtime.evaluate", map[string]any{"expression": "document.body && document.body.textContent", "returnByValue": true})
					var result struct {
						Result struct {
							Value string `json:"value"`
						} `json:"result"`
					}
					if json.Unmarshal(raw, &result) == nil && result.Result.Value == "VELIQ continuity "+path {
						observed = true
						break
					}
					time.Sleep(50 * time.Millisecond)
				}
				if !observed {
					t.Fatal("HTTP_BODY_NOT_OBSERVED", stage)
				}
				after, e := wp.NewDiscovery().Lookup(identity.PID)
				if e != nil || after.CreationTime != identity.CreationTime {
					t.Fatal("BROWSER_RESTARTED", stage)
				}
			}
			visit("active")
			if backend.nativeCalls.Load() == 0 {
				t.Fatal("real policy did not reach native-dispatch seam")
			}
			logTrace := func(stage string) continuityTrace {
				t.Helper()
				trace := backend.trace()
				raw, _ := json.Marshal(trace)
				t.Logf("stage=%s proxy_active=%d native=%s", stage, proxy.Snapshot().ActiveConnections, raw)
				return trace
			}
			checkDisabled := func(stage string) {
				t.Helper()
				trace := logTrace(stage)
				if trace.StartedWhileDisabled != 0 || trace.StartedAfterDisable != 0 {
					t.Errorf("disabled browser re-entered native backend: off_entry=%d after_disable_complete=%d", trace.StartedWhileDisabled, trace.StartedAfterDisable)
				}
			}
			backend.mark("disable_requested")
			logTrace("disable_requested")
			if _, err = c.Handle(context.Background(), "optimize", []byte(`{"enabled":false}`)); err != nil {
				t.Fatal(err)
			}
			backend.mark("disable_complete")
			checkDisabled("disable_complete")
			if _, _, err = key.GetStringValue("ProxySettings"); !errors.Is(err, registry.ErrNotExist) {
				t.Fatal("owned policy retained", err)
			}
			proxy.CloseConnections() // fixture forces NEW sockets; never rely on old keepalive/preconnect
			visit("disabled")
			checkDisabled("disabled_page_loaded")
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			if err = c.CloseForHost(ctx); err != nil {
				t.Fatal(err)
			}
			if proxy.Snapshot().Listening {
				t.Fatal("host stop retained primary")
			}
			visit("host-stopped")
			checkDisabled("host_stopped_page_loaded")
			if !t.Failed() {
				t.Log("PASS controlled real browser HTTP body, real user policy removal, PID/birth unchanged, stopped native backend not used; NOT Internet/WinDivert/SCM runtime proof")
			}
		})
	}
}
