//go:build windows

package clientservice

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/buzzmean/neexitlag/core/flowpolicy"
	"github.com/buzzmean/neexitlag/core/profiles"
	"github.com/buzzmean/neexitlag/core/security"
	"github.com/buzzmean/neexitlag/core/transport"
	wp "github.com/buzzmean/neexitlag/platform/windows"
	"github.com/buzzmean/neexitlag/services/relay"
	"github.com/buzzmean/neexitlag/tools/labcert"
	"golang.org/x/net/websocket"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// The only simulated part is privileged packet reflection into this TCP accept.
// Actual Chrome/Edge, PID/SID socket ownership, Host parsing, native controller,
// mTLS+one-shot ticket QUIC relay, HTTP body and relay source are real Windows.
// This is NOT WinDivert/SCM/Internet acceptance and never writes browser policy.
func TestWindowsNativeBrowserStartsBeforeControllerWithoutPAC(t *testing.T) {
	if os.Getenv("NEEXITLAG_TEST_NATIVE_BROWSER") != "1" {
		t.Skip("disposable native Windows browser fixture only")
	}
	runNativeBrowserHotAttachFixture(t, false)
}

func runNativeBrowserHotAttachFixture(t *testing.T, driver bool) {
	for _, edge := range []bool{false, true} {
		t.Run(map[bool]string{false: "Chrome", true: "Edge"}[edge], func(t *testing.T) {
			vendor, name, exe := "Google", "Chrome", "chrome.exe"
			if edge {
				vendor, name, exe = "Microsoft", "Edge", "msedge.exe"
			}
			for _, brand := range []string{`Google\Chrome`, `Microsoft\Edge`} {
				k, e := registry.OpenKey(registry.CURRENT_USER, `Software\Policies\`+brand, registry.QUERY_VALUE)
				if e == nil {
					defer k.Close()
					for _, field := range []string{"ProxySettings", "ProxyServer", "ProxyMode", "ProxyPacUrl"} {
						if _, _, err := k.GetValue(field, nil); !errors.Is(err, registry.ErrNotExist) {
							t.Fatal("foreign policy preserved; disposable VM required", field)
						}
					}
				} else if !errors.Is(e, registry.ErrNotExist) {
					t.Fatal(e)
				}
			}
			executable := ""
			for _, root := range []string{os.Getenv("ProgramFiles"), os.Getenv("ProgramFiles(x86)"), os.Getenv("LOCALAPPDATA")} {
				p := filepath.Join(root, vendor, name, "Application", exe)
				if _, e := os.Stat(p); e == nil {
					executable = p
					break
				}
			}
			if executable == "" {
				t.Fatal("real browser required")
			}
			ingress, e := net.Listen("tcp4", "127.0.0.1:0")
			if e != nil {
				t.Fatal(e)
			}
			t.Cleanup(func() { ingress.Close() })
			port := ingress.Addr().(*net.TCPAddr).Port
			origin, e := net.Listen("tcp4", fmt.Sprintf("127.0.0.2:%d", port))
			if e != nil {
				t.Fatal(e)
			}
			target := origin.Addr().(*net.TCPAddr).AddrPort()
			var accepted, requested atomic.Uint64
			t.Cleanup(func() {
				if t.Failed() {
					t.Logf("NATIVE_FIXTURE_TRAFFIC driver=%t ingress_accepts=%d origin_requests=%d", driver, accepted.Load(), requested.Load())
				}
			})
			web := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requested.Add(1)
				host, _, _ := net.SplitHostPort(r.RemoteAddr)
				w.Header().Set("Connection", "close")
				w.Header().Set("Cache-Control", "no-store")
				fmt.Fprint(w, "VELIQ continuity "+r.URL.Path+" source="+host)
			})}
			go web.Serve(origin)
			t.Cleanup(func() { web.Close() })
			var current atomic.Pointer[Controller]
			go func() {
				for {
					conn, err := ingress.Accept()
					if err != nil {
						return
					}
					accepted.Add(1)
					go func() {
						defer conn.Close()
						var up net.Conn
						var hello []byte
						if c := current.Load(); c != nil {
							id, err := wp.LookupTCPPeer(conn.RemoteAddr().(*net.TCPAddr).AddrPort(), conn.LocalAddr().(*net.TCPAddr).AddrPort())
							if err != nil {
								return
							}
							tuple := wp.Tuple{Protocol: "tcp", Source: conn.RemoteAddr().(*net.TCPAddr).AddrPort(), Destination: target}
							decision := c.Classify(id, tuple)
							if decision.Block {
								return
							}
							if decision.Deferred {
								var host, reason string
								hello, host, reason = wp.ReadDeferredHello(conn)
								decision = wp.ResolveDeferredDecision(decision, host, reason)
								if decision.Block || decision.OpenDeferred == nil {
									return
								}
								up, _, err = decision.OpenDeferred(c.ctx, decision, reason)
								if err != nil || up == nil {
									return
								}
							} else if !decision.Route.Direct() {
								return
							}
						}
						if up == nil {
							up, err = net.DialTimeout("tcp", target.String(), time.Second)
							if err != nil {
								return
							}
						}
						defer up.Close()
						if len(hello) > 0 {
							if _, err = up.Write(hello); err != nil {
								return
							}
						}
						go func() {
							io.Copy(up, conn)
							if w, ok := up.(interface{ CloseWrite() error }); ok {
								w.CloseWrite()
							}
						}()
						io.Copy(conn, up)
					}()
				}
			}()
			// This real browser is already alive before New/activation/capture configuration.
			browserAddress := "127.0.0.1"
			if driver {
				ingress.Close()
				browserAddress = "192.0.2.254"
			}
			visit := startNativeFixtureBrowser(t, executable, port, browserAddress)
			visit("before-controller", "127.0.0.1")
			c := New(context.Background())
			t.Cleanup(c.Close)
			token, e := windows.GetCurrentProcessToken().GetTokenUser()
			if e != nil {
				t.Fatal(e)
			}
			c.BrowserOwnerSID = token.User.Sid.String()
			c.customPath = filepath.Join(t.TempDir(), "profiles.json")
			c.BrowserResolver = continuityResolver(t, [4]byte{127, 0, 0, 2})
			b := &nativeBackendFixture{}
			b.ready = true
			c.Backend = b
			if driver {
				raw, e := os.ReadFile(filepath.Join(os.Getenv("NEEXITLAG_TEST_DRIVER_DIR"), "pins.json"))
				if e != nil {
					t.Fatal(e)
				}
				var files wp.DriverFiles
				if e = json.Unmarshal(raw, &files); e != nil {
					t.Fatal(e)
				}
				files.Directory = os.Getenv("NEEXITLAG_TEST_DRIVER_DIR")
				real := wp.NewWinDivert(files, c.Engine)
				c.Backend = real
				if e = real.Start(c.ctx, c.Classify); e != nil {
					t.Fatal("actual WinDivert Start", e)
				}
				t.Cleanup(func() { real.Stop() })
			}
			c.mu.Lock()
			c.enabled = true
			c.settings.Automatic = true
			c.mu.Unlock()
			c.browser.readiness.enforced.Store(true)
			st, ct, e := labcert.Pair()
			if e != nil {
				t.Fatal(e)
			}
			pub, key, _ := ed25519.GenerateKey(rand.Reader)
			r, e := relay.Listen("127.0.0.1:0", relay.Config{TLS: st, TicketVerifier: security.NewTicketVerifier(map[string]ed25519.PublicKey{"test": pub}, "VPS-01"), Allow: []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}, Acceptance: &relay.AcceptanceConfig{LeaseDuration: 2 * time.Minute, OutboundSource: netip.MustParseAddr("127.0.0.3")}})
			if e != nil {
				t.Fatal(e)
			}
			t.Cleanup(func() { r.Close() })
			peer := ct.Certificates[0].PrivateKey.(ed25519.PrivateKey).Public().(ed25519.PublicKey)
			pool, e := transport.NewPool(c.ctx, transport.DefaultPoolConfig(), func(ctx context.Context) (*transport.Client, error) {
				id, _ := security.NewID()
				now := time.Now()
				ticket, err := security.Sign("ticket", "test", key, security.Ticket{ID: id, DeviceID: "native-fixture", DeviceKey: security.Fingerprint(peer), RelayID: "VPS-01", IssuedAt: now, ExpiresAt: now.Add(time.Minute)})
				if err != nil {
					return nil, err
				}
				return transport.DialWithTicket(ctx, r.Addr().String(), ct, ticket)
			})
			if e != nil {
				t.Fatal(e)
			}
			t.Cleanup(func() { pool.Close() })
			c.Engine.SetRelay("VPS-01", pool)
			p := profiles.Profile{ID: "native-browser", Name: name, Executables: []string{executable}, Mode: profiles.Auto, BrowserTransport: "native", Custom: true, Rules: []flowpolicy.Rule{{ID: "native-fixture", Protocol: "tcp", Domains: []string{"native-browser.test"}, Action: flowpolicy.RelayRequired, RelayID: "VPS-01", Fallback: flowpolicy.Required}}}
			raw, _ := json.Marshal(p)
			if _, e = c.Handle(context.Background(), "profile.set", raw); e != nil {
				t.Fatal(e)
			}
			current.Store(c)
			if driver {
				t.Cleanup(func() {
					status := c.nativeSnapshot()
					if t.Failed() {
						raw, _ := json.Marshal(status)
						t.Log("actual driver native status", string(raw))
					}
				})
			}
			visit("native-active", "127.0.0.3")
			// Тот же 5s бюджет, что у CDP-команды: ждём публикации plan, а не спим.
			proofCtx, proofCancel := context.WithTimeout(c.ctx, 5*time.Second)
			snap, proofErr := awaitNativeRouteProof(proofCtx, driver, func() (nativeBrowserSnapshot, <-chan struct{}) {
				return observeNativeRouteProof(c)
			})
			proofCancel()
			if proofErr != nil {
				t.Fatal("native route proof", proofErr)
			}
			if c.browser.server != nil || c.browser.edge != nil && c.browser.edge.server != nil {
				t.Fatal("fresh native opened PAC listener")
			}
			if _, e = c.Handle(context.Background(), "optimize", []byte(`{"enabled":false}`)); e != nil {
				t.Fatal(e)
			}
			visit("disabled", "127.0.0.1")
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			if e = c.CloseForHost(ctx); e != nil {
				t.Fatal(e)
			}
			current.Store(nil)
			visit("host-stopped", "127.0.0.1")
			if driver {
				if snap.CaptureIngress == nil || snap.CaptureIngress.TCPPackets == 0 {
					t.Fatal("no actual NETWORK captures")
				}
				if snap.CaptureIngress.NativeDeferredSYN == 0 || snap.CaptureIngress.ReflectedAccepts == 0 {
					t.Fatal("driver/owner/profile/reflection boundary missing", snap.CaptureIngress)
				}
				t.Logf("ACTUAL_DRIVER_NATIVE_ONLY_OBSERVED accepted=%d opened=%d exchanges=%d; same browser PID/birth; actual WinDivert NETWORK/SOCKET/owner/profile, authenticated relay and HTTP body; NOT Internet/SCM proof", snap.NativeOnly.Accepted, snap.NativeOnly.Opened, snap.NativeOnly.Exchanges)
			} else {
				t.Log("PASS controlled browser HTTP, no PAC, same PID/birth, authenticated relay source then DIRECT after OFF; packet reflection seam, NOT driver/SCM/ISP proof")
			}
		})
	}
}

func startNativeFixtureBrowser(t *testing.T, executable string, port int, addresses ...string) func(string, string) {
	t.Helper()
	dir := t.TempDir()
	address := "127.0.0.1"
	if len(addresses) > 0 {
		address = addresses[0]
	}
	cmd := exec.Command(executable, "--headless=new", "--no-first-run", "--no-default-browser-check", "--disable-background-networking", "--remote-debugging-port=0", "--remote-allow-origins=http://localhost", "--host-resolver-rules=MAP native-browser.test "+address, "--user-data-dir="+dir, "about:blank")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cmd.Process.Kill(); cmd.Wait() }) // fixture process only
	identity, err := wp.NewDiscovery().Lookup(uint32(cmd.Process.Pid))
	if err != nil {
		t.Fatal(err)
	}
	httpClient := &http.Client{Transport: &http.Transport{Proxy: nil}, Timeout: 2 * time.Second}
	t.Cleanup(httpClient.CloseIdleConnections)
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
	t.Cleanup(func() { ws.Close() })
	ws.MaxPayloadBytes = 1 << 20
	seq := 0
	stage := "startup"
	call := func(method string, params any) json.RawMessage {
		t.Helper()
		seq++
		started := time.Now()
		if e := ws.SetDeadline(started.Add(5 * time.Second)); e != nil {
			t.Fatalf("CDP_DEADLINE_FAILED stage=%s method=%s: %v", stage, method, e)
		}
		if e := websocket.JSON.Send(ws, map[string]any{"id": seq, "method": method, "params": params}); e != nil {
			t.Fatalf("CDP_SEND_FAILED stage=%s method=%s elapsed=%s: %v", stage, method, time.Since(started), e)
		}
		lastEvent := "none"
		for i := 0; i < 512; i++ {
			var r struct {
				ID     int             `json:"id"`
				Method string          `json:"method"`
				Result json.RawMessage `json:"result"`
				Error  json.RawMessage `json:"error"`
			}
			if e := websocket.JSON.Receive(ws, &r); e != nil {
				t.Fatalf("CDP_RECEIVE_FAILED stage=%s method=%s elapsed=%s messages=%d last_event=%s: %v", stage, method, time.Since(started), i, lastEvent, e)
			}
			// Record event names only, never page content, URLs or CDP payloads.
			if r.Method != "" {
				lastEvent = r.Method
			}
			if r.ID == seq {
				if len(r.Error) > 0 {
					t.Fatalf("CDP_COMMAND_FAILED stage=%s method=%s", stage, method)
				}
				return r.Result
			}
		}
		t.Fatalf("CDP_EVENT_LIMIT stage=%s method=%s last_event=%s", stage, method, lastEvent)
		return nil
	}
	call("Page.enable", map[string]any{})
	// port is the controlled original destination port.
	visit := func(nextStage, source string) {
		t.Helper()
		stage = nextStage
		t.Logf("NATIVE_BROWSER_STAGE stage=%s", stage)
		path := "/" + stage
		url := fmt.Sprintf("http://native-browser.test:%d%s", port, path)
		// The TEST-NET route exists only while the driver reflects it. Baseline/OFF
		// test the same live browser against the actual local origin, with no proxy.
		if address == "192.0.2.254" && stage != "native-active" {
			url = fmt.Sprintf("http://127.0.0.2:%d%s", port, path)
		}
		raw := call("Page.navigate", map[string]any{"url": url})
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
			if json.Unmarshal(raw, &result) == nil && result.Result.Value == "VELIQ continuity "+path+" source="+source {
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
	return visit
}
