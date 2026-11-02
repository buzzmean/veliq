//go:build windows

package clientservice

import (
	"context"
	"github.com/buzzmean/neexitlag/core/browserproxy"
	"github.com/buzzmean/neexitlag/core/profiles"
	wp "github.com/buzzmean/neexitlag/platform/windows"
	"golang.org/x/sys/windows"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestWindowsOwnerAuthorityWorkerAndOtherApplications(t *testing.T) {
	if os.Getenv("VELIQ_TEST_AUTHORITY_RUNTIME") != "1" {
		t.Skip("isolated Windows owner authority acceptance")
	}
	helper := os.Getenv("VELIQ_TEST_OWNER_WORKER")
	if helper == "" {
		t.Fatal("compiled service worker required")
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal("owner token unavailable")
	}
	sid := user.User.Sid.String()
	exchange := func(ctx context.Context, q wp.OwnerProxyCommand) (wp.OwnerProxyState, error) {
		return exchangeOwnerProxyWithBinary(ctx, q, helper)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	original, err := exchange(ctx, wp.OwnerProxyCommand{Owner: sid})
	if err != nil {
		t.Fatal("real owner query", err)
	}
	if _, err := exchange(ctx, wp.OwnerProxyCommand{Owner: "S-1-5-18"}); err == nil {
		t.Fatal("SYSTEM user proxy accepted")
	}
	if _, err := exchange(ctx, wp.OwnerProxyCommand{Owner: "S-1-5-21-1-2-3-1001"}); err == nil {
		t.Fatal("another owner accepted")
	}
	if !freeOwnerProxy(original) {
		t.Fatal("foreign proxy preserved; disposable clean VM required")
	}
	c := New(context.Background())
	t.Cleanup(c.Close)
	c.BrowserOwnerSID = sid
	c.enabled = true
	c.selfExecutable = helper // The real service binary differs from this client process.
	server, err := browserproxy.Listen(c.ctx, browserproxy.Config{RequireClientHelloReplay: true, Authorize: c.authorityOwner, Plan: c.authorityPlan, Open: c.authorityOpen, OpenPlan: c.authorityOpenPlan})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { server.Close() })
	path := filepath.Join(t.TempDir(), "owner-proxy.json")
	if err := acquireOwnerProxyState(ctx, path, sid, authorityFixedState(server.Address()), exchange); err != nil {
		t.Fatal("real acquire", err)
	}
	t.Cleanup(func() {
		cleanup, stop := context.WithTimeout(context.Background(), 10*time.Second)
		defer stop()
		if err := releaseOwnerProxy(cleanup, path, sid, exchange); err != nil {
			t.Error("real conditional restore", err)
		}
		actual, err := exchange(cleanup, wp.OwnerProxyCommand{Owner: sid})
		if err != nil || actual != original {
			t.Error("complete original proxy not restored")
		}
	})
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "owner application direct body") }))
	defer target.Close()
	proxyURL, _ := url.Parse("http://" + server.Address())
	transport := &http.Transport{Proxy: http.ProxyURL(proxyURL)}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second}
	response, err := client.Get(target.URL + "/unselected")
	if err != nil {
		t.Fatal("unselected application lost connectivity", err)
	}
	body, err := io.ReadAll(response.Body)
	response.Body.Close()
	if err != nil || string(body) != "owner application direct body" {
		t.Fatal("unselected body missing")
	}
	transport.CloseIdleConnections()
	self, err := wp.NewDiscovery().Lookup(uint32(os.Getpid()))
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Profiles.Upsert(profiles.Profile{ID: "other-app-block", Name: "other app block", Executables: []string{self.Path}, Mode: profiles.Block, Custom: true}); err != nil {
		t.Fatal(err)
	}
	response, err = client.Get(target.URL + "/selected-block")
	if err == nil {
		defer response.Body.Close()
		if response.StatusCode < 400 {
			t.Fatal("other application's BLOCK policy bypassed")
		}
	}
	for _, record := range server.Snapshot().Records {
		if record.Owner.PID != self.PID || record.Owner.Birth != self.CreationTime {
			t.Fatal("other application attribution missing")
		}
	}
	t.Log("OWNER_AUTHORITY_WORKER real_primary_owner=true wrong_owner_refused=true unselected_body=true selected_block_preserved=true")
	// Foreign change after installation is refused by the product. The fixture
	// restores only its own explicitly known temporary value on this disposable VM.
	installed, err := exchange(ctx, wp.OwnerProxyCommand{Owner: sid})
	if err != nil {
		t.Fatal(err)
	}
	foreign := installed
	foreign.PAC = "https://foreign-proxy.invalid/fixture.pac"
	if _, err := exchange(ctx, wp.OwnerProxyCommand{Owner: sid, Expected: &installed, Desired: &foreign}); err != nil {
		t.Fatal("fixture foreign change", err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		current, err := exchange(ctx, wp.OwnerProxyCommand{Owner: sid})
		if err == nil && current == foreign {
			_, err = exchange(ctx, wp.OwnerProxyCommand{Owner: sid, Expected: &foreign, Desired: &installed})
		}
		if err != nil {
			t.Error("fixture foreign value cleanup", err)
		}
	})
	if err := releaseOwnerProxy(ctx, path, sid, exchange); err == nil || !strings.Contains(err.Error(), "FOREIGN_PRESERVED") {
		t.Error("foreign proxy was not refused")
	}
	actual, err := exchange(ctx, wp.OwnerProxyCommand{Owner: sid})
	if err != nil || actual != foreign {
		t.Error("foreign proxy overwritten")
	}
	if _, err := exchange(ctx, wp.OwnerProxyCommand{Owner: sid, Expected: &foreign, Desired: &installed}); err != nil {
		t.Fatal("fixture foreign value cleanup", err)
	}
}

// Capture capability is the only simulated component in this lifecycle case.
// The owner worker, Windows proxy, sockets and Controller.Start maintenance are
// real. Separate Chromium/pinned-driver cases verify TLS authority isolation.
func TestWindowsAuthorityControllerStartAndCrashGuard(t *testing.T) {
	if os.Getenv("VELIQ_TEST_AUTHORITY_RUNTIME") != "1" {
		t.Skip("isolated owner startup lifecycle")
	}
	helper := os.Getenv("VELIQ_TEST_OWNER_WORKER")
	if helper == "" {
		t.Fatal("compiled service worker required")
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal("owner token unavailable")
	}
	sid := user.User.Sid.String()
	exchange := func(ctx context.Context, q wp.OwnerProxyCommand) (wp.OwnerProxyState, error) {
		return exchangeOwnerProxyWithBinary(ctx, q, helper)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	original, err := exchange(ctx, wp.OwnerProxyCommand{Owner: sid})
	if err != nil || !freeOwnerProxy(original) {
		t.Fatal("disposable clean owner proxy required")
	}
	statePath := filepath.Join(t.TempDir(), "profiles.json")
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	profile := profiles.Profile{ID: "owner-controller-lifecycle", Name: "Owner controller lifecycle", Mode: profiles.Auto, BrowserTransport: "native", Custom: true, Executables: []string{self, `C:\IsolatedFixture\chrome.exe`}}
	configure := func(c *Controller) {
		c.BrowserOwnerSID = sid
		c.customPath = statePath
		c.Profiles.Upsert(profile)
		c.browser.authority.exchange = exchange
		c.BrowserResolver = continuityResolver(t, [4]byte{127, 0, 0, 1})
	}
	seed := New(context.Background())
	configure(seed)
	backend := &nativeBackendFixture{}
	backend.ready = true
	seed.Backend = backend
	seed.enabled = true
	seed.retryBrowserAuthority(true)
	if !seed.authorityStatus().Applied {
		seed.Close()
		t.Fatal("owned proxy seed unavailable", seed.authorityStatus().Reason)
	}
	installed, err := exchange(ctx, wp.OwnerProxyCommand{Owner: sid})
	if err != nil {
		seed.Close()
		t.Fatal(err)
	}
	seed.Close() // Simulated process crash: retain journal/settings, close sockets.
	c := New(context.Background())
	configure(c)
	t.Cleanup(c.Close)
	c.activation.networkBlocked.Store(true)
	if err := c.RestoreOwnerAuthorityListener(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := c.releaseBrowserAuthority(); err != nil {
			t.Error("startup fixture restore", err)
		}
	})
	c.Start()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		c.browser.authority.mu.Lock()
		checked := c.browser.authority.checked
		c.browser.authority.mu.Unlock()
		if !checked.IsZero() {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	actual, err := exchange(ctx, wp.OwnerProxyCommand{Owner: sid})
	if err != nil || actual != installed {
		t.Fatal("Controller.Start withdrew the guard while activation was pending")
	}
	var requests atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		io.WriteString(w, "startup direct body")
	}))
	defer target.Close()
	endpoint, _ := url.Parse(target.URL)
	port, _ := strconv.Atoi(endpoint.Port())
	proxyURL, _ := url.Parse("http://" + c.browser.authority.server.Address())
	transport := &http.Transport{Proxy: http.ProxyURL(proxyURL)}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second}
	response, err := client.Get("http://ordinary.example:" + strconv.Itoa(port) + "/ordinary")
	if err != nil {
		t.Fatal("ordinary startup availability", err)
	}
	body, err := io.ReadAll(response.Body)
	response.Body.Close()
	if err != nil || string(body) != "startup direct body" {
		t.Fatal("ordinary startup body missing")
	}
	response, err = client.Get("http://chatgpt.com:" + strconv.Itoa(port) + "/protected")
	if err == nil {
		response.Body.Close()
		if response.StatusCode < 400 {
			t.Fatal("protected startup authority escaped")
		}
	}
	if requests.Load() != 1 {
		t.Fatal("protected startup request reached origin")
	}
	if _, err := c.Handle(ctx, "optimize", []byte(`{"enabled":false}`)); err != nil {
		t.Fatal("deliberate OFF", err)
	}
	restored, err := exchange(ctx, wp.OwnerProxyCommand{Owner: sid})
	if err != nil || restored != original {
		t.Fatal("deliberate OFF did not restore the full original")
	}
	t.Log("OWNER_AUTHORITY_LIFECYCLE controller_start=true pending_activation_guard_retained=true exact_port_rebound=true ordinary_body=true protected_origin_requests=0 deliberate_off_restored=true capture_capability=fixture")
}
