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
	"strings"
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
