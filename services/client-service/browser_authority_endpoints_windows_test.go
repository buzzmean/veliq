//go:build windows

package clientservice

import (
	"github.com/buzzmean/veliq/core/profiles"
	"golang.org/x/sys/windows"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// Disposable Windows CI only. The clients keep their cached proxy URLs for the
// whole test. Every request crosses the production owner/PID/birth/profile
// authorization and policy path, before and after replacing the controller.
func TestWindowsAuthorityEndpointsCachedClientsAcrossUpdate(t *testing.T) {
	if os.Getenv("VELIQ_TEST_AUTHORITY_RUNTIME") != "1" {
		t.Skip("isolated Windows authority acceptance")
	}
	u, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	owner := u.User.Sid.String()
	dir := t.TempDir()
	primary := endpointAddress(t)
	compat := endpointAddress(t)
	endpointLease(t, filepath.Join(dir, "browser-owner-proxy.json"), owner, primary)
	old := filepath.Join(t.TempDir(), "previous.json")
	endpointLease(t, old, owner, compat)
	if err = prepareAuthorityEndpoints(dir, owner, old); err != nil {
		t.Fatal(err)
	}
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "endpoint continuity body") }))
	defer target.Close()
	var clients []*http.Client
	for _, address := range []string{primary, compat} {
		u, _ := url.Parse("http://" + address)
		transport := &http.Transport{Proxy: http.ProxyURL(u)}
		defer transport.CloseIdleConnections()
		clients = append(clients, &http.Client{Transport: transport, Timeout: 3 * time.Second})
	}
	start := func() *Controller {
		c := endpointController(dir, owner)
		c.selfExecutable = "different-service.exe"
		c.enabled = true
		if err := c.RestoreOwnerAuthorityListener(); err != nil {
			t.Fatal(err)
		}
		return c
	}
	get := func(client *http.Client, wantOK bool) {
		t.Helper()
		response, err := client.Get(target.URL + "/cached-endpoint")
		if err != nil {
			if wantOK {
				t.Fatal(err)
			}
			return
		}
		defer response.Body.Close()
		body, _ := io.ReadAll(response.Body)
		if wantOK && (response.StatusCode != 200 || string(body) != "endpoint continuity body") {
			t.Fatalf("client exchange failed: status=%d", response.StatusCode)
		}
		if !wantOK && response.StatusCode < 400 {
			t.Fatal("foreign owner bypassed")
		}
	}
	c := start()
	for _, client := range clients {
		get(client, true)
	}
	c.Close()
	// Deliberate old-version stop removes only the reversible settings lease.
	if err = os.Remove(filepath.Join(dir, "browser-owner-proxy.json")); err != nil {
		t.Fatal(err)
	}
	c = start()
	defer c.Close()
	for _, client := range clients {
		get(client, true)
	}
	view := c.authorityStatus()
	if len(view.Listeners) != 2 {
		t.Fatal("missing primary/compatibility diagnostics")
	}
	for _, listener := range view.Listeners {
		if len(listener.Requests) == 0 || listener.Requests[0].PID != uint32(os.Getpid()) || listener.Requests[0].Birth == 0 {
			t.Fatal("real client identity not retained")
		}
	}
	// Owner mismatch fails at the same production authorization on both ports.
	c.Close()
	c = endpointController(dir, "S-1-5-21-1-2-3-1001")
	if err = c.RestoreOwnerAuthorityListener(); err == nil {
		t.Fatal("foreign installation owner restored endpoints")
	}
	c.Close()
	c = endpointController(dir, owner)
	c.selfExecutable = "different-service.exe"
	c.enabled = true
	if err = c.RestoreOwnerAuthorityListener(); err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	if err = c.Profiles.Upsert(profiles.Profile{ID: "blocked-client", Name: "Blocked client", Executables: []string{self}, Mode: profiles.Block, Custom: true}); err != nil {
		t.Fatal(err)
	}
	for _, client := range clients {
		get(client, false)
	}
}
