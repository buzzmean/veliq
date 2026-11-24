//go:build windows

package clientservice

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/buzzmean/veliq/core/browserproxy"
	"github.com/buzzmean/veliq/core/flowpolicy"
	"github.com/buzzmean/veliq/core/profiles"
	wp "github.com/buzzmean/veliq/platform/windows"
)

func TestWindowsLanGameAuthorityPassthrough(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	c := New(ctx)
	t.Cleanup(c.Close)
	self, err := wp.NewDiscovery().Lookup(uint32(os.Getpid()))
	if err != nil {
		t.Fatal(err)
	}
	c.BrowserOwnerSID, err = wp.ProcessUserSID(self)
	if err != nil {
		t.Fatal(err)
	}
	c.isLanGameProcess = func(id wp.ProcessIdentity) bool {
		return id.PID == self.PID && id.CreationTime == self.CreationTime && id.Path == self.Path
	}
	c.enabled = true
	if err := c.Profiles.Upsert(profiles.Profile{ID: "stale-selection", Name: "Older profile", Executables: []string{self.Path}, Mode: profiles.Block, Custom: true}); err != nil {
		t.Fatal(err)
	}
	// Real Windows socket owner and user checks still apply to the proxy.
	proxy, err := browserproxy.Listen(ctx, browserproxy.Config{Authorize: c.authorityOwner, Plan: c.authorityPlan, Open: c.authorityOpen, OpenPlan: c.authorityOpenPlan})
	if err != nil {
		t.Fatal(err)
	}
	defer proxy.Close()
	fixture := func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "club online") }
	plain := httptest.NewServer(http.HandlerFunc(fixture))
	defer plain.Close()
	secure := httptest.NewTLSServer(http.HandlerFunc(fixture))
	defer secure.Close()
	proxyURL, err := url.Parse("http://" + proxy.Address())
	if err != nil {
		t.Fatal(err)
	}
	transport := secure.Client().Transport.(*http.Transport).Clone()
	transport.Proxy = http.ProxyURL(proxyURL)
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second}
	for _, target := range []string{plain.URL, secure.URL} {
		response, err := client.Get(target)
		if err != nil {
			t.Fatal(err)
		}
		body, err := io.ReadAll(response.Body)
		response.Body.Close()
		if err != nil || response.StatusCode != http.StatusOK || string(body) != "club online" {
			t.Fatalf("club exchange failed: HTTP %d, %v", response.StatusCode, err)
		}
	}
	q := browserproxy.Request{Owner: browserproxy.Owner{PID: self.PID, Birth: self.CreationTime, Exe: self.Path, Profile: "owner-system-passthrough"}, Host: "club-control.invalid", Port: 443, Secure: true}
	plan, err := c.authorityPlan(ctx, q)
	if err != nil || plan.Enabled || plan.Policy.Action != flowpolicy.Direct {
		t.Fatalf("club TLS must bypass the browser stall watcher: %+v, %v", plan.Policy, err)
	}
	q.Host = "api.openai.com"
	plan, err = c.authorityPlan(ctx, q)
	if err != nil || plan.Policy.Action != flowpolicy.Block || plan.Policy.Fallback != flowpolicy.FailBlock {
		t.Fatalf("protected authority received a direct route: %+v, %v", plan.Policy, err)
	}
	q.Owner.Birth++
	if _, err := c.authorityPlan(ctx, q); err == nil {
		t.Fatal("accepted stale Windows identity")
	}
}
