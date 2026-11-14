//go:build windows

package clientservice

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/buzzmean/neexitlag/core/browserproxy"
	"github.com/buzzmean/neexitlag/core/profiles"
	wp "github.com/buzzmean/neexitlag/platform/windows"
)

func TestYouTubeLocalBetaUsesWindowsOwnerIdentityAndChromeAUTO(t *testing.T) {
	id := cdnColdOwner(t)
	sid, err := wp.ProcessUserSID(id)
	if err != nil {
		t.Fatal(err)
	}
	c := New(context.Background())
	t.Cleanup(c.Close)
	c.BrowserOwnerSID = sid
	if err := c.SetCustomPath(filepath.Join(t.TempDir(), "profiles.json")); err != nil {
		t.Fatal(err)
	}
	profile := profiles.Profile{ID: "chrome-beta-windows-owner-test", Name: "Chrome beta", Executables: []string{id.Path}, Mode: profiles.Auto, BrowserTransport: "native", Custom: true}
	if err := c.Profiles.Upsert(profile); err != nil {
		t.Fatal(err)
	}
	request := browserproxy.Request{Owner: browserproxy.Owner{PID: id.PID, Birth: id.CreationTime, Exe: id.Path, Profile: profile.ID}, Host: "www.youtube.com", Ingress: "PAC_CONNECT", Secure: true, Port: 443}
	if c.youtubeLocalBetaScope(request) != 0 {
		t.Fatal("OFF should retain normal routing")
	}
	status, err := c.handleYouTubeLocalBeta("browser.youtube.local.set", []byte(`{"enabled":true}`))
	if err != nil || status.Generation == 0 || c.youtubeLocalBetaScope(request) != status.Generation {
		t.Fatalf("live owner Chrome AUTO was not scoped: %+v, %v", status, err)
	}
	request.Owner.Birth++
	if c.youtubeLocalBetaScope(request) != 0 {
		t.Fatal("reused PID with another birth accepted")
	}
	request.Owner.Birth--
	c.BrowserOwnerSID = "another-account"
	if c.youtubeLocalBetaScope(request) != 0 {
		t.Fatal("mismatched Windows owner accepted")
	}
	c.BrowserOwnerSID = sid
	c.enabled = true
	if status := c.youtubeLocalBetaStatus(); status.Reason != "WAITING_FOR_CAPTURE" || status.Active {
		t.Fatalf("missing capture should not be shown as active: %+v", status)
	}
	c.Backend = &nativeBackendFixture{hotBackendFixture: hotBackendFixture{ready: true}}
	if status := c.youtubeLocalBetaStatus(); status.Reason != "WAITING_FOR_NETWORK" || status.Active {
		t.Fatalf("missing network should not be shown as active: %+v", status)
	}
	c.network.Store(&wp.NetworkContext{Fingerprint: "fixture", ObservedAt: time.Now()})
	if status := c.youtubeLocalBetaStatus(); status.Reason != "WAITING_FOR_LOCAL_GUARD" || status.Active {
		t.Fatalf("no conflict scan should not be shown as active: %+v", status)
	}
	c.network.Store(&wp.NetworkContext{Fingerprint: "fixture", ObservedAt: time.Now(), ConflictsObservedAt: time.Now()})
	if status := c.youtubeLocalBetaStatus(); status.Reason != "WAITING_FOR_CHROME_AUTHORITY" || status.Active {
		t.Fatalf("capture and network alone are insufficient: %+v", status)
	}
	c.browser.authority.published.Store(&browserAuthorityPublished{applied: true, server: &browserproxy.Server{}})
	if status := c.youtubeLocalBetaStatus(); status.Reason != "READY" || !status.Active {
		t.Fatalf("normal Chrome authority with capture and valid network: %+v", status)
	}
	profile.Mode = profiles.Direct
	if err := c.Profiles.Upsert(profile); err != nil {
		t.Fatal(err)
	}
	if c.youtubeLocalBetaScope(request) != 0 {
		t.Fatal("explicit DIRECT profile was changed by the beta")
	}
}
