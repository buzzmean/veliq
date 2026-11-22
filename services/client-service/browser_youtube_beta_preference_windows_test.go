//go:build windows

package clientservice

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/buzzmean/neexitlag/core/browserproxy"
	"github.com/buzzmean/neexitlag/core/flowpolicy"
	"github.com/buzzmean/neexitlag/core/profiles"
	wp "github.com/buzzmean/neexitlag/platform/windows"
)

func TestYouTubeLocalAutomaticUsesWindowsOwnerIdentity(t *testing.T) {
	for _, executable := range []string{"chrome.exe", "msedge.exe"} {
		t.Run(executable, func(t *testing.T) { checkYouTubeLocalAutomaticOwner(t, executable) })
	}
}

func checkYouTubeLocalAutomaticOwner(t *testing.T, executable string) {
	t.Helper()
	id := cdnColdOwnerExecutable(t, executable)
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
	profile := profiles.Profile{ID: "youtube-windows-owner-test", Name: "YouTube fixture", Executables: []string{id.Path}, Mode: profiles.Auto, BrowserTransport: "native", Custom: true}
	if err := c.Profiles.Upsert(profile); err != nil {
		t.Fatal(err)
	}
	request := browserproxy.Request{Owner: browserproxy.Owner{PID: id.PID, Birth: id.CreationTime, Exe: id.Path, Profile: profile.ID}, Host: "www.youtube.com", Ingress: "PAC_CONNECT", Secure: true, Port: 443}
	if c.youtubeLocalBetaScope(request) != 0 {
		t.Fatal("global AUTO disabled should retain direct compatibility")
	}
	c.enabled = true
	status := c.youtubeLocalBetaStatus()
	if !status.Automatic || status.Generation == 0 || c.youtubeLocalBetaScope(request) != status.Generation {
		t.Fatalf("live owner AUTO was not scoped by default: %+v", status)
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
	if status := c.youtubeLocalBetaStatus(); status.Reason != "WAITING_FOR_BROWSER_AUTHORITY" || status.Active {
		t.Fatalf("capture and network alone are insufficient: %+v", status)
	}
	c.browser.authority.published.Store(&browserAuthorityPublished{applied: true, server: &browserproxy.Server{}})
	if status := c.youtubeLocalBetaStatus(); status.Reason != "DIRECT_ONLY_CAPTURE_NOT_READY" || !status.Active {
		t.Fatalf("missing capture should leave plain DIRECT available: %+v", status)
	}
	c.Backend = &nativeBackendFixture{hotBackendFixture: hotBackendFixture{ready: true}}
	if status := c.youtubeLocalBetaStatus(); status.Reason != "DIRECT_ONLY_NETWORK_PENDING" || !status.Active {
		t.Fatalf("missing network should not be shown as active: %+v", status)
	}
	c.network.Store(&wp.NetworkContext{Fingerprint: "fixture", ObservedAt: time.Now()})
	if status := c.youtubeLocalBetaStatus(); status.Reason != "DIRECT_ONLY_LOCAL_GUARD" || !status.Active {
		t.Fatalf("no conflict scan should not be shown as active: %+v", status)
	}
	c.network.Store(&wp.NetworkContext{Fingerprint: "fixture", ObservedAt: time.Now(), ConflictsObservedAt: time.Now()})
	if status := c.youtubeLocalBetaStatus(); status.Reason != "READY" || !status.Active {
		t.Fatalf("normal browser authority with capture and valid network: %+v", status)
	}
	plan := browserproxy.Plan{YouTubeLocalGeneration: status.Generation, Policy: flowpolicy.Result{Action: flowpolicy.RelayRequired, RelayID: "VPS-01"}}
	if conn, err := c.browserOpen(context.Background(), request, plan); conn != nil || err == nil || err.Error() != "YOUTUBE_LOCAL_RELAY_FORBIDDEN" {
		t.Fatalf("service admitted a relay for YouTube: error=%v", err)
	}
	profile.Mode = profiles.Direct
	if err := c.Profiles.Upsert(profile); err != nil {
		t.Fatal(err)
	}
	if c.youtubeLocalBetaScope(request) != 0 {
		t.Fatal("explicit DIRECT profile was changed")
	}
}
