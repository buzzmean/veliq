package clientservice

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/buzzmean/neexitlag/core/browserproxy"
)

func TestYouTubeLocalAutomaticAndRollbackCompatibility(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "profiles.json")
	settingsPath := filepath.Join(dir, "settings.json")
	stableSettings := []byte(`{"automatic":true,"failover":"DIRECT","update_channel":"stable"}`)
	if err := os.WriteFile(settingsPath, stableSettings, 0600); err != nil {
		t.Fatal(err)
	}
	oldPreferencePath := filepath.Join(dir, "browser-youtube-local-beta.json")
	oldPreference := []byte(`{"enabled":false}`)
	if err := os.WriteFile(oldPreferencePath, oldPreference, 0600); err != nil {
		t.Fatal(err)
	}
	newController := func() *Controller {
		t.Helper()
		c := New(context.Background())
		t.Cleanup(c.Close)
		c.BrowserOwnerSID = "installation-owner"
		if err := c.SetCustomPath(path); err != nil {
			t.Fatal(err)
		}
		return c
	}
	call := func(c *Controller, method, raw string) youtubeLocalBetaStatus {
		t.Helper()
		value, err := c.HandleOwnerIPC(context.Background(), method, []byte(raw))
		if err != nil {
			t.Fatal(err)
		}
		return value.(youtubeLocalBetaStatus)
	}

	c := newController()
	if status := call(c, "browser.youtube.local.status", `{}`); !status.Automatic || status.Manageable || !status.Enabled || status.Active || status.Reason != "WAITING_FOR_BROWSER_AUTO" {
		t.Fatalf("unexpected default: %+v", status)
	}
	if _, err := c.HandleOwnerIPC(context.Background(), "browser.youtube.local.set", []byte(`{}`)); err == nil || err.Error() != "YOUTUBE_LOCAL_INVALID_PREFERENCE" {
		t.Fatalf("missing boolean: %v", err)
	}
	if status := call(c, "browser.youtube.local.set", `{"enabled":true}`); !status.Automatic || !status.Enabled || status.Active || status.Reason != "WAITING_FOR_BROWSER_AUTO" {
		t.Fatalf("unexpected ON before Chrome AUTO: %+v", status)
	}
	first := call(c, "browser.youtube.local.status", `{}`).Generation
	if first == 0 || !c.youtubeLocalBetaCurrent(first) || c.youtubeLocalBetaScope(browserproxy.Request{}) != 0 {
		t.Fatal("enabled setting did not require verified browser ownership")
	}
	c.youtubeLocalBetaOutcome(first, "DPI_LOCAL_DNS_FAILED")
	c.youtubeLocalBetaOutcome(first, "DPI_LOCAL_BAD.leaked.host")
	c.youtubeLocalBetaCount(first, 123, 4)
	if status := call(c, "browser.youtube.local.status", `{}`); status.LastFailure != "DPI_LOCAL_DNS_FAILED" || status.LocalCDNRX != 123 || status.LocalDNSQueries != 4 {
		t.Fatalf("current generation evidence missing: %+v", status)
	}
	if status := call(newController(), "browser.youtube.local.status", `{}`); !status.Enabled || status.LastFailure != "" || status.LocalCDNRX != 0 || status.LocalDNSQueries != 0 {
		t.Fatalf("unexpected reload: %+v", status)
	}
	if _, err := c.HandleOwnerIPC(context.Background(), "browser.youtube.local.set", []byte(`{"enabled":false}`)); err == nil || err.Error() != "YOUTUBE_LOCAL_AUTOMATIC" {
		t.Fatalf("legacy switch disabled mandatory route: %v", err)
	}
	if status := call(c, "browser.youtube.local.status", `{}`); !status.Enabled || status.Generation != first || !c.youtubeLocalBetaCurrent(first) {
		t.Fatalf("legacy switch changed automatic route: %+v", status)
	}
	if raw, err := os.ReadFile(oldPreferencePath); err != nil || !bytes.Equal(raw, oldPreference) {
		t.Fatalf("old beta preference changed during upgrade: %v", err)
	}
	if raw, err := os.ReadFile(settingsPath); err != nil || !bytes.Equal(raw, stableSettings) {
		t.Fatalf("0.3.708 settings were modified: %v", err)
	}
}

func TestYouTubeLocalAutomaticWhileClubSettingsStayManaged(t *testing.T) {
	c := New(context.Background())
	t.Cleanup(c.Close)
	c.BrowserOwnerSID = "installation-owner"
	if err := c.SetCustomPath(filepath.Join(t.TempDir(), "profiles.json")); err != nil {
		t.Fatal(err)
	}
	c.clubMode.Store(true)
	out, err := c.HandleOwnerIPC(context.Background(), "browser.youtube.local.status", []byte(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	if status := out.(youtubeLocalBetaStatus); !status.Automatic || !status.Enabled || status.Manageable || !c.youtubeLocalBetaCurrent(status.Generation) {
		t.Fatalf("club lost the automatic policy: %+v", status)
	}
	if _, err := c.HandleOwnerIPC(context.Background(), "browser.youtube.local.set", []byte(`{"enabled":true}`)); err == nil || err.Error() != "CLUB_ADMIN_MANAGED" {
		t.Fatalf("club mutation: %v", err)
	}
}
