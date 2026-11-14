package clientservice

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/buzzmean/neexitlag/core/browserproxy"
)

func TestYouTubeLocalBetaPreferenceAndRollbackCompatibility(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "profiles.json")
	settingsPath := filepath.Join(dir, "settings.json")
	stableSettings := []byte(`{"automatic":true,"failover":"DIRECT","update_channel":"stable"}`)
	if err := os.WriteFile(settingsPath, stableSettings, 0600); err != nil {
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
	if status := call(c, "browser.youtube.local.status", `{}`); !status.Manageable || status.Enabled || status.Active || status.Reason != "OFF" {
		t.Fatalf("unexpected default: %+v", status)
	}
	if _, err := c.HandleOwnerIPC(context.Background(), "browser.youtube.local.set", []byte(`{}`)); err == nil || err.Error() != "YOUTUBE_LOCAL_INVALID_PREFERENCE" {
		t.Fatalf("missing boolean: %v", err)
	}
	if status := call(c, "browser.youtube.local.set", `{"enabled":true}`); !status.Enabled || status.Active || status.Reason != "WAITING_FOR_CHROME_AUTO" {
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
	if status := call(c, "browser.youtube.local.set", `{"enabled":false}`); status.Enabled || status.Active || status.Reason != "OFF" || c.youtubeLocalBetaCurrent(first) {
		t.Fatalf("OFF must invalidate existing decisions: %+v", status)
	}
	if status := call(newController(), "browser.youtube.local.status", `{}`); status.Enabled || status.Reason != "OFF" {
		t.Fatalf("OFF did not persist across restart: %+v", status)
	}
	call(c, "browser.youtube.local.set", `{"enabled":true}`)
	c.youtubeLocalBetaCount(first, 999, 999)
	c.youtubeLocalBetaOutcome(first, "DPI_LOCAL_DNS_FAILED")
	if status := call(c, "browser.youtube.local.status", `{}`); status.LastFailure != "" || status.LocalCDNRX != 0 || status.LocalDNSQueries != 0 || c.youtubeLocalBetaCurrent(first) {
		t.Fatalf("old attempts must not update the new generation: %+v", status)
	}
	if raw, err := os.ReadFile(settingsPath); err != nil || !bytes.Equal(raw, stableSettings) {
		t.Fatalf("0.3.708 settings were modified: %v", err)
	}
}

func TestYouTubeLocalBetaRespectsClubAndRepairsMalformedPreference(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, youtubeLocalBetaPreferenceFile), []byte(`{"enabled":true,"unexpected":true}`), 0600); err != nil {
		t.Fatal(err)
	}
	c := New(context.Background())
	t.Cleanup(c.Close)
	c.BrowserOwnerSID = "installation-owner"
	if err := c.SetCustomPath(filepath.Join(dir, "profiles.json")); err != nil {
		t.Fatal(err)
	}
	if status := c.youtubeLocalBetaStatus(); status.Enabled || status.Reason != "PREFERENCE_UNREADABLE" {
		t.Fatalf("malformed preference should be OFF: %+v", status)
	}
	c.clubMode.Store(true)
	out, err := c.HandleOwnerIPC(context.Background(), "browser.youtube.local.status", []byte(`{}`))
	if err != nil || out.(youtubeLocalBetaStatus).Manageable || out.(youtubeLocalBetaStatus).Reason != "CLUB_ADMIN_MANAGED" {
		t.Fatalf("club status: %+v, %v", out, err)
	}
	if _, err := c.HandleOwnerIPC(context.Background(), "browser.youtube.local.set", []byte(`{"enabled":true}`)); err == nil || err.Error() != "CLUB_ADMIN_MANAGED" {
		t.Fatalf("club mutation: %v", err)
	}
	c.clubMode.Store(false)
	if _, err := c.HandleOwnerIPC(context.Background(), "browser.youtube.local.set", []byte(`{"enabled":false}`)); err != nil {
		t.Fatal(err)
	}
	if status := c.youtubeLocalBetaStatus(); status.Enabled || status.Reason != "OFF" {
		t.Fatalf("explicit OFF should repair malformed preference: %+v", status)
	}
}
