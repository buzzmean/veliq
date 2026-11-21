package clientservice

import (
	"context"
	"github.com/buzzmean/neexitlag/core/profiles"
	"os"
	"path/filepath"
	"testing"
)

func TestClubSeedsBrowsersBeforeActivationAndBlocksOwnerMutations(t *testing.T) {
	c := New(context.Background())
	defer c.Close()
	dir := t.TempDir()
	if err := c.SetCustomPath(filepath.Join(dir, "state", "profiles.json")); err != nil {
		t.Fatal(err)
	}
	var paths []string
	for _, name := range []string{"chrome.exe", "msedge.exe"} {
		p := filepath.Join(dir, name)
		os.WriteFile(p, []byte("fixture"), 0600)
		paths = append(paths, p)
	}
	if err := c.ConfigureClub(Manifest{ClubImage: true, ClubBrowserPaths: paths, DeviceIdentityFile: filepath.Join(dir, "identity.json")}); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"club-chrome", "club-edge"} {
		var p profiles.Profile
		ok := false
		for _, candidate := range c.Profiles.List() {
			if candidate.ID == id {
				p = candidate
				ok = true
			}
		}
		if !ok || p.Mode != profiles.Auto || p.BrowserTransport != "native" {
			t.Fatalf("browser not AUTO native: %s", id)
		}
	}
	if c.clubConfig.Load().manifest.ProbeTokenFile != filepath.Join(dir, "probe.token") {
		t.Fatal("fresh ActivationOnly probe token default missing")
	}
	if !c.Snapshot().Settings.Automatic {
		t.Fatal("automatic off")
	}
	for _, method := range []string{"optimize", "settings.set", "profile.set", "profile.delete", "activation.set", "gameudp.set", "browser.native.enable", "future.mutation"} {
		if _, err := c.HandleOwnerIPC(context.Background(), method, []byte(`{}`)); err == nil || err.Error() != "CLUB_ADMIN_MANAGED" {
			t.Fatalf("mutation accepted %s: %v", method, err)
		}
	}
	if _, err := c.HandleOwnerIPC(context.Background(), "status", nil); err != nil {
		t.Fatal(err)
	}
	// Internal activation automation must remain usable, not routed through owner gate.
	if _, err := c.Handle(context.Background(), "optimize", []byte(`{"enabled":false}`)); err != nil && err.Error() == "CLUB_ADMIN_MANAGED" {
		t.Fatal(err)
	}
	if err := c.ConfigureClub(Manifest{ClubImage: true, ClubBrowserPaths: paths, DeviceIdentityFile: filepath.Join(dir, "identity.json")}); err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, p := range c.Profiles.List() {
		if p.ID == "club-chrome" || p.ID == "club-edge" {
			n++
		}
	}
	if n != 2 {
		t.Fatal("duplicate browser profiles")
	}
}
func TestNonClubOwnerContractUnchanged(t *testing.T) {
	c := New(context.Background())
	defer c.Close()
	if err := c.ConfigureClub(Manifest{}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.HandleOwnerIPC(context.Background(), "optimize", []byte(`{"enabled":false}`)); err != nil && err.Error() == "CLUB_ADMIN_MANAGED" {
		t.Fatal(err)
	}
}

func TestClubUpgradesLegacyDirectBrowserButHonorsExplicitOptOut(t *testing.T) {
	c := New(context.Background())
	defer c.Close()
	dir := t.TempDir()
	paths := []string{}
	for i, name := range []string{"chrome.exe", "msedge.exe"} {
		file := filepath.Join(dir, name)
		os.WriteFile(file, []byte("fixture"), 0600)
		paths = append(paths, file)
		p := profiles.Profile{ID: name, Name: name, Executables: []string{file}, Mode: profiles.Direct, Custom: true, BrowserAutoDisabled: i == 1}
		if err := c.Profiles.Upsert(p); err != nil {
			t.Fatal(err)
		}
	}
	if err := c.ConfigureClub(Manifest{ClubImage: true, ClubBrowserPaths: paths, DeviceIdentityFile: filepath.Join(dir, "identity.json")}); err != nil {
		t.Fatal(err)
	}
	for _, p := range c.Profiles.List() {
		if p.ID == "chrome.exe" && (p.Mode != profiles.Auto || p.BrowserTransport != "native") {
			t.Fatal("legacy DIRECT circle")
		}
		if p.ID == "msedge.exe" && (p.Mode != profiles.Direct || !p.BrowserAutoDisabled) {
			t.Fatal("admin opt out overwritten")
		}
	}
}

func TestClubReadOnlyGameEvidenceAllowedButGameChangesDenied(t *testing.T) {
	for _, m := range []string{"gameudp.status", "capture.changes.marker", "capture.changes", "capture.diagnostics"} {
		if !clubReadMethod(m) {
			t.Fatal("read-only game evidence blocked", m)
		}
	}
	for _, m := range []string{"gameudp.set", "pubg.set", "capture.start", "capture.stop", "optimize", "profile.set"} {
		if clubReadMethod(m) {
			t.Fatal("guest mutation allowed", m)
		}
	}
}
