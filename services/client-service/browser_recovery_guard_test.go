package clientservice

import (
	"context"
	"encoding/json"
	"github.com/buzzmean/neexitlag/core/browserproxy"
	"github.com/buzzmean/neexitlag/core/profiles"
	"os"
	"path/filepath"
	"testing"
)

func TestChromeRecoveryGuardTracksAtomicPolicyAndRemoval(t *testing.T) {
	c := New(context.Background())
	defer c.Close()
	if err := c.SetCustomPath(filepath.Join(t.TempDir(), "profiles.json")); err != nil {
		t.Fatal(err)
	}
	p := profiles.Profile{ID: "chrome", Name: "Chrome", Custom: true, Executables: []string{`C:\Chrome\chrome.exe`}, Mode: profiles.Auto}
	read := func() browserproxy.RecoveryGuard {
		raw, err := os.ReadFile(c.browserGuardFile())
		if err != nil {
			t.Fatal(err)
		}
		var guard browserproxy.RecoveryGuard
		if err = json.Unmarshal(raw, &guard); err != nil {
			t.Fatal(err)
		}
		return guard
	}
	set := func() {
		raw, _ := json.Marshal(p)
		if _, err := c.Handle(context.Background(), "profile.set", raw); err != nil {
			t.Fatal(err)
		}
	}
	set()
	if guard := read(); guard.Deny || guard.Profiles[p.ID].Strict {
		t.Fatal("AUTO ordinary recovery was not published", guard)
	}
	p.Mode = profiles.Manual
	p.RelayID = "VPS-01"
	set()
	if guard := read(); guard.Deny || !guard.Profiles[p.ID].Strict {
		t.Fatal("stale AUTO grant survived MANUAL", guard)
	}
	if err := c.publishBrowserGuard(true); err != nil {
		t.Fatal(err)
	}
	if !read().Deny {
		t.Fatal("interrupted transaction did not fail closed")
	}
	if _, err := c.Handle(context.Background(), "profile.delete", []byte(`{"id":"chrome"}`)); err != nil {
		t.Fatal(err)
	}
	if guard := read(); guard.Deny || len(guard.Profiles) != 0 {
		t.Fatal("deleted profile remained authorized", guard)
	}
}
