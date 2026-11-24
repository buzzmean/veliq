package clientservice

import (
	"context"
	"encoding/json"
	"github.com/buzzmean/veliq/core/profiles"
	"testing"
)

func TestChromeReadinessReportsFixedCodeWithoutExposingRequest(t *testing.T) {
	c := New(context.Background())
	defer c.Close()
	_, err := c.Handle(context.Background(), "browser.confirm", []byte(`{"profile_id":"private","health_url":"private-nonce"}`))
	if err == nil {
		t.Fatal("missing owner proof passed")
	}
	result, err := c.Handle(context.Background(), "browser.status", nil)
	if err != nil {
		t.Fatal(err)
	}
	s := result.(browserStatusView)
	if s.LastError != "browser.confirm: CHROME_READINESS_NOT_OBSERVED" || s.ReadinessState != "NOT_PREPARED" || s.Listening || s.PolicyReady {
		t.Fatalf("unexpected safe state: %+v", s)
	}
}

func TestFreshChromePrepareWithActiveCaptureDoesNotNeedPrematureAUTO(t *testing.T) {
	c := New(context.Background())
	defer c.Close()
	c.BrowserOwnerSID = "S-1-test"
	c.enabled = true
	c.settings.Automatic = true
	p := profiles.Profile{ID: "fresh-chrome", Name: "Chrome", Executables: []string{`C:\Apps\chrome.exe`}, Mode: profiles.Direct, Custom: true}
	if err := c.Profiles.Upsert(p); err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(map[string]string{"profile_id": p.ID, "directory": t.TempDir(), "recovery_address": "127.0.0.1:45678"})
	if _, err := c.Handle(context.Background(), "browser.prepare", raw); err != nil {
		t.Fatal(err)
	}
	result, err := c.Handle(context.Background(), "browser.status", nil)
	if err != nil {
		t.Fatal(err)
	}
	s := result.(browserStatusView)
	if !s.Listening || s.PolicyReady || s.ReadinessState != "PREPARED" || len(s.ReadyProfiles) != 0 || s.LastError != "" {
		t.Fatalf("prepare invented proof: %+v", s)
	}
	for _, saved := range c.Profiles.List() {
		if saved.ID == p.ID && saved.Mode != profiles.Direct {
			t.Fatal("premature AUTO")
		}
	}
	if !c.enabled {
		t.Fatal("other applications disabled")
	}
}
