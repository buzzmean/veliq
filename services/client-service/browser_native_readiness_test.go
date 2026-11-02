package clientservice

import (
	"encoding/json"
	"github.com/buzzmean/neexitlag/core/profiles"
	"testing"
)

func TestNativeReadinessNeedsAuthorityIngressAndNotPageSuccess(t *testing.T) {
	c, p, b := nativeEdgeFixture(t)
	p.Mode = profiles.Auto
	p.BrowserTransport = "native"
	c.Profiles.Upsert(p)
	c.enabled = true
	c.settings.Automatic = true
	c.browser.readiness.enforced.Store(true)
	if c.nativeSnapshot().State != "PREPARING" {
		t.Fatal(c.nativeSnapshot())
	}
	b.ready = true
	c.browser.readiness.relay = func() bool { return true }
	s := c.nativeSnapshot()
	if s.State != "AUTHORITY_PENDING" || s.NativeOnlyState != "NATIVE_ONLY_NOT_OBSERVED" || s.ConfiguredProfiles != 1 {
		t.Fatal(s)
	}
	c.enabled = false
	if c.nativeSnapshot().State != "DISABLED" {
		t.Fatal(c.nativeSnapshot())
	}
}

func TestFreshNativeStatusReportsAuthorityPendingAndSafeRelay(t *testing.T) {
	c, p, b := nativeEdgeFixture(t)
	b.ready = true
	c.enabled = true
	c.settings.Automatic = true
	c.browser.readiness.relay = func() bool { return true }
	p.Mode = profiles.Auto
	p.BrowserTransport = "native"
	c.Profiles.Upsert(p)
	result, err := edgeCall(c, "edge.status", map[string]string{})
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(result)
	var status map[string]any
	json.Unmarshal(raw, &status)
	if status["transport_mode"] != "NATIVE_NEW_TCP" || status["readiness_state"] != "AUTHORITY_TRANSPORT_PENDING" || status["policy_ready"] != false || status["listening"] != false {
		t.Fatal(status)
	}
	p.Executables = []string{`C:\Apps\chrome.exe`}
	p.AppPreset = ""
	c.Profiles.Upsert(p)
	result, err = edgeCall(c, "browser.status", map[string]string{})
	if err != nil {
		t.Fatal(err)
	}
	view := result.(browserStatusView)
	if view.ReadinessState != "AUTHORITY_TRANSPORT_PENDING" || view.Listening || view.PolicyReady {
		t.Fatal(view)
	}
}
