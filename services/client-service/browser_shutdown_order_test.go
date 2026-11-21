package clientservice

import (
	"context"
	"encoding/json"
	"github.com/buzzmean/neexitlag/core/controlclient"
	"github.com/buzzmean/neexitlag/core/security"
	"os"
	"testing"
)

func TestActivationCloseRemovesPolicyBeforeListener(t *testing.T) {
	c, value, _, _ := policyReadyFixture(t, false)
	if _, err := c.Handle(context.Background(), "browser.silent.apply", []byte(`{"profile_id":"browser"}`)); err != nil {
		t.Fatal(err)
	}
	removed := false
	c.browser.chromeRemove = func(_ string, _ []string) error {
		if *value != "" && (c.browser.server == nil || !c.browser.server.Snapshot().Listening) {
			t.Error("listener stopped before policy removal")
		}
		*value = ""
		removed = true
		return nil
	}
	c.Close()
	if !removed || *value != "" {
		t.Fatal("policy retained")
	}
}
func TestActivationRevocationRemovesPACBeforeRelayClose(t *testing.T) {
	c, value, _, _ := policyReadyFixture(t, false)
	defer c.Close()
	if _, err := c.Handle(context.Background(), "browser.silent.apply", []byte(`{"profile_id":"browser"}`)); err != nil {
		t.Fatal(err)
	}
	s := remoteState{controller: c, cp: &controlclient.Client{DeviceID: "revoked"}}
	if err := s.apply(context.Background(), security.Config{RevokedDevices: []string{"revoked"}}); err == nil {
		t.Fatal("revocation accepted")
	}
	c.RetrySilentBrowserPolicies()
	if c.activationNetworkAllowed() {
		t.Fatal("revoked device capture still permitted")
	}
	if *value != "" {
		t.Fatal("revoked identity retained PAC")
	}
}

func TestHostStopPublishesDirectCompatibilityBeforeRemovingPolicy(t *testing.T) {
	c, value, _, _ := policyReadyFixture(t, false)
	*value = "owned"
	c.browser.silent.Owned = []string{"owned"}
	c.browser.chromeRemove = func(_ string, _ []string) error {
		if *value == "" {
			return nil
		}
		raw, e := os.ReadFile(c.browserGuardFile())
		if e != nil {
			t.Fatal(e)
		}
		var g struct {
			Direct bool `json:"direct_compatibility"`
		}
		if json.Unmarshal(raw, &g) != nil || !g.Direct {
			t.Fatal("SCM stop retained active guard")
		}
		if c.browser.server == nil || !c.browser.server.Snapshot().Listening {
			t.Fatal("listener closed before compatibility")
		}
		*value = ""
		return nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if e := c.CloseForHost(ctx); e != nil {
		t.Fatal(e)
	}
	if c.browser.server.Snapshot().Listening {
		t.Fatal("SCM stop retained primary")
	}
}
