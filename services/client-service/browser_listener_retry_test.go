package clientservice

import (
	"context"
	"net"
	"testing"
)

func TestActivationListenerBindConflictRecoversOnNextTick(t *testing.T) {
	for _, edge := range []bool{false, true} {
		c, value, _, _ := policyReadyFixture(t, edge)
		method := "browser.silent.apply"
		if edge {
			method = "edge.silent.apply"
		}
		if _, err := c.Handle(context.Background(), method, []byte(`{"profile_id":"browser"}`)); err != nil {
			t.Fatal(err)
		}
		_ = c.CleanupOwnedBrowserPolicies()
		c.browser.mu.Lock()
		server := c.browser.server
		if edge {
			server = c.edgeLocked().server
		}
		c.browser.mu.Unlock()
		address := server.Address()
		server.Close()
		blocker, err := net.Listen("tcp4", address)
		if err != nil {
			t.Fatal(err)
		}
		c.browser.mu.Lock()
		if edge {
			c.edgeLocked().server = nil
		} else {
			c.browser.server = nil
		}
		c.browser.mu.Unlock()
		c.RetrySilentBrowserPolicies()
		if *value != "" {
			t.Fatal("policy with blocked listener")
		}
		blocker.Close()
		c.RetrySilentBrowserPolicies()
		if *value == "" {
			t.Fatal("next tick did not recover")
		}
		health := c.browserPolicyHealth()
		i := 0
		if edge {
			i = 1
		}
		if health.ListenerAttempts[i] < 2 {
			t.Fatal("missing retry evidence", health)
		}
	}
}
