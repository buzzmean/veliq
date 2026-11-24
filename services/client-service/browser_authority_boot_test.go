package clientservice

import (
	"context"
	"github.com/buzzmean/veliq/core/flowpolicy"
	"github.com/buzzmean/veliq/core/profiles"
	"net"
	"os"
	"path/filepath"
	"testing"
)

func TestLanGameProxyPreservesRelayFloors(t *testing.T) {
	c := New(context.Background())
	defer c.Close()
	for _, host := range []string{"club-server", "192.168.1.14", "club.example", "openai.com.other.example"} {
		if p := c.lanGameProxyPolicy(host); p.Action != flowpolicy.Direct || p.Fallback != flowpolicy.FailOpen {
			t.Errorf("ordinary club destination %q: %+v", host, p)
		}
	}
	for _, host := range []string{"api.openai.com", "telegram.org"} {
		if p := c.lanGameProxyPolicy(host); p.Action != flowpolicy.Block || p.Fallback != flowpolicy.FailBlock {
			t.Errorf("direct passthrough allowed for %q: %+v", host, p)
		}
	}
}

func TestOwnedAuthorityBootRestoresListenerWithoutDiscardingGuard(t *testing.T) {
	c := New(context.Background())
	defer c.Close()
	c.BrowserOwnerSID = "owner"
	c.customPath = filepath.Join(t.TempDir(), "profiles.json")
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	listener.Close()
	lease := ownerProxyLease{Version: 1, Owner: "owner", Installed: authorityFixedState(address)}
	if err := writeOwnerProxyLease(c.authorityLeasePath(), lease); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(c.authorityLeasePath())
	c.Profiles.Upsert(profiles.Profile{ID: "chrome-boot", Name: "Chrome boot", Executables: []string{"chrome.exe"}, Mode: profiles.Auto, BrowserTransport: "native"})
	c.activation.networkBlocked.Store(true)
	if err := c.RestoreOwnerAuthorityListener(); err != nil {
		t.Fatal(err)
	}
	c.retryBrowserAuthority(true)
	after, _ := os.ReadFile(c.authorityLeasePath())
	if string(before) != string(after) || !c.authorityGuardPending() || !c.browser.authority.server.Snapshot().Listening {
		t.Fatal("startup discarded its owned guard or rewrote settings")
	}
	connection, err := net.Dial("tcp4", address)
	if err != nil {
		t.Fatal("exact listener not rebound")
	}
	connection.Close()
}
