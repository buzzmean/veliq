package clientservice

import (
	"context"
	"github.com/buzzmean/neexitlag/core/profiles"
	"net"
	"os"
	"path/filepath"
	"testing"
)

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
