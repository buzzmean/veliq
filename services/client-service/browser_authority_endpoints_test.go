package clientservice

import (
	"context"
	wp "github.com/buzzmean/veliq/platform/windows"
	"net"
	"os"
	"path/filepath"
	"testing"
)

func endpointAddress(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().String()
}
func endpointLease(t *testing.T, path, owner, address string) {
	t.Helper()
	if err := writeOwnerProxyLease(path, ownerProxyLease{Version: 1, Owner: owner, Installed: authorityFixedState(address)}); err != nil {
		t.Fatal(err)
	}
}
func endpointController(directory, owner string) *Controller {
	c := New(context.Background())
	c.customPath = filepath.Join(directory, "profiles.json")
	c.BrowserOwnerSID = owner
	return c
}

func TestAuthorityEndpointsSurviveReleaseRestartAndLegacyLease(t *testing.T) {
	dir := t.TempDir()
	address := endpointAddress(t)
	leasePath := filepath.Join(dir, "browser-owner-proxy.json")
	endpointLease(t, leasePath, "owner", address)
	legacy, err := os.ReadFile(leasePath)
	if err != nil {
		t.Fatal(err)
	}
	if err = prepareAuthorityEndpoints(dir, "owner", ""); err != nil {
		t.Fatal(err)
	}
	current := authorityFixedState(address)
	exchange := func(_ context.Context, q wp.OwnerProxyCommand) (wp.OwnerProxyState, error) {
		if q.Desired != nil {
			current = *q.Desired
		}
		return current, nil
	}
	if err = releaseOwnerProxy(context.Background(), leasePath, "owner", exchange); err != nil {
		t.Fatal(err)
	}
	if !freeOwnerProxy(current) {
		t.Fatal("OFF did not restore original settings")
	}
	if _, err = os.Stat(leasePath); !os.IsNotExist(err) {
		t.Fatal("reversible lease not released")
	}
	c := endpointController(dir, "owner")
	if err = c.RestoreOwnerAuthorityListener(); err != nil {
		t.Fatal(err)
	}
	if c.browser.authority.server.Address() != address {
		t.Fatal("cached endpoint changed")
	}
	c.Close()
	// Older 730 ignores the separate file and can read its unmodified old lease.
	if err = os.WriteFile(leasePath, legacy, 0600); err != nil {
		t.Fatal(err)
	}
	old, err := readOwnerProxyLease(leasePath, "owner")
	if err != nil || authorityLeaseEndpoint(old) != address {
		t.Fatal("legacy rollback lease incompatible", err)
	}
	c = endpointController(dir, "owner")
	defer c.Close()
	if err = c.RestoreOwnerAuthorityListener(); err != nil {
		t.Fatal(err)
	}
	if c.browser.authority.server.Address() != address {
		t.Fatal("restart changed persisted endpoint")
	}
}

func TestAuthorityCompatibilityPreservesPrimaryAndForeignPort(t *testing.T) {
	dir := t.TempDir()
	foreign, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer foreign.Close()
	compat := foreign.Addr().String()
	primary := endpointAddress(t)
	leasePath := filepath.Join(dir, "browser-owner-proxy.json")
	endpointLease(t, leasePath, "owner", primary)
	previous := filepath.Join(t.TempDir(), "old.json")
	endpointLease(t, previous, "owner", compat)
	if err = prepareAuthorityEndpoints(dir, "owner", previous); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(leasePath)
	c := endpointController(dir, "owner")
	defer c.Close()
	if err = c.RestoreOwnerAuthorityListener(); err == nil || err.Error() != "AUTHORITY_COMPAT_LISTENER_UNAVAILABLE" {
		t.Fatal("occupied compatibility port accepted", err)
	}
	if c.browser.authority.server == nil || c.browser.authority.server.Address() != primary {
		t.Fatal("compatibility failure removed/replaced primary")
	}
	view := c.authorityStatus()
	if len(view.Listeners) != 2 || !view.Listeners[0].Listening || view.Listeners[1].Error == "" {
		t.Fatalf("actual bind state missing: %+v", view.Listeners)
	}
	foreign.Close()
	if err = c.RestoreOwnerAuthorityListener(); err != nil {
		t.Fatal(err)
	}
	view = c.authorityStatus()
	if len(view.Listeners) != 2 || !view.Listeners[1].Listening || view.Listeners[1].Address != compat {
		t.Fatal("compatible endpoint not restored")
	}
	after, _ := os.ReadFile(leasePath)
	if string(before) != string(after) {
		t.Fatal("compatibility listener rewrote system proxy lease")
	}
}

func TestAuthorityEndpointsRejectForeignMalformedAndOverflow(t *testing.T) {
	for _, v := range []ownerAuthorityEndpoints{
		{Version: 1, Owner: "foreign", Primary: "127.0.0.1:32101"},
		{Version: 1, Owner: "owner", Primary: "0.0.0.0:32101"},
		{Version: 1, Owner: "owner", Primary: "127.0.0.2:32101"},
		{Version: 1, Owner: "owner", Primary: "127.0.0.1:0"},
		{Version: 1, Owner: "owner", Primary: "127.0.0.1:32101", Compatibility: []string{"127.0.0.1:32101"}},
		{Version: 1, Owner: "owner", Primary: "127.0.0.1:32101", Compatibility: []string{"127.0.0.1:32102", "127.0.0.1:32103"}},
	} {
		if validAuthorityEndpoints(v, "owner") {
			t.Fatalf("unsafe state accepted: %+v", v)
		}
	}
	dir := t.TempDir()
	endpointLease(t, filepath.Join(dir, "browser-owner-proxy.json"), "owner", "127.0.0.1:32101")
	old := filepath.Join(t.TempDir(), "lease.json")
	endpointLease(t, old, "foreign", "127.0.0.1:32102")
	if err := prepareAuthorityEndpoints(dir, "owner", old); err == nil {
		t.Fatal("foreign owner lease imported")
	}
	endpointLease(t, old, "owner", "127.0.0.1:32102")
	if err := prepareAuthorityEndpoints(dir, "owner", old); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(authorityEndpointsPath(dir))
	endpointLease(t, old, "owner", "127.0.0.1:32103")
	if err := prepareAuthorityEndpoints(dir, "owner", old); err == nil {
		t.Fatal("third address silently evicted a live client endpoint")
	}
	after, _ := os.ReadFile(authorityEndpointsPath(dir))
	if string(before) != string(after) {
		t.Fatal("rejected migration changed state")
	}
}
