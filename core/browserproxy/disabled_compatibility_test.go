package browserproxy

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

func TestCachedPACRecoveryDirectOnlyWithServiceOwnedDisabledGrant(t *testing.T) {
	_, dial := recoveryEcho(t)
	file := filepath.Join(t.TempDir(), "browser-recovery-guard.json")
	owner := Owner{PID: 1, Birth: 1, Exe: "chrome.exe", Profile: "chrome"}
	r, err := ListenRecovery(context.Background(), "127.0.0.1:0", func(context.Context, netip.AddrPort, netip.AddrPort, RecoverySettings) (Owner, error) {
		return owner, nil
	}, dial)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	cfg := RecoverySettings{Primary: "127.0.0.1:1", Executable: "chrome.exe", Profile: "chrome", GuardFile: file}
	if err = r.Configure(cfg); err != nil {
		t.Fatal(err)
	}
	write := func(g RecoveryGuard) {
		b, _ := json.Marshal(g)
		if e := os.WriteFile(file, b, 0600); e != nil {
			t.Fatal(e)
		}
	}
	g := RecoveryGuard{Version: 1, Profiles: map[string]RecoveryGuardProfile{"chrome": {Executables: []string{"chrome.exe"}, Domains: []string{"private.example"}}}}
	// Active protection remains authoritative, even though the local primary is down.
	write(g)
	for _, host := range []string{"chatgpt.com", "private.example"} {
		c, code := recoveryConnect(t, r.Address(), host, "")
		c.Close()
		if code == 200 {
			t.Fatal("active protected DIRECT", host)
		}
	}
	g.DirectCompatibility = true
	write(g)
	for _, host := range []string{"vk.ru", "chatgpt.com", "private.example"} {
		c, code := recoveryConnect(t, r.Address(), host, "")
		if code != 200 {
			t.Fatal("disabled browser denied", host, code)
		}
		if _, e := c.Write([]byte("same socket")); e != nil {
			t.Fatal(e)
		}
		b := make([]byte, 11)
		if _, e := io.ReadFull(c, b); e != nil || string(b) != "same socket" {
			t.Fatal(e, string(b))
		}
		c.Close()
	}
	g.Deny = true
	write(g)
	c, code := recoveryConnect(t, r.Address(), "vk.ru", "")
	c.Close()
	if code == 200 {
		t.Fatal("deny overridden by compatibility")
	}
	g.Deny = false
	g.Profiles["chrome"] = RecoveryGuardProfile{Executables: []string{"unrelated.exe"}}
	write(g)
	if recoveryCompatibilityAuthorized(cfg) {
		t.Fatal("unrelated executable authorized")
	}
}

func TestIdleListenerNeverClosesActiveBrowserAndForeignOwnerStillDenied(t *testing.T) {
	_, dial := recoveryEcho(t)
	var allow atomic.Bool
	r, err := ListenRecovery(context.Background(), "127.0.0.1:0", func(context.Context, netip.AddrPort, netip.AddrPort, RecoverySettings) (Owner, error) {
		if allow.Load() {
			return Owner{Exe: "chrome.exe", Profile: "chrome"}, nil
		}
		return Owner{}, errors.New("unrelated process")
	}, dial)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if err = r.Configure(RecoverySettings{Primary: "127.0.0.1:1", Executable: "chrome.exe", Profile: "chrome"}); err != nil {
		t.Fatal(err)
	}
	c, code := recoveryConnect(t, r.Address(), "vk.ru", "")
	c.Close()
	if code != 403 {
		t.Fatal(code)
	}
	allow.Store(true)
	c, code = recoveryConnect(t, r.Address(), "vk.ru", "")
	if code != 200 {
		t.Fatal(code)
	}
	if r.server.CloseIfIdle(time.Now().Add(time.Hour), time.Minute) {
		t.Fatal("active socket closed")
	}
	c.Write([]byte("ok"))
	if _, err = io.ReadFull(c, make([]byte, 2)); err != nil {
		t.Fatal(err)
	}
	c.Close()
	until := time.Now().Add(time.Second)
	for r.server.Snapshot().ActiveConnections != 0 && time.Now().Before(until) {
		time.Sleep(time.Millisecond)
	}
	if r.server.CloseIfIdle(time.Now(), time.Minute) {
		t.Fatal("new use did not reset idle")
	}
	if !r.server.CloseIfIdle(time.Now().Add(2*time.Minute), time.Minute) || r.server.Snapshot().Listening {
		t.Fatal("idle listener retained")
	}
}
