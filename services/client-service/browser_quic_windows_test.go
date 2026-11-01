//go:build windows

package clientservice

import (
	"context"
	"io"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/buzzmean/neexitlag/core/localstrategy"
	"github.com/buzzmean/neexitlag/core/profiles"
	wp "github.com/buzzmean/neexitlag/platform/windows"
)

func TestBrowserQUICProbeOwnerChild(t *testing.T) {
	if os.Getenv("VELIQ_QUIC_SERVICE_CHILD") != "1" {
		t.Skip("isolated child")
	}
	_, _ = io.Copy(io.Discard, os.Stdin)
}
func TestBrowserQUICProbeNativeServiceScope(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(exe)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "chrome.exe")
	if err = os.WriteFile(path, data, 0700); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(path, "-test.run=^TestBrowserQUICProbeOwnerChild$")
	cmd.Env = append(os.Environ(), "VELIQ_QUIC_SERVICE_CHILD=1")
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err = cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { stdin.Close(); cmd.Process.Kill(); cmd.Wait() }()
	id, err := wp.NewDiscovery().Lookup(uint32(cmd.Process.Pid))
	if err != nil {
		t.Fatal(err)
	}
	sid, err := wp.ProcessUserSID(id)
	if err != nil {
		t.Fatal(err)
	}
	c := New(context.Background())
	defer c.Close()
	c.BrowserOwnerSID = sid
	b := &nativeBackendFixture{}
	b.ready = true
	c.Backend = b
	c.enabled = true
	c.network.Store(&wp.NetworkContext{Fingerprint: "net", ObservedAt: time.Now()})
	if err = c.Local.Reload(localstrategy.Config{Version: 1, Enabled: true}); err != nil {
		t.Fatal(err)
	}
	p := profiles.Profile{ID: "quic-chrome", Name: "QUIC scoped test", Executables: []string{id.Path}, Mode: profiles.Auto, BrowserTransport: "native", Custom: true}
	if err = c.Profiles.Upsert(p); err != nil {
		t.Fatal(err)
	}
	k := browserQUICKey()
	k.PID = id.PID
	k.Birth = id.CreationTime
	k.Executable = id.Path
	k.Profile = p.ID
	k.Revision = c.policyRevision(p)
	tuple := wp.Tuple{Protocol: "udp", Source: netip.MustParseAddrPort("127.0.0.1:50001"), Destination: k.Endpoint}
	d := c.Classify(id, tuple)
	if !d.Block || !d.BlockOnFailure || d.QUICProbe == nil || d.Policy.Source != "browser_native_quic_tcp_fallback" {
		t.Fatal("controller not wired to blocked native flow", d.Policy)
	}
	d.QUICProbe(wp.QUICProbeTrigger{})
	if c.browser.quic.snapshot()["attempts"] != uint64(0) {
		t.Fatal("forged trigger scheduled")
	}
	if !c.browserQUICCurrent(k, id, sid) {
		t.Fatal("fresh native owner/scope refused")
	}
	if c.browserQUICCurrent(k, id, "S-1-0-0") {
		t.Fatal("foreign installation owner accepted")
	}
	for _, field := range []string{"birth", "path", "profile", "revision", "network", "protected", "ordinary"} {
		bad := k
		switch field {
		case "birth":
			bad.Birth++
		case "path":
			bad.Executable = `C:\Other\chrome.exe`
		case "profile":
			bad.Profile = "other"
		case "revision":
			bad.Revision = "other"
		case "network":
			bad.Network = "other"
		case "protected":
			bad.Host = "api.openai.com"
		case "ordinary":
			bad.Host = "example.com"
		}
		if c.browserQUICCurrent(bad, id, sid) {
			t.Fatal("changed scope accepted", field)
		}
	}
	c.mu.Lock()
	c.enabled = false
	c.mu.Unlock()
	if c.browserQUICCurrent(k, id, sid) {
		t.Fatal("OFF accepted")
	}
	c.mu.Lock()
	c.enabled = true
	c.mu.Unlock()
	c.network.Store(&wp.NetworkContext{Fingerprint: "net", ObservedAt: time.Now(), VPN: []string{"fixture"}})
	if c.browserQUICCurrent(k, id, sid) {
		t.Fatal("VPN accepted")
	}
	c.network.Store(&wp.NetworkContext{Fingerprint: "net", ObservedAt: time.Now().Add(-time.Minute)})
	if c.browserQUICCurrent(k, id, sid) {
		t.Fatal("stale network accepted")
	}
	c.network.Store(&wp.NetworkContext{Fingerprint: "net", ObservedAt: time.Now()})
	b.ready = false
	if c.browserQUICCurrent(k, id, sid) {
		t.Fatal("capture failure accepted")
	}
	b.ready = true
	c.cancel()
	if c.browserQUICCurrent(k, id, sid) {
		t.Fatal("stopped controller accepted")
	}
	t.Log("real owner/SID + controller classification verified; browser remains BLOCK; scope revocations deny before open")
}
