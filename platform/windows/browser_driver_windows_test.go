//go:build windows

package windowsplatform

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/buzzmean/veliq/core/routing"
)

// Isolates the actual signed-driver TCP handoff from Chrome policy and slow
// network inventory. A mocked packetWriter cannot satisfy this test.
func TestNativeBrowserDriverHandshake(t *testing.T) {
	dir := os.Getenv("NEEXITLAG_TEST_DRIVER_DIR")
	if dir == "" {
		t.Skip("signed driver directory not configured")
	}
	if os.Getenv("NEEXITLAG_NATIVE_APP_FIREWALL_CHILD") != "1" {
		root, err := filepath.Abs(filepath.Join("..", "..", ".e2e"))
		if err != nil {
			t.Fatal(err)
		}
		if err = os.MkdirAll(root, 0700); err != nil {
			t.Fatal(err)
		}
		stage, err := os.MkdirTemp(root, "native-app-firewall-")
		if err != nil {
			t.Fatal(err)
		}
		defer func() {
			var err error
			for i := 0; i < 20; i++ {
				err = os.RemoveAll(stage)
				if err == nil {
					return
				}
				time.Sleep(100 * time.Millisecond)
			}
			t.Error("fixture executable cleanup", err)
		}()
		own, err := os.Executable()
		if err != nil {
			t.Fatal(err)
		}
		binary, err := os.ReadFile(own)
		if err != nil {
			t.Fatal(err)
		}
		child := filepath.Join(stage, "veliq-service.exe")
		if err = os.WriteFile(child, binary, 0700); err != nil {
			t.Fatal(err)
		}
		run, stop := context.WithTimeout(context.Background(), 60*time.Second)
		defer stop()
		command := exec.CommandContext(run, child, "-test.run", "^TestNativeBrowserDriverHandshake$", "-test.v")
		command.Env = append(os.Environ(), "NEEXITLAG_NATIVE_APP_FIREWALL_CHILD=1")
		output, err := command.CombinedOutput()
		t.Log(string(output))
		if err != nil {
			t.Fatal("production app-scoped firewall/native driver fixture", err)
		}
		return
	}
	raw, err := os.ReadFile(filepath.Join(dir, "pins.json"))
	if err != nil {
		t.Fatal(err)
	}
	var files DriverFiles
	if err = json.Unmarshal(raw, &files); err != nil {
		t.Fatal(err)
	}
	files.Directory = dir
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()
	b := NewBrowserLoopbackFixture(files, routing.New(16))
	if err = b.Start(ctx, func(ProcessIdentity, Tuple) Decision { return Decision{} }); err != nil {
		t.Fatal(err)
	}
	defer b.Stop()
	admitNativeApplicationFixture(t)
	firewall := InspectNativeFirewall(ctx)
	if firewall.State != "APPLIED" || !firewall.Known || !firewall.Effective || !firewall.ProgramMatches {
		t.Fatal("actual embedded firewall status", firewall)
	}
	t.Log("APPLIED: embedded read-only firewall query matches this EXE and effective ActiveStore")
	id, err := NewDiscovery().Lookup(uint32(os.Getpid()))
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	trace := []string{}
	b.TraceNativeFixture(func(phase string, tuple Tuple, flags, addr byte) {
		mu.Lock()
		defer mu.Unlock()
		if len(trace) < 100 {
			trace = append(trace, phase+" "+tuple.Source.String()+" -> "+tuple.Destination.String()+" flags="+fmt.Sprint(flags)+" address="+fmt.Sprint(addr))
		}
	})
	d := Decision{NewConnectionsOnly: true, BlockOnFailure: true, OriginDomain: "controlled.example"}
	d.OpenDeferred = func(_ context.Context, d Decision, _ string) (net.Conn, Decision, error) {
		up, peer := net.Pipe()
		go func() { defer peer.Close(); _, _ = io.Copy(peer, peer) }()
		return up, d, nil
	}
	conn, err := b.OpenBrowserNativeTCP(ctx, id, netip.MustParseAddrPort("127.0.0.1:12345"), netip.MustParseAddrPort("127.0.0.1:443"), d)
	dump := func() {
		mu.Lock()
		defer mu.Unlock()
		for _, line := range trace {
			t.Log(line)
		}
	}
	if err != nil {
		dump()
		t.Fatal("real native TCP handshake", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	const payload = "VELIQ-native-TCP-nonce"
	if _, err = io.WriteString(conn, payload); err != nil {
		dump()
		t.Fatal(err)
	}
	got := make([]byte, len(payload))
	if _, err = io.ReadFull(conn, got); err != nil || string(got) != payload {
		dump()
		t.Fatal("actual native bidirectional payload", string(got), err)
	}
	dump()
	_ = conn.Close()
	testNativeColdStallRetry(t, b, id)
}

// Exercises the actual opt-in production helper against this isolated copied
// test executable. Never installs SCM or reads real identity/credentials.
func admitNativeApplicationFixture(t *testing.T) {
	t.Helper()
	helper, err := filepath.Abs(filepath.Join("..", "..", "tools", "windows", "native-tcp-firewall.ps1"))
	if err != nil {
		t.Fatal(err)
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	quote := func(s string) string { return "'" + strings.ReplaceAll(s, "'", "''") + "'" }
	run := func(operation string) ([]byte, error) {
		ctx, stop := context.WithTimeout(context.Background(), 15*time.Second)
		defer stop()
		script := "$ErrorActionPreference='Stop';. " + quote(helper) + ";" + operation + " " + quote(exe)
		return exec.CommandContext(ctx, "powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script).CombinedOutput()
	}
	output, err := run("Add-NativeTcpFirewallAdmission")
	if err != nil {
		t.Fatal("actual application-scoped firewall admission", err, string(output))
	}
	if strings.TrimSpace(string(output)) != "True" {
		t.Fatal("expected fresh isolated app rule", string(output))
	}
	t.Cleanup(func() {
		output, err := run("Remove-NativeTcpFirewallAdmission")
		if err != nil {
			t.Error("remove isolated app rule", err, string(output))
		}
	})
}
