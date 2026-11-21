//go:build windows

package windowsplatform

import (
	"context"
	"fmt"
	"github.com/buzzmean/neexitlag/core/routing"
	"os"
	"os/exec"
	"testing"
	"time"
)

// Only compiled into this package's test binary. No production API enables the
// loopback driver seam, changes destination policy or certificate validation.
func NewBrowserLoopbackFixture(files DriverFiles, engine *routing.Engine) *WinDivertBackend {
	b := NewWinDivert(files, engine)
	b.testBrowserLoopback = true
	return b
}

func (b *WinDivertBackend) TraceNativeFixture(f func(string, Tuple, byte, byte)) {
	if !b.testBrowserLoopback {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.tcp != nil {
		b.tcp.fixtureTrace.Store(&nativeTCPTraceHook{f: f})
	}
}

// Isolated CI only: do not disable Windows Firewall or admit a subnet. The test
// listener still rejects every connection without an exact native state entry.
func (b *WinDivertBackend) AdmitNativeFixtureListener(t testing.TB) {
	t.Helper()
	if !b.testBrowserLoopback {
		t.Fatal("fixture-only firewall admission")
	}
	b.mu.Lock()
	port := b.tcp.port
	b.mu.Unlock()
	name := fmt.Sprintf("veliq-driver-fixture-%d-%d", os.Getpid(), port)
	run := func(script string) ([]byte, error) {
		ctx, stop := context.WithTimeout(context.Background(), 15*time.Second)
		defer stop()
		return exec.CommandContext(ctx, "powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script).CombinedOutput()
	}
	profiles, err := run("$ErrorActionPreference='Stop';Get-NetFirewallProfile | Select-Object Name,Enabled,DefaultInboundAction | Format-Table -AutoSize")
	if err != nil {
		t.Fatal("read fixture firewall state", err, string(profiles))
	}
	t.Log(string(profiles))
	script := fmt.Sprintf("$ErrorActionPreference='Stop';New-NetFirewallRule -Name '%s' -DisplayName '%s' -Direction Inbound -Action Allow -Protocol TCP -LocalPort %d -RemoteAddress 192.0.2.254 | Out-Null", name, name, port)
	output, err := run(script)
	if err != nil {
		t.Fatal("fixture listener admission", err, string(output))
	}
	t.Cleanup(func() {
		output, err := run("$ErrorActionPreference='Stop';Remove-NetFirewallRule -Name '" + name + "' -ErrorAction Stop")
		if err != nil {
			t.Error("remove owned fixture admission", err, string(output))
		}
	})
}

func (b *WinDivertBackend) NativeFixtureListenerPort() uint16 {
	if !b.testBrowserLoopback {
		return 0
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.tcp == nil {
		return 0
	}
	return b.tcp.port
}
