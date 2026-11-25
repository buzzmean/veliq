//go:build windows

package clientservice

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Explicit disposable VM gate: real sandboxed Chrome AND Edge, actual signed
// WinDivert, production filter, real IP Helper owners, hot profile publication,
// controller native opener and authenticated relay. No synthetic packet writer,
// no PAC, no disabled firewall, no trust changes or production credentials.
func TestWindowsNativeBrowserDriverHotAttach(t *testing.T) {
	if os.Getenv("VELIQ_TEST_NATIVE_BROWSER_DRIVER") != "1" {
		t.Skip("explicit disposable Windows signed-driver fixture")
	}
	if os.Getenv("VELIQ_TEST_DRIVER_DIR") == "" {
		t.Fatal("signed driver pins required, cannot claim PASS")
	}
	preflight := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-Command", "$ErrorActionPreference='Stop';if(Get-Service neexitlag -ErrorAction SilentlyContinue){throw 'DISPOSABLE_VM_REQUIRED: installed service must not be touched'}")
	if output, err := preflight.CombinedOutput(); err != nil {
		t.Fatal("fixture cannot run on an installed owner PC", err, string(output))
	}
	if os.Getenv("VELIQ_NATIVE_BROWSER_DRIVER_CHILD") != "1" {
		// Use the exact application-name contract of the production firewall helper.
		directory, err := os.MkdirTemp(t.TempDir(), "driver-service-")
		if err != nil {
			t.Fatal(err)
		}
		own, err := os.Executable()
		if err != nil {
			t.Fatal(err)
		}
		raw, err := os.ReadFile(own)
		if err != nil {
			t.Fatal(err)
		}
		child := filepath.Join(directory, "veliq-service.exe")
		if err = os.WriteFile(child, raw, 0700); err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 150*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, child, "-test.run=^TestWindowsNativeBrowserDriverHotAttach$", "-test.v")
		cmd.Env = append(os.Environ(), "VELIQ_NATIVE_BROWSER_DRIVER_CHILD=1")
		output, err := cmd.CombinedOutput()
		t.Log(string(output))
		if err != nil {
			t.Fatal("actual WinDivert browser fixture", err)
		}
		return
	}
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
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		script := "$ErrorActionPreference='Stop';. " + quote(helper) + ";" + operation + " " + quote(exe)
		return exec.CommandContext(ctx, "powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script).CombinedOutput()
	}
	output, err := run("Add-NativeTcpFirewallAdmission")
	if err != nil {
		t.Fatal("production app-scoped firewall admission", err, string(output))
	}
	if strings.TrimSpace(string(output)) != "True" {
		t.Fatal("disposable VM must not have an existing owned service rule", string(output))
	}
	t.Cleanup(func() {
		output, err := run("Remove-NativeTcpFirewallAdmission")
		if err != nil {
			t.Error("owned fixture cleanup", err, string(output))
		}
	})
	runNativeBrowserHotAttachFixture(t, true)
}
