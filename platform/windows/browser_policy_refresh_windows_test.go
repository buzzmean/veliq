//go:build windows

package windowsplatform

import (
	"context"
	"os"
	"os/exec"
	"testing"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc/mgr"
)

// Observe the documented notification Chromium actually subscribes to. A TRUE
// RefreshPolicyEx return is not evidence of delivery or of browser policy uptake.
// The command comparison is isolated to a disposable runner, never product code.
func TestOwnerPolicyRefreshEventProbe(t *testing.T) {
	if os.Getenv("VELIQ_TEST_GP_NOTIFY") != "1" {
		t.Skip("explicit Windows GP event probe")
	}
	if os.Getenv("GITHUB_ACTIONS") != "true" {
		t.Fatal("disposable Actions runner required")
	}
	token, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	sid := token.User.Sid.String()
	event, err := windows.CreateEvent(nil, 0, 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer windows.CloseHandle(event)
	dll := windows.NewLazySystemDLL("userenv.dll")
	register := dll.NewProc("RegisterGPNotification")
	unregister := dll.NewProc("UnregisterGPNotification")
	ok, _, callErr := register.Call(uintptr(event), 0)
	if ok == 0 {
		t.Fatalf("OWNER_GP_EVENT registration failed: %v", callErr)
	}
	defer unregister.Call(uintptr(event))
	var session uint32
	if err := windows.ProcessIdToSessionId(windows.GetCurrentProcessId(), &session); err != nil {
		t.Fatal(err)
	}
	active, _, _ := windows.NewLazySystemDLL("kernel32.dll").NewProc("WTSGetActiveConsoleSessionId").Call()
	serviceState := uint32(0)
	if manager, err := mgr.Connect(); err == nil {
		if service, err := manager.OpenService("gpsvc"); err == nil {
			if status, err := service.Query(); err == nil {
				serviceState = uint32(status.State)
			}
			service.Close()
		}
		manager.Disconnect()
	}
	t.Logf("OWNER_GP_CONTEXT process_session=%d console_session=%d gpsvc_state=%d", session, uint32(active), serviceState)
	started := time.Now()
	state := refreshOwnerUserPolicy(sid)
	observed, err := windows.WaitForSingleObject(event, 8000)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("OWNER_GP_NATIVE state=%s notification=%t elapsed_ms=%d", state, observed == windows.WAIT_OBJECT_0, time.Since(started).Milliseconds())
	// Exercise the standard user-only command as an independent delivery probe.
	// No logoff/boot switches, no output containing machine/user/domain names.
	windows.ResetEvent(event)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, "gpupdate.exe", "/target:user", "/force", "/wait:5")
	started = time.Now()
	err = command.Run()
	exit := 0
	if err != nil {
		exit = -1
		if command.ProcessState != nil {
			exit = command.ProcessState.ExitCode()
		}
	}
	observed, err = windows.WaitForSingleObject(event, 8000)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("OWNER_GP_COMMAND exit=%d notification=%t elapsed_ms=%d timed_out=%t", exit, observed == windows.WAIT_OBJECT_0, time.Since(started).Milliseconds(), ctx.Err() != nil)
}
