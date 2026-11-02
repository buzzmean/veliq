//go:build windows

package windowsplatform

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
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
		name, _ := windows.UTF16PtrFromString("gpsvc")
		handle, openErr := windows.OpenService(manager.Handle, name, windows.SERVICE_QUERY_STATUS)
		if openErr == nil {
			service := &mgr.Service{Name: "gpsvc", Handle: handle}
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
	// Raw policy registry writes are not a Local GPO. Determine whether a
	// configured registry CSE is necessary for the documented event to fire.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	cleanup, err := prepareGPNotificationCanary()
	if err != nil {
		t.Logf("OWNER_GP_CSE unavailable=%v", err)
		return
	}
	defer cleanup()
	immediate, _ := windows.WaitForSingleObject(event, 0)
	t.Logf("OWNER_GP_SAVE notification=%t", immediate == windows.WAIT_OBJECT_0)
	windows.ResetEvent(event)
	started = time.Now()
	state = refreshOwnerUserPolicy(sid)
	observed, err = windows.WaitForSingleObject(event, 8000)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("OWNER_GP_CSE state=%s notification=%t elapsed_ms=%d prepared_for_disposable_job=%t", state, observed == windows.WAIT_OBJECT_0, time.Since(started).Milliseconds(), true)

}

// This canary is test-only, under a disposable machine's Local GPO. It preserves
// all loaded entries and adds only a private, behavior-free VELIQ test value.
// No proxy, security, account, machine policy or production state is written.
func prepareGPNotificationCanary() (func(), error) {
	ole := windows.NewLazySystemDLL("ole32.dll")
	init := ole.NewProc("CoInitializeEx")
	uninit := ole.NewProc("CoUninitialize")
	result, _, _ := init.Call(0, 2)
	if uint32(result)&0x80000000 != 0 {
		return nil, fmt.Errorf("GP_COM_INIT_%08X", uint32(result))
	}
	clsid, _ := windows.GUIDFromString("{EA502722-A23D-11d1-A7D3-0000F87571E3}")
	iid, _ := windows.GUIDFromString("{EA502723-A23D-11d1-A7D3-0000F87571E3}")
	extension, _ := windows.GUIDFromString("{35378EAC-683F-11D2-A89A-00C04FBBCFA2}")
	snapin, _ := windows.GUIDFromString("{A15C6F71-3971-4F5F-BE41-86028AC523E8}")
	var object uintptr
	result, _, _ = ole.NewProc("CoCreateInstance").Call(uintptr(unsafe.Pointer(&clsid)), 0, 1, uintptr(unsafe.Pointer(&iid)), uintptr(unsafe.Pointer(&object)))
	if uint32(result)&0x80000000 != 0 {
		uninit.Call()
		return nil, fmt.Errorf("GP_COM_CREATE_%08X", uint32(result))
	}
	table := *(**[21]uintptr)(unsafe.Pointer(object))
	release := func() { syscall.SyscallN(table[2], object); uninit.Call() }
	call := func(slot int, args ...uintptr) error {
		values := append([]uintptr{object}, args...)
		result, _, _ := syscall.SyscallN(table[slot], values...)
		if uint32(result)&0x80000000 != 0 {
			return fmt.Errorf("GP_METHOD_%d_%08X", slot, uint32(result))
		}
		return nil
	}
	if err := call(5, 1); err != nil {
		release()
		return nil, err
	} // OpenLocalMachineGPO(LOAD_REGISTRY)
	var root registry.Key
	if err := call(15, 1, uintptr(unsafe.Pointer(&root))); err != nil {
		release()
		return nil, err
	} // USER section
	key, _, err := registry.CreateKey(root, `Software\Policies\VELIQTest`, registry.QUERY_VALUE|registry.SET_VALUE)
	if err != nil {
		root.Close()
		release()
		return nil, fmt.Errorf("GP_CANARY_KEY")
	}
	name := fmt.Sprintf("Notification-%d", os.Getpid())
	if _, _, err := key.GetValue(name, nil); err != registry.ErrNotExist {
		key.Close()
		root.Close()
		release()
		return nil, fmt.Errorf("GP_CANARY_EXISTS")
	}
	if err := key.SetDWordValue(name, 1); err != nil {
		key.Close()
		root.Close()
		release()
		return nil, fmt.Errorf("GP_CANARY_WRITE")
	}
	save := func(add uintptr) error {
		return call(7, 0, add, uintptr(unsafe.Pointer(&extension)), uintptr(unsafe.Pointer(&snapin)))
	}
	if err := save(1); err != nil {
		key.DeleteValue(name)
		key.Close()
		root.Close()
		release()
		return nil, err
	}
	// Release the editor/hive before asking gpsvc to process this GPO.
	// The disposable runner is destroyed after this job; this behavior-free
	// canary remains only for subsequent steps in this same isolated VM.
	key.Close()
	root.Close()
	release()
	return func() {}, nil
}

// Used by the isolated browser test after its owned proxy value is written.
// No application code calls this helper, and no shared/user PC is supported.
func TestCommitUserGPOCanary(t *testing.T) {
	if os.Getenv("VELIQ_GPO_NOTIFICATION_COMMIT") != "1" {
		t.Skip("explicit Local GPO probe")
	}
	if os.Getenv("GITHUB_ACTIONS") != "true" {
		t.Fatal("disposable Actions VM required")
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	_, err := prepareGPNotificationCanary()
	if err != nil {
		t.Fatal(err)
	}
	t.Log("OWNER_GP_SAVE_COMMITTED released_editor=true")
}
