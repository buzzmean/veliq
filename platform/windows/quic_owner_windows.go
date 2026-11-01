//go:build windows

package windowsplatform

import (
	"golang.org/x/sys/windows"
	"strings"
	"sync"
	"unsafe"
)

var quicClockOnce sync.Once
var quicClockFrequency int64
var quicPerformanceCounter = kernel.NewProc("QueryPerformanceCounter")

func quicOwnerClock() (int64, int64) {
	quicClockOnce.Do(func() {
		p := kernel.NewProc("QueryPerformanceFrequency")
		ok, _, _ := p.Call(uintptr(unsafe.Pointer(&quicClockFrequency)))
		if ok == 0 {
			quicClockFrequency = 0
		}
	})
	var now int64
	ok, _, _ := quicPerformanceCounter.Call(uintptr(unsafe.Pointer(&now)))
	if ok == 0 {
		return 0, 0
	}
	return now, quicClockFrequency
}

// Birth, image and user SID are read through the SAME process handle. A PID
// replacement between an IsCurrent check and OpenProcess cannot inherit access.
// No handle, SID or token is exported in diagnostics.
func CurrentQUICProcessOwner(id ProcessIdentity, sid string) bool {
	if !browserProcess(id) || id.PID == 0 || id.CreationTime == 0 || sid == "" || len(sid) > 184 {
		return false
	}
	expected, err := windows.StringToSid(sid)
	if err != nil {
		return false
	}
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, id.PID)
	if err != nil {
		return false
	}
	defer windows.CloseHandle(h)
	alive := func() bool {
		var born, exit, kernel, user windows.Filetime
		return windows.GetProcessTimes(h, &born, &exit, &kernel, &user) == nil && exit.HighDateTime == 0 && exit.LowDateTime == 0 && (uint64(born.HighDateTime)<<32|uint64(born.LowDateTime)) == id.CreationTime
	}
	if !alive() {
		return false
	}
	path := make([]uint16, 32768)
	n := uint32(len(path))
	ok, _, _ := queryImage.Call(uintptr(h), 0, uintptr(unsafe.Pointer(&path[0])), uintptr(unsafe.Pointer(&n)))
	if ok == 0 || n > uint32(len(path)) || !strings.EqualFold(strings.ReplaceAll(windows.UTF16ToString(path[:n]), "\\", "/"), strings.ReplaceAll(id.Path, "\\", "/")) {
		return false
	}
	var token windows.Token
	if windows.OpenProcessToken(h, windows.TOKEN_QUERY, &token) != nil {
		return false
	}
	defer token.Close()
	user, err := token.GetTokenUser()
	return err == nil && user.User.Sid.Equals(expected) && alive()
}
