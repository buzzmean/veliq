//go:build windows

package windowsplatform

import (
	"golang.org/x/sys/windows"
	"unsafe"
)

// Read-only SCM query works without elevation; never Starts/Stops a service.
func BrowserRecoveryServiceState() string {
	manager, e := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_CONNECT)
	if e != nil {
		return "UNKNOWN"
	}
	defer windows.CloseServiceHandle(manager)
	name, _ := windows.UTF16PtrFromString(ServiceName)
	service, e := windows.OpenService(manager, name, windows.SERVICE_QUERY_STATUS)
	if e == windows.ERROR_SERVICE_DOES_NOT_EXIST {
		return "NOT_INSTALLED"
	}
	if e != nil {
		return "UNKNOWN"
	}
	defer windows.CloseServiceHandle(service)
	var status windows.SERVICE_STATUS_PROCESS
	var needed uint32
	if windows.QueryServiceStatusEx(service, windows.SC_STATUS_PROCESS_INFO, (*byte)(unsafe.Pointer(&status)), uint32(unsafe.Sizeof(status)), &needed) != nil {
		return "UNKNOWN"
	}
	switch status.CurrentState {
	case windows.SERVICE_RUNNING:
		return "RUNNING"
	case windows.SERVICE_START_PENDING:
		return "START_PENDING"
	case windows.SERVICE_STOP_PENDING:
		return "STOP_PENDING"
	case windows.SERVICE_STOPPED:
		return "STOPPED"
	}
	return "UNKNOWN"
}
