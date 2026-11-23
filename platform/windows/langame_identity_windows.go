//go:build windows

package windowsplatform

import (
	"path/filepath"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

func lanGameSCMStatus(service windows.Handle) windows.SERVICE_STATUS_PROCESS {
	var status windows.SERVICE_STATUS_PROCESS
	var needed uint32
	err := windows.QueryServiceStatusEx(service, windows.SC_STATUS_PROCESS_INFO,
		(*byte)(unsafe.Pointer(&status)), uint32(unsafe.Sizeof(status)), &needed)
	if err != nil || status.ServiceType&windows.SERVICE_WIN32_OWN_PROCESS == 0 {
		return windows.SERVICE_STATUS_PROCESS{}
	}
	return status
}

func verifyLanGameOwner(request ProcessIdentity) bool {
	manager, err := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_CONNECT)
	if err != nil {
		return false
	}
	defer windows.CloseServiceHandle(manager)
	name, _ := windows.UTF16PtrFromString("LanGameService")
	handle, err := windows.OpenService(manager, name, windows.SERVICE_QUERY_STATUS)
	if err != nil {
		return false
	}
	defer windows.CloseServiceHandle(handle)
	status := lanGameSCMStatus(handle)
	if status.CurrentState != windows.SERVICE_RUNNING && status.CurrentState != windows.SERVICE_START_PENDING {
		return false
	}
	var discovery ProcessDiscovery
	live, err := discovery.Lookup(request.PID)
	if err != nil || !sameLanGameInstance(request, live) {
		return false
	}

	root := live
	if status.CurrentState == windows.SERVICE_START_PENDING {
		// Windows does not guarantee a valid service PID during START_PENDING.
		// Authenticate both the configured image and its live SCM ancestry.
		root = startingLanGameRoot(manager, name, live)
		if root.PID == 0 {
			return false
		}
		after := lanGameSCMStatus(handle)
		return (after.CurrentState == windows.SERVICE_START_PENDING ||
			after.CurrentState == windows.SERVICE_RUNNING && after.ProcessId == root.PID) && IsCurrent(root)
	}
	if live.PID != status.ProcessId {
		if status.ProcessId == 0 || live.ParentPID != status.ProcessId {
			return false
		}
		root, err = discovery.Lookup(status.ProcessId)
		if err != nil {
			return false
		}
	}
	after := lanGameSCMStatus(handle)
	return lanGameOwnershipMatches(request, live, root) && after.CurrentState == windows.SERVICE_RUNNING && after.ProcessId == root.PID
}

func startingLanGameRoot(manager windows.Handle, name *uint16, live ProcessIdentity) ProcessIdentity {
	// A second read-only handle keeps the ordinary RUNNING path available on
	// a service that grants QUERY_STATUS but restricts QUERY_CONFIG.
	h, err := windows.OpenService(manager, name, windows.SERVICE_QUERY_CONFIG)
	if err != nil {
		return ProcessIdentity{}
	}
	defer windows.CloseServiceHandle(h)
	var buf [8192]byte // Documented maximum buffer for QueryServiceConfig.
	config := (*windows.QUERY_SERVICE_CONFIG)(unsafe.Pointer(&buf[0]))
	var needed uint32
	if err = windows.QueryServiceConfig(h, config, uint32(len(buf)), &needed); err != nil {
		return ProcessIdentity{}
	}
	command, err := registry.ExpandString(windows.UTF16PtrToString(config.BinaryPathName))
	if err != nil || !lanGameConfiguredImage(command, live.Path) {
		return ProcessIdentity{}
	}
	var discovery ProcessDiscovery
	root := live
	parent, err := discovery.Lookup(root.ParentPID)
	if err != nil {
		return ProcessIdentity{}
	}
	if strings.EqualFold(parent.Path, live.Path) {
		if !lanGameOwnershipMatches(live, live, parent) {
			return ProcessIdentity{}
		}
		root = parent
		parent, err = discovery.Lookup(root.ParentPID)
		if err != nil {
			return ProcessIdentity{}
		}
	}
	system, err := windows.GetSystemDirectory()
	if err != nil {
		return ProcessIdentity{}
	}
	var session uint32
	if err = windows.ProcessIdToSessionId(parent.PID, &session); err != nil {
		return ProcessIdentity{}
	}
	sid, err := ProcessUserSID(parent)
	if err != nil || !lanGameManagerMatches(root, parent, filepath.Join(system, "services.exe"), sid, session) {
		return ProcessIdentity{}
	}
	return root
}
