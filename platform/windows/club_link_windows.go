//go:build windows

package windowsplatform

import (
	"errors"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// PassiveClubLinks never opens a network connection, changes SCM state or uses
// the hot-attach reset path. A native/ownership failure invalidates the sample.
func PassiveClubLinks() (ClubLinkSnapshot, error) {
	root, err := clubLinkServiceOwner()
	if err != nil {
		return ClubLinkSnapshot{}, err
	}
	started := uint64(time.Now().UnixNano()/100) + 116444736000000000
	var rows []clubLinkTCPRow
	for _, family := range []uintptr{2, 23} {
		part, err := readClubLinkTCPFamily(family)
		if err != nil {
			return ClubLinkSnapshot{}, err
		}
		rows = append(rows, part...)
	}
	out, err := filterClubLinkTCPRows(root, rows, NewDiscovery().Lookup, started)
	if err != nil {
		return ClubLinkSnapshot{}, err
	}
	after, err := clubLinkServiceOwner()
	if err != nil || root.PID == 0 && after.PID != 0 || root.PID != 0 && !sameLanGameInstance(root, after) {
		return ClubLinkSnapshot{}, errors.New("CLUB_LINK_SERVICE_CHANGED")
	}
	return out, nil
}

func readClubLinkTCPFamily(family uintptr) ([]clubLinkTCPRow, error) {
	width := uint32(24)
	if family == 23 {
		width = 56
	}
	limit := uint32(4) + clubLinkTCPRowLimit*width
	var size uint32
	r, _, _ := getTCPTable.Call(0, uintptr(unsafe.Pointer(&size)), 0, family, 5, 0)
	if uint32(r) == uint32(windows.ERROR_NOT_SUPPORTED) && family == 23 {
		return nil, nil
	}
	if uint32(r) != uint32(windows.ERROR_INSUFFICIENT_BUFFER) || size < 4 || size > limit {
		return nil, errors.New("CLUB_LINK_TCP_TABLE_SIZING")
	}
	for range 3 {
		if size < 4 || size > limit {
			return nil, errors.New("CLUB_LINK_TCP_TABLE_BOUND")
		}
		raw := make([]byte, size)
		r, _, _ = getTCPTable.Call(uintptr(unsafe.Pointer(&raw[0])), uintptr(unsafe.Pointer(&size)), 0, family, 5, 0)
		if uint32(r) == uint32(windows.ERROR_INSUFFICIENT_BUFFER) {
			continue
		}
		if r != 0 || size > uint32(len(raw)) {
			return nil, errors.New("CLUB_LINK_TCP_TABLE_READ")
		}
		return decodeClubLinkTCPTable(raw[:size], family == 23)
	}
	return nil, errors.New("CLUB_LINK_TCP_TABLE_CHURN")
}

func clubLinkServiceOwner() (ProcessIdentity, error) {
	manager, err := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_CONNECT)
	if err != nil {
		return ProcessIdentity{}, errors.New("CLUB_LINK_SCM_UNAVAILABLE")
	}
	defer windows.CloseServiceHandle(manager)
	name, _ := windows.UTF16PtrFromString("LanGameService")
	service, err := windows.OpenService(manager, name, windows.SERVICE_QUERY_STATUS)
	if err != nil {
		return ProcessIdentity{}, errors.New("CLUB_LINK_SERVICE_UNAVAILABLE")
	}
	defer windows.CloseServiceHandle(service)
	var status windows.SERVICE_STATUS_PROCESS
	var size uint32
	if windows.QueryServiceStatusEx(service, windows.SC_STATUS_PROCESS_INFO, (*byte)(unsafe.Pointer(&status)), uint32(unsafe.Sizeof(status)), &size) != nil {
		return ProcessIdentity{}, errors.New("CLUB_LINK_SCM_UNAVAILABLE")
	}
	if status.CurrentState == windows.SERVICE_STOPPED {
		return ProcessIdentity{}, nil
	}
	if status.CurrentState != windows.SERVICE_RUNNING || status.ProcessId == 0 || status.ServiceType&windows.SERVICE_WIN32_OWN_PROCESS == 0 {
		return ProcessIdentity{}, errors.New("CLUB_LINK_SERVICE_TRANSITION")
	}
	id, err := NewDiscovery().Lookup(status.ProcessId)
	if err != nil || !verifyLanGameOwner(id) || !IsCurrent(id) {
		return ProcessIdentity{}, errors.New("CLUB_LINK_OWNER_UNAVAILABLE")
	}
	return id, nil
}
