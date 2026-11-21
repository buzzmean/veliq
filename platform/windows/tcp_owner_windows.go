//go:build windows

package windowsplatform

import (
	"fmt"
	"golang.org/x/sys/windows"
	"unsafe"
)

var getTCPTable = windows.NewLazySystemDLL("iphlpapi.dll").NewProc("GetExtendedTcpTable")

func resolveTCPOwner(t Tuple) (uint32, error) {
	owners := map[uint32]bool{}
	for _, family := range []uintptr{2, 23} {
		var size uint32
		r, _, _ := getTCPTable.Call(0, uintptr(unsafe.Pointer(&size)), 0, family, 5, 0)
		if uint32(r) == uint32(windows.ERROR_NOT_SUPPORTED) && family == 23 {
			continue
		}
		if uint32(r) != uint32(windows.ERROR_INSUFFICIENT_BUFFER) || size < 4 || size > 8*1024*1024 {
			return 0, fmt.Errorf("TCP_OWNER_TABLE_SIZING family=%d code=%d bytes=%d", family, r, size)
		}
		var b []byte
		for tries := 0; tries < 3; tries++ {
			if size < 4 || size > 8*1024*1024 {
				return 0, fmt.Errorf("TCP_OWNER_TABLE_SIZE family=%d bytes=%d", family, size)
			}
			b = make([]byte, size)
			r, _, _ = getTCPTable.Call(uintptr(unsafe.Pointer(&b[0])), uintptr(unsafe.Pointer(&size)), 0, family, 5, 0)
			if uint32(r) != uint32(windows.ERROR_INSUFFICIENT_BUFFER) {
				break
			}
		}
		if r != 0 {
			return 0, fmt.Errorf("TCP_OWNER_TABLE_READ family=%d code=%d bytes=%d", family, r, size)
		}
		found, e := tcpOwners(b, t, family == 23)
		if e != nil {
			return 0, e
		}
		for p := range found {
			owners[p] = true
		}
	}
	if len(owners) == 0 {
		return 0, fmt.Errorf("TCP_OWNER_NOT_FOUND")
	}
	if len(owners) != 1 {
		return 0, fmt.Errorf("TCP_OWNER_AMBIGUOUS")
	}
	for pid := range owners {
		return pid, nil
	}
	panic("unreachable")
}
