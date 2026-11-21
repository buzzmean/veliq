//go:build windows

package windowsplatform

import (
	"errors"
	"fmt"
	"golang.org/x/sys/windows"
	"net/netip"
	"unsafe"
)

var getUDPTable = windows.NewLazySystemDLL("iphlpapi.dll").NewProc("GetExtendedUdpTable")

func queryUDPTable(family uintptr) ([]byte, error) {
	var size uint32
	result, _, _ := getUDPTable.Call(0, uintptr(unsafe.Pointer(&size)), 1, family, 1, 0)
	if uint32(result) == uint32(windows.ERROR_NOT_SUPPORTED) && family == 23 {
		return []byte{0, 0, 0, 0}, nil
	}
	if uint32(result) != uint32(windows.ERROR_INSUFFICIENT_BUFFER) || size < 4 || size > 8*1024*1024 {
		return nil, fmt.Errorf("UDP owner table unavailable (family=%d error=%d)", family, result)
	}
	for tries := 0; tries < 2; tries++ {
		if size < 4 || size > 8*1024*1024 {
			return nil, errors.New("invalid UDP table size")
		}
		b := make([]byte, size)
		result, _, _ = getUDPTable.Call(uintptr(unsafe.Pointer(&b[0])), uintptr(unsafe.Pointer(&size)), 1, family, 1, 0)
		if uint32(result) == uint32(windows.ERROR_INSUFFICIENT_BUFFER) {
			continue
		}
		if result != 0 {
			return nil, errors.New("UDP owner query failed")
		}
		return b, nil
	}
	return nil, errors.New("UDP owner table changed")
}

// IPv4 packets can originate from dual-stack sockets; inspect both ownership tables.
func resolveUDPOwner(source netip.AddrPort) (uint32, error) {
	owners := map[uint32]bool{}
	for _, family := range []uintptr{2, 23} {
		b, e := queryUDPTable(family)
		if e != nil {
			return 0, e
		}
		found, e := udpOwners(b, source, family == 23)
		if e != nil {
			return 0, e
		}
		for pid := range found {
			owners[pid] = true
		}
	}
	return uniqueUDPOwner(owners)
}
