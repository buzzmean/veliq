//go:build windows

package windowsplatform

import (
	"net/netip"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

func TestPrivateISCSIExcludedByActualWinDivertFilterEvaluator(t *testing.T) {
	dll := loadPinnedFilterDLL(t)
	eval, err := dll.FindProc("WinDivertHelperEvalFilter")
	if err != nil {
		t.Fatal(err)
	}
	compile, err := dll.FindProc("WinDivertHelperCompileFilter")
	if err != nil {
		t.Fatal(err)
	}
	if err := compileDivertFilter(compile, nativeTCPNetworkFilter(50165, false), 0); err != nil {
		t.Fatal(err)
	}
	filter, _ := windows.BytePtrFromString(nativeTCPNetworkFilter(50165, false))
	cases := []struct {
		src, dst   string
		out, match bool
	}{
		{"192.168.88.10:50000", "192.168.88.252:3260", true, false},
		{"192.168.88.10:50000", "10.0.0.0:3260", true, false},
		{"10.0.0.0:3260", "192.168.88.10:50000", false, false},
		{"192.168.88.10:50000", "10.255.255.255:3260", true, false},
		{"10.255.255.255:3260", "192.168.88.10:50000", false, false},
		{"192.168.88.10:50000", "9.255.255.255:3260", true, true},
		{"9.255.255.255:3260", "192.168.88.10:50000", false, true},
		{"192.168.88.10:50000", "11.0.0.0:3260", true, true},
		{"11.0.0.0:3260", "192.168.88.10:50000", false, true},
		{"192.168.88.10:50000", "172.16.0.0:3260", true, false},
		{"172.16.0.0:3260", "192.168.88.10:50000", false, false},
		{"192.168.88.10:50000", "172.31.255.255:3260", true, false},
		{"172.31.255.255:3260", "192.168.88.10:50000", false, false},
		{"192.168.88.10:50000", "172.15.255.255:3260", true, true},
		{"172.15.255.255:3260", "192.168.88.10:50000", false, true},
		{"192.168.88.10:50000", "172.32.0.0:3260", true, true},
		{"172.32.0.0:3260", "192.168.88.10:50000", false, true},
		{"192.168.88.10:50000", "192.168.0.0:3260", true, false},
		{"192.168.0.0:3260", "192.168.88.10:50000", false, false},
		{"192.168.88.10:50000", "192.168.255.255:3260", true, false},
		{"192.168.255.255:3260", "192.168.88.10:50000", false, false},
		{"192.168.88.10:50000", "192.167.255.255:3260", true, true},
		{"192.167.255.255:3260", "192.168.88.10:50000", false, true},
		{"192.168.88.10:50000", "192.169.0.0:3260", true, true},
		{"192.169.0.0:3260", "192.168.88.10:50000", false, true},
		{"192.168.88.252:3260", "192.168.88.10:50000", false, false},
		{"192.168.88.10:50000", "8.8.8.8:443", true, true},
		{"192.168.88.10:50000", "8.8.8.8:3260", true, true},
		{"192.168.88.10:3260", "8.8.8.8:443", true, true},
		{"8.8.8.8:443", "192.168.88.10:3260", false, true},
	}
	for _, tt := range cases {
		packet := tcpPacket(t, Tuple{Protocol: "tcp", Source: netip.MustParseAddrPort(tt.src), Destination: netip.MustParseAddrPort(tt.dst)})
		var a [80]byte
		if tt.out {
			a[10] = 2
		}
		result, _, _ := eval.Call(uintptr(unsafe.Pointer(filter)), uintptr(unsafe.Pointer(&packet[0])), uintptr(len(packet)), uintptr(unsafe.Pointer(&a[0])))
		if (result != 0) != tt.match {
			t.Fatalf("actual filter src=%s dst=%s matched=%v expected=%v", tt.src, tt.dst, result != 0, tt.match)
		}
	}
}
