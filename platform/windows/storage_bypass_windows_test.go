//go:build windows

package windowsplatform

import (
	"encoding/binary"
	"net/netip"
	"syscall"
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

func TestClubInfrastructureWithActualWinDivertFilterEvaluator(t *testing.T) {
	dll := loadPinnedFilterDLL(t)
	eval, err := dll.FindProc("WinDivertHelperEvalFilter")
	if err != nil {
		t.Fatal(err)
	}
	const listener = 50165
	for _, test := range []struct {
		peer       string
		remotePort uint16
		localPort  uint16
		protocol   string
		bypass     bool
	}{
		{"192.168.88.252", 1883, 52123, "tcp", true},
		{"10.255.255.255", 1883, 52123, "tcp", true},
		{"172.31.255.255", 1883, 52123, "tcp", true},
		{"172.32.0.1", 1883, 52123, "tcp", false},
		{"192.168.88.252", 1884, 1883, "tcp", false},
		{"192.168.88.252", 53, 52123, "tcp", false},
		{"192.168.88.252", 1883, listener, "tcp", true},
		{"fc00::", 1883, 52123, "tcp", true},
		{"fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", 3260, 52123, "tcp", true},
		{"fbff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", 1883, 52123, "tcp", false},
		{"fe00::", 1883, 52123, "tcp", false},
		{"2001:db8::1", 3260, 1883, "tcp", false},
		{"fd00::1", 443, 1883, "tcp", false},
		{"fd00::1", 1883, 52123, "udp", false},
	} {
		peer := netip.MustParseAddr(test.peer)
		local := netip.MustParseAddr("192.168.88.10")
		expression := nativeTCPNetworkFilter(listener, false)
		if peer.Is6() {
			local = netip.MustParseAddr("fd00::10")
			expression = captureIPv6Filter
		}
		filter, err := windows.BytePtrFromString(expression)
		if err != nil {
			t.Fatal(err)
		}
		tuple := Tuple{Protocol: test.protocol, Source: netip.AddrPortFrom(local, test.localPort), Destination: netip.AddrPortFrom(peer, test.remotePort)}
		if IsPrivateClubInfrastructure(tuple) != test.bypass {
			t.Fatalf("classifier tuple=%v expected bypass=%v", tuple, test.bypass)
		}
		for _, outbound := range []bool{true, false} {
			wire := tuple
			var addr [80]byte
			if outbound {
				addr[10] = 2
			} else {
				wire.Source, wire.Destination = wire.Destination, wire.Source
			}
			var packet []byte
			if peer.Is4() {
				packet = tcpPacket(t, wire)
			} else {
				addr[10] |= 16 // WINDIVERT_ADDRESS.IPv6
				packet = ipv6ClubTestPacket(wire)
			}
			match, _, evalErr := eval.Call(uintptr(unsafe.Pointer(filter)), uintptr(unsafe.Pointer(&packet[0])), uintptr(len(packet)), uintptr(unsafe.Pointer(&addr[0])))
			if match == 0 && evalErr != syscall.Errno(0) {
				t.Fatalf("invalid driver evaluation tuple=%v: %v", wire, evalErr)
			}
			// Replies to an ephemeral client pass outside the capture handle.
			// Physical requests to the wildcard redirect listener still enter its guard.
			want := !test.bypass || (!outbound && peer.Is4() && test.localPort == listener)
			if (match != 0) != want {
				t.Fatalf("driver tuple=%v outbound=%v matched=%v want=%v", wire, outbound, match != 0, want)
			}
		}
	}
}

func ipv6ClubTestPacket(tuple Tuple) []byte {
	size, protocol := 20, byte(6)
	if tuple.Protocol == "udp" {
		size, protocol = 8, 17
	}
	p := make([]byte, 40+size)
	p[0], p[6], p[7] = 0x60, protocol, 64
	binary.BigEndian.PutUint16(p[4:6], uint16(size))
	src, dst := tuple.Source.Addr().As16(), tuple.Destination.Addr().As16()
	copy(p[8:24], src[:])
	copy(p[24:40], dst[:])
	binary.BigEndian.PutUint16(p[40:42], tuple.Source.Port())
	binary.BigEndian.PutUint16(p[42:44], tuple.Destination.Port())
	if protocol == 6 {
		p[52], p[53] = 0x50, 2
	} else {
		binary.BigEndian.PutUint16(p[44:46], uint16(size))
	}
	return p
}

func TestClubInfrastructureExcludedFromActiveTCPReset(t *testing.T) {
	b := &WinDivertBackend{}
	for _, peer := range []string{"192.168.88.252:1883", "192.168.88.252:3260", "[fd12::7]:1883", "[fd12::7]:3260"} {
		row := ownedTCPRow{Tuple: Tuple{Protocol: "tcp", Destination: netip.MustParseAddrPort(peer)}}
		considered, waiting, reset, err := b.reconcileHotTarget(hotAttachTarget{}, row, 0)
		if considered || waiting || reset || err != nil {
			t.Fatalf("hot attach attempted reconciliation of infrastructure peer %s", peer)
		}
		if err := resetOwnedTCP(row, ProcessIdentity{}); err == nil || err.Error() != "HOT_ATTACH infrastructure connection excluded" {
			t.Fatalf("reset guard for %s: %v", peer, err)
		}
	}
}
