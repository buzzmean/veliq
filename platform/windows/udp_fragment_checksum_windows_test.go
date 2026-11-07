//go:build windows

package windowsplatform

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"testing"
	"unsafe"

	"github.com/buzzmean/neexitlag/core/localstrategy"
)

// The DLL helper is the same final mutation used before native reinjection.
// This is entirely offline: no WinDivertOpen, service or kernel capture handle.
func TestUDPFragmentNativeChecksumHelper(t *testing.T) {
	dll := loadPinnedFilterDLL(t)
	calc, err := dll.FindProc("WinDivertHelperCalcChecksums")
	if err != nil {
		t.Fatal(err)
	}
	for _, split := range []int{8, 16, 24} {
		for _, size := range []int{21 + split, 128, 1500} {
			t.Run(fmt.Sprintf("split%d/bytes%d", split, size), func(t *testing.T) {
				raw, tuple := gamePacket()
				raw = append(raw[:28], bytes.Repeat([]byte{0x5a}, size-28)...)
				binary.BigEndian.PutUint16(raw[2:], uint16(size))
				binary.BigEndian.PutUint16(raw[4:], 0x1234)
				binary.BigEndian.PutUint16(raw[24:], uint16(size-20))
				e := localstrategy.New()
				p := localstrategy.Profile{ID: "fragment", Version: 1, Application: `C:\Games\cs2.exe`, Protocol: "udp", Ports: []uint16{tuple.Destination.Port()}, IPs: []string{tuple.Destination.Addr().String()}, Strategy: fmt.Sprintf("udp-fragment-%d", split), ContinuousUDP: true, Enabled: true}
				if err := e.Reload(localstrategy.Config{Version: 1, Enabled: true, User: []localstrategy.Profile{p}}); err != nil {
					t.Fatal(err)
				}
				r := e.Process(raw, &localstrategy.State{}, localstrategy.Metadata{Application: p.Application, Protocol: "udp", Destination: tuple.Destination, StrategyID: p.ID})
				if !r.Modified || len(r.Packets) != 2 || len(r.Packets[0]) != 20+split {
					t.Fatal("fragment plan unavailable")
				}
				for i, q := range r.Packets {
					before := append([]byte(nil), q...)
					var a [80]byte
					a[10] = 2 // outbound, input checksum offload not completed
					a = LocalPacketAddress(q, a)
					ok, _, _ := calc.Call(uintptr(unsafe.Pointer(&q[0])), uintptr(len(q)), uintptr(unsafe.Pointer(&a[0])), 0)
					if !bytes.Equal(before, q) || a[10]&0xa0 != 0xa0 {
						t.Fatalf("native helper changed fragment: return%d equal%v flags%x", ok, bytes.Equal(before, q), a[10])
					}
					// The first fragment has an incomplete UDP datagram: the pinned
					// helper returns false for transport calculation; later fragments
					// only need IP. Precomputed checksum bytes must remain intact.
					wantReturn := uintptr(1)
					if i == 0 {
						wantReturn = 0
					}
					if ok != wantReturn {
						t.Fatalf("unexpected pinned helper return%d want%d", ok, wantReturn)
					}
					t.Logf("fragment bytes%d helper_return%d checksum_flags%x", len(q), ok, a[10])
				}
			})
		}
	}
}
