//go:build windows

package windowsplatform

import (
	"bytes"
	"github.com/buzzmean/neexitlag/core/gameudp"
	"testing"
	"unsafe"
)

// Helper-only proof: never opens WinDivert, a socket or a service.
func TestGameInitialPrimerNativeChecksumHelper(t *testing.T) {
	dll := loadPinnedFilterDLL(t)
	calc, err := dll.FindProc("WinDivertHelperCalcChecksums")
	if err != nil {
		t.Fatal(err)
	}
	for _, ttl := range []uint8{1, 4, 8, 16} {
		raw, _ := gamePacket()
		payload, err := gameudp.InitialPayload()
		if err != nil {
			t.Fatal(err)
		}
		q, err := gameUDPPacketTTL(raw, payload, ttl)
		if err != nil {
			t.Fatal(err)
		}
		before := append([]byte(nil), q...)
		var a [80]byte
		a[10] = 2
		ok, _, _ := calc.Call(uintptr(unsafe.Pointer(&q[0])), uintptr(len(q)), uintptr(unsafe.Pointer(&a[0])), 0)
		if ok != 1 || !bytes.Equal(q, before) || q[8] != ttl || a[10]&0xa0 != 0xa0 {
			t.Fatal("pinned helper changed valid primer", ok, ttl, a[10])
		}
	}
}
