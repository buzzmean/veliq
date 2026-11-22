package windowsplatform

import (
	"encoding/binary"
	"net/netip"
	"testing"
)

func TestSocketIPv4NativeAddressLayout(t *testing.T) {
	for _, protocol := range []byte{6, 17} {
		for _, event := range []byte{3, 4} {
			var a [80]byte
			a[8], a[9] = 3, event
			d := a[16:]
			binary.LittleEndian.PutUint32(d[16:20], 42)
			// Native 2.2.2 helper representation: 192.0.2.10 / 51.38.142.176.
			copy(d[20:36], []byte{10, 2, 0, 192, 255, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0})
			copy(d[36:52], []byte{176, 142, 38, 51, 255, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0})
			binary.LittleEndian.PutUint16(d[52:54], 50000)
			binary.LittleEndian.PutUint16(d[54:56], 27015)
			d[56] = protocol
			wantProtocol := "tcp"
			if protocol == 17 {
				wantProtocol = "udp"
			}
			want := Tuple{wantProtocol, netip.MustParseAddrPort("192.0.2.10:50000"), netip.MustParseAddrPort("51.38.142.176:27015")}
			pid, got, err := DecodeSocketEvent(a)
			if err != nil || pid != 42 || got != want {
				t.Fatalf("protocol=%d event=%d: pid=%d tuple=%v want=%v err=%v", protocol, event, pid, got, want, err)
			}
		}
	}
}
