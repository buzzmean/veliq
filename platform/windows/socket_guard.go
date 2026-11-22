package windowsplatform

import (
	"encoding/binary"
	"errors"
	"net/netip"
)

// DecodeSocketEvent reads native SOCKET_BIND/CONNECT events. A
// connect gives us identity before a SYN, including dual-stack sockets.
// This is observation only; NETWORK guard implements packet decisions.
func DecodeSocketEvent(a [80]byte) (uint32, Tuple, error) {
	if a[8] != 3 || (a[9] != 3 && a[9] != 4) {
		return 0, Tuple{}, errors.New("not socket bind/connect")
	}
	data := a[16:]
	protocol := "tcp"
	if data[56] == 17 {
		protocol = "udp"
	} else if data[56] != 6 {
		return 0, Tuple{}, errors.New("unsupported protocol")
	}
	decode := func(b []byte) netip.Addr {
		if a[10]&16 == 0 {
			var ip [4]byte
			binary.BigEndian.PutUint32(ip[:], binary.LittleEndian.Uint32(b[0:4]))
			return netip.AddrFrom4(ip)
		}
		var ip [16]byte
		for i := 0; i < 4; i++ {
			binary.BigEndian.PutUint32(ip[i*4:], binary.LittleEndian.Uint32(b[(3-i)*4:]))
		}
		return netip.AddrFrom16(ip).Unmap()
	}
	return binary.LittleEndian.Uint32(data[16:20]), Tuple{protocol, netip.AddrPortFrom(decode(data[20:36]), binary.LittleEndian.Uint16(data[52:54])), netip.AddrPortFrom(decode(data[36:52]), binary.LittleEndian.Uint16(data[54:56]))}, nil
}
