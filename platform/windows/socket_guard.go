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
	ipv6 := a[10]&16 != 0
	src := decodeDivertAddress(data[20:36], ipv6)
	dst := decodeDivertAddress(data[36:52], ipv6)
	return binary.LittleEndian.Uint32(data[16:20]), Tuple{protocol, netip.AddrPortFrom(src, binary.LittleEndian.Uint16(data[52:54])), netip.AddrPortFrom(dst, binary.LittleEndian.Uint16(data[54:56]))}, nil
}

// WinDivert FLOW and SOCKET use the same host-order address words, with
// IPv4 in word zero and IPv6 words in least-significant-first order.
func decodeDivertAddress(words []byte, ipv6 bool) netip.Addr {
	if !ipv6 {
		var ip [4]byte
		binary.BigEndian.PutUint32(ip[:], binary.LittleEndian.Uint32(words[:4]))
		return netip.AddrFrom4(ip)
	}
	var ip [16]byte
	for i := 0; i < 4; i++ {
		binary.BigEndian.PutUint32(ip[i*4:], binary.LittleEndian.Uint32(words[(3-i)*4:]))
	}
	return netip.AddrFrom16(ip).Unmap()
}
