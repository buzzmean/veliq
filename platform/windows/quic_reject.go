package windowsplatform

import (
	"encoding/binary"
	"errors"
)

// A port-unreachable quotes only the IPv4 and UDP headers, never QUIC payload.
// It is emitted once for an attributable native-browser UDP/443 flow so the
// browser can try TCP immediately instead of waiting for a black-holed QUIC.
func RejectBrowserQUIC(packet []byte) ([]byte, error) {
	tuple, _, err := ParseUDP(packet)
	if err != nil || tuple.Destination.Port() != 443 {
		return nil, errors.New("QUIC_REJECT_INVALID_PACKET")
	}
	h := int(packet[0]&15) * 4
	reply := make([]byte, 20+8+h+8)
	reply[0] = 0x45
	reply[8] = 64
	reply[9] = 1
	binary.BigEndian.PutUint16(reply[2:4], uint16(len(reply)))
	copy(reply[12:16], packet[16:20])
	copy(reply[16:20], packet[12:16])
	reply[20] = 3
	reply[21] = 3
	copy(reply[28:], packet[:h+8])
	sum := func(b []byte) uint16 {
		var s uint32
		for i := 0; i+1 < len(b); i += 2 {
			s += uint32(binary.BigEndian.Uint16(b[i : i+2]))
		}
		if len(b)%2 != 0 {
			s += uint32(b[len(b)-1]) << 8
		}
		for s>>16 != 0 {
			s = (s & 0xffff) + (s >> 16)
		}
		return ^uint16(s)
	}
	binary.BigEndian.PutUint16(reply[10:12], sum(reply[:20]))
	binary.BigEndian.PutUint16(reply[22:24], sum(reply[20:]))
	return reply, nil
}
