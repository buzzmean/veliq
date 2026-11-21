package windowsplatform

import (
	"encoding/binary"
	"errors"
	"github.com/buzzmean/neexitlag/core/protocol"
	"net/netip"
)

// ParseUDP only accepts complete unfragmented IPv4 datagrams. Other traffic stays DIRECT.
func ParseUDP(packet []byte) (Tuple, []byte, error) {
	if len(packet) < 28 || packet[0]>>4 != 4 {
		return Tuple{}, nil, errors.New("not complete IPv4 UDP")
	}
	ihl := int(packet[0]&15) * 4
	size := int(binary.BigEndian.Uint16(packet[2:4]))
	if ihl < 20 || ihl+8 > len(packet) || size != len(packet) || packet[9] != 17 || binary.BigEndian.Uint16(packet[6:8])&0x3fff != 0 {
		return Tuple{}, nil, errors.New("fragmented or malformed UDP")
	}
	udp := packet[ihl:]
	n := int(binary.BigEndian.Uint16(udp[4:6]))
	if n != len(udp) || n < 8 {
		return Tuple{}, nil, errors.New("invalid UDP length")
	}
	var src, dst [4]byte
	copy(src[:], packet[12:16])
	copy(dst[:], packet[16:20])
	t := Tuple{"udp", netip.AddrPortFrom(netip.AddrFrom4(src), binary.BigEndian.Uint16(udp[:2])), netip.AddrPortFrom(netip.AddrFrom4(dst), binary.BigEndian.Uint16(udp[2:4]))}
	return t, udp[8:], nil
}

// Keep only validated headers for reply reconstruction, not a retained payload.
func udpReplyTemplate(packet []byte) []byte {
	h := int(packet[0]&15) * 4
	out := append([]byte(nil), packet[:h+8]...)
	binary.BigEndian.PutUint16(out[2:4], uint16(len(out)))
	binary.BigEndian.PutUint16(out[h+4:h+6], 8)
	return out
}
func ReplyUDP(template, payload []byte) ([]byte, error) {
	tuple, _, err := ParseUDP(template)
	if err != nil || len(payload) > protocol.MaxPayload {
		return nil, errors.New("invalid UDP reply")
	}
	ihl := int(template[0]&15) * 4
	b := make([]byte, ihl+8+len(payload))
	copy(b, template[:ihl+8])
	src, dst := tuple.Source.Addr().As4(), tuple.Destination.Addr().As4()
	copy(b[12:16], dst[:])
	copy(b[16:20], src[:])
	binary.BigEndian.PutUint16(b[2:4], uint16(len(b)))
	binary.BigEndian.PutUint16(b[6:8], 0)
	binary.BigEndian.PutUint16(b[ihl:ihl+2], tuple.Destination.Port())
	binary.BigEndian.PutUint16(b[ihl+2:ihl+4], tuple.Source.Port())
	binary.BigEndian.PutUint16(b[ihl+4:ihl+6], uint16(8+len(payload)))
	b[10] = 0
	b[11] = 0
	b[ihl+6] = 0
	b[ihl+7] = 0
	copy(b[ihl+8:], payload)
	return b, nil
}
