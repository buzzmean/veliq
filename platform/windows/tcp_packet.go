package windowsplatform

import (
	"encoding/binary"
	"errors"
	"net/netip"
)

// ParseTCP rejects fragments, truncation and invalid option/header lengths.
// TLS/application bytes are never parsed or modified.
func ParseTCP(p []byte) (Tuple, byte, int, error) {
	if len(p) < 40 || p[0]>>4 != 4 {
		return Tuple{}, 0, 0, errors.New("not complete IPv4 TCP")
	}
	h := int(p[0]&15) * 4
	if h < 20 || h+20 > len(p) || int(binary.BigEndian.Uint16(p[2:4])) != len(p) || p[9] != 6 || binary.BigEndian.Uint16(p[6:8])&0x3fff != 0 {
		return Tuple{}, 0, 0, errors.New("fragmented or malformed TCP")
	}
	th := int(p[h+12]>>4) * 4
	if th < 20 || h+th > len(p) {
		return Tuple{}, 0, 0, errors.New("invalid TCP header")
	}
	var s, d [4]byte
	copy(s[:], p[12:16])
	copy(d[:], p[16:20])
	return Tuple{"tcp", netip.AddrPortFrom(netip.AddrFrom4(s), binary.BigEndian.Uint16(p[h:h+2])), netip.AddrPortFrom(netip.AddrFrom4(d), binary.BigEndian.Uint16(p[h+2:h+4]))}, p[h+13], len(p) - h - th, nil
}

// ReflectTCP follows WinDivert's network-layer stream reflection technique.
// A unique virtual peer port prevents collisions between connections sharing a
// local port but using different destinations. WinDivert calculates checksums.
func ReflectTCP(p []byte, source, destination netip.AddrPort) ([]byte, error) {
	if _, _, _, e := ParseTCP(p); e != nil {
		return nil, e
	}
	if !source.Addr().Is4() || !destination.Addr().Is4() {
		return nil, errors.New("IPv4 required")
	}
	out := append([]byte(nil), p...)
	h := int(out[0]&15) * 4
	s, d := source.Addr().As4(), destination.Addr().As4()
	copy(out[12:16], s[:])
	copy(out[16:20], d[:])
	binary.BigEndian.PutUint16(out[h:h+2], source.Port())
	binary.BigEndian.PutUint16(out[h+2:h+4], destination.Port())
	out[10], out[11], out[h+16], out[h+17] = 0, 0, 0, 0
	return out, nil
}

// tcpOwners reads TCP_TABLE_OWNER_PID_ALL. Match the full original tuple;
// guessing an owner from a port alone can intercept the wrong application.
func tcpOwners(b []byte, t Tuple, ipv6 bool) (map[uint32]bool, error) {
	width := 24
	if ipv6 {
		width = 56
	}
	if len(b) < 4 || uint64(binary.LittleEndian.Uint32(b))*uint64(width) > uint64(len(b)-4) {
		return nil, errors.New("invalid TCP owner table")
	}
	out := map[uint32]bool{}
	for i := 0; i < int(binary.LittleEndian.Uint32(b)); i++ {
		r := b[4+i*width : 4+(i+1)*width]
		var s, d netip.Addr
		var sp, dp, pid int
		if ipv6 {
			var a, c [16]byte
			copy(a[:], r[:16])
			copy(c[:], r[24:40])
			s, d = netip.AddrFrom16(a).Unmap(), netip.AddrFrom16(c).Unmap()
			sp, dp, pid = 20, 44, 52
		} else {
			var a, c [4]byte
			copy(a[:], r[4:8])
			copy(c[:], r[12:16])
			s, d = netip.AddrFrom4(a), netip.AddrFrom4(c)
			sp, dp, pid = 8, 16, 20
		}
		if s == t.Source.Addr() && d == t.Destination.Addr() && binary.BigEndian.Uint16(r[sp:sp+2]) == t.Source.Port() && binary.BigEndian.Uint16(r[dp:dp+2]) == t.Destination.Port() {
			p := binary.LittleEndian.Uint32(r[pid : pid+4])
			if p != 0 {
				out[p] = true
			}
		}
	}
	return out, nil
}
