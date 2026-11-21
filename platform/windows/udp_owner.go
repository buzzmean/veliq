package windowsplatform

import (
	"encoding/binary"
	"errors"
	"net/netip"
)

func udpOwners(b []byte, source netip.AddrPort, ipv6 bool) (map[uint32]bool, error) {
	owners := map[uint32]bool{}
	if len(b) < 4 {
		return nil, errors.New("truncated UDP table")
	}
	width := uint64(12)
	portOffset := 4
	if ipv6 {
		width = 28
		portOffset = 20
	}
	n := uint64(binary.LittleEndian.Uint32(b))
	if n > (uint64(len(b))-4)/width {
		return nil, errors.New("invalid UDP table size")
	}
	for i := uint64(0); i < n; i++ {
		r := b[4+i*width : 4+(i+1)*width]
		var a netip.Addr
		if ipv6 {
			var ip [16]byte
			copy(ip[:], r[:16])
			a = netip.AddrFrom16(ip).Unmap()
		} else {
			var ip [4]byte
			copy(ip[:], r[:4])
			a = netip.AddrFrom4(ip)
		}
		if binary.BigEndian.Uint16(r[portOffset:portOffset+2]) != source.Port() || (!a.IsUnspecified() && a != source.Addr()) {
			continue
		}
		pid := binary.LittleEndian.Uint32(r[portOffset+4 : portOffset+8])
		if pid == 0 {
			return nil, errors.New("unknown UDP owner")
		}
		owners[pid] = true
	}
	return owners, nil
}
func uniqueUDPOwner(owners map[uint32]bool) (uint32, error) {
	if len(owners) != 1 {
		return 0, errors.New("missing or ambiguous UDP owner")
	}
	for pid := range owners {
		return pid, nil
	}
	return 0, errors.New("UDP owner not found")
}
func udpOwner(b []byte, source netip.AddrPort) (uint32, error) {
	owners, e := udpOwners(b, source, false)
	if e != nil {
		return 0, e
	}
	return uniqueUDPOwner(owners)
}
