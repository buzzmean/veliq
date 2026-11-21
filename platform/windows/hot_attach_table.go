package windowsplatform

import (
	"encoding/binary"
	"errors"
	"net/netip"
)

type ownedTCPRow struct {
	Tuple      Tuple
	PID, State uint32
	raw        [20]byte
}

func decodeOwnedTCP(b []byte) ([]ownedTCPRow, error) {
	if len(b) < 4 {
		return nil, errors.New("TCP owner table truncated")
	}
	n := int(binary.LittleEndian.Uint32(b))
	if n > hotAttachLimit || n > (len(b)-4)/24 {
		return nil, errors.New("HOT_ATTACH TCP table bound/truncation")
	}
	out := make([]ownedTCPRow, 0, n)
	for i := 0; i < n; i++ {
		r := b[4+i*24 : 4+(i+1)*24]
		state := binary.LittleEndian.Uint32(r)
		if state < 3 || state > 10 {
			continue
		}
		var a, c [4]byte
		copy(a[:], r[4:8])
		copy(c[:], r[12:16])
		row := ownedTCPRow{Tuple: Tuple{Protocol: "tcp", Source: netip.AddrPortFrom(netip.AddrFrom4(a), binary.BigEndian.Uint16(r[8:10])), Destination: netip.AddrPortFrom(netip.AddrFrom4(c), binary.BigEndian.Uint16(r[16:18]))}, PID: binary.LittleEndian.Uint32(r[20:24]), State: state}
		copy(row.raw[:], r[:20])
		out = append(out, row)
	}
	return out, nil
}
