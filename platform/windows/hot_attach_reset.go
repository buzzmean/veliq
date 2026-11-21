package windowsplatform

import (
	"encoding/binary"
	"errors"
)

// Construct a payload-free local reset from this exact packet's sequence space.
func hotTCPReset(p []byte, outbound bool) ([]byte, error) {
	t, flags, _, err := ParseTCP(p)
	h := 0
	v6 := len(p) > 0 && p[0]>>4 == 6
	if v6 {
		t, flags, err = ParseIPv6Transport(p)
		h = 40
		next := p[6]
		for i := 0; err == nil && next != 6 && i < 8; i++ {
			if next != 0 && next != 43 && next != 60 {
				err = errors.New("not TCP")
				break
			}
			next, h = p[h], h+(int(p[h+1])+1)*8
		}
		if h+20 > len(p) {
			err = errors.New("truncated TCP")
		}
	} else if err == nil {
		h = int(p[0]&15) * 4
	}
	if err != nil || t.Protocol != "tcp" {
		return nil, errors.New("unsupported reset packet")
	}
	if flags&4 != 0 {
		return nil, errors.New("RST needs no response")
	}
	th := 20
	if v6 {
		th = 40
	}
	out := make([]byte, th+20)
	source, dest := t.Source, t.Destination
	seq := binary.BigEndian.Uint32(p[h+4:])
	ack := uint32(0)
	rstFlags := byte(4)
	if outbound {
		source, dest = dest, source
		if flags&16 != 0 {
			seq = binary.BigEndian.Uint32(p[h+8:])
		} else if flags&2 != 0 {
			ack = seq + 1
			seq = 0
			rstFlags |= 16
		} else {
			return nil, errors.New("no reset sequence evidence")
		}
	}
	if v6 {
		out[0] = 0x60
		out[6] = 6
		out[7] = 64
		binary.BigEndian.PutUint16(out[4:], 20)
		a, b := source.Addr().As16(), dest.Addr().As16()
		copy(out[8:24], a[:])
		copy(out[24:40], b[:])
	} else {
		out[0] = 0x45
		out[8] = 64
		out[9] = 6
		binary.BigEndian.PutUint16(out[2:], 40)
		a, b := source.Addr().As4(), dest.Addr().As4()
		copy(out[12:16], a[:])
		copy(out[16:20], b[:])
	}
	out[th+12] = 0x50
	out[th+13] = rstFlags
	binary.BigEndian.PutUint16(out[th:], source.Port())
	binary.BigEndian.PutUint16(out[th+2:], dest.Port())
	binary.BigEndian.PutUint32(out[th+4:], seq)
	binary.BigEndian.PutUint32(out[th+8:], ack)
	return out, nil
}
