package localstrategy

import (
	"bytes"
	"encoding/binary"
	"strings"
)

// Strictly unfragmented IPv4 without IP options. Unsupported packets pass through.
func packetPayload(p []byte, proto string) ([]byte, bool) {
	if len(p) < 28 || p[0] != 0x45 || int(binary.BigEndian.Uint16(p[2:])) != len(p) || binary.BigEndian.Uint16(p[6:])&0x3fff != 0 {
		return nil, false
	}
	if proto == "udp" && p[9] == 17 && int(binary.BigEndian.Uint16(p[24:])) == len(p)-20 {
		return p[28:], true
	}
	if proto != "tcp" || p[9] != 6 || len(p) < 40 {
		return nil, false
	}
	h := int(p[32]>>4) * 4
	if h < 20 || 20+h > len(p) || p[33]&0x27 != 0 {
		return nil, false
	}
	for i := 40; i < 20+h; {
		kind := p[i]
		if kind == 0 {
			break
		}
		if kind == 1 {
			i++
			continue
		}
		if i+2 > 20+h {
			return nil, false
		}
		n := int(p[i+1])
		if n < 2 || i+n > 20+h || kind == 19 || kind == 29 || kind == 30 {
			return nil, false
		}
		i += n
	}
	return p[20+h:], true
}
func sum(b []byte) uint32 {
	var s uint32
	for len(b) >= 2 {
		s += uint32(binary.BigEndian.Uint16(b))
		b = b[2:]
	}
	if len(b) == 1 {
		s += uint32(b[0]) << 8
	}
	return s
}
func finish(s uint32) uint16 {
	for s>>16 != 0 {
		s = (s & 65535) + (s >> 16)
	}
	return ^uint16(s)
}
func checksumIP(p []byte) {
	p[10] = 0
	p[11] = 0
	binary.BigEndian.PutUint16(p[10:], finish(sum(p[:20])))
}
func checksumTransport(p []byte) {
	off := 36
	if p[9] == 17 {
		off = 26
	}
	p[off] = 0
	p[off+1] = 0
	s := sum(p[12:20]) + uint32(p[9]) + uint32(len(p)-20) + sum(p[20:])
	v := finish(s)
	if v == 0 && p[9] == 17 {
		v = 65535
	}
	binary.BigEndian.PutUint16(p[off:], v)
	checksumIP(p)
}
func transform(p []byte, strategy string) [][]byte { return transformAt(p, strategy, 0) }
func transformAt(p []byte, strategy string, position uint16) [][]byte {
	if fragmentSize := udpFragmentSize(strategy); fragmentSize != 0 {
		split := 20 + fragmentSize
		if _, ok := packetPayload(p, "udp"); !ok || len(p) <= split || len(p) > 1500 {
			return nil
		}
		// Complete UDP checksum before fragmentation; one shared nonzero IP ID.
		full := append([]byte(nil), p...)
		checksumTransport(full)
		a, b := append([]byte(nil), full[:split]...), append([]byte(nil), full[:20]...)
		b = append(b, full[split:]...)
		// DF is explicitly cleared by this opt-in fragmentation strategy.
		if binary.BigEndian.Uint16(a[4:]) == 0 {
			return nil
		} // avoid ambiguous ID-zero reassembly
		binary.BigEndian.PutUint16(a[2:], uint16(len(a)))
		binary.BigEndian.PutUint16(b[2:], uint16(len(b)))
		binary.BigEndian.PutUint16(a[6:], 0x2000)
		binary.BigEndian.PutUint16(b[6:], uint16(fragmentSize/8))
		checksumIP(a)
		checksumIP(b)
		return [][]byte{a, b}
	}
	if strategy != "tcp-split" && strategy != "tcp-split-1" && strategy != "tcp-split-5" {
		return nil
	}
	payload, ok := packetPayload(p, "tcp")
	if !ok {
		return nil
	}
	split := 1
	if strategy == "tcp-split" {
		if position < 1 || position > 512 {
			return nil
		}
		split = int(position)
	}
	if strategy == "tcp-split-5" {
		split = 5
	}
	if len(payload) <= split || len(p) > 1500 {
		return nil
	}
	h := len(p) - len(payload)
	a := make([]byte, h+split)
	copy(a, p[:h+split])
	b := make([]byte, h+len(payload)-split)
	copy(b, p[:h])
	copy(b[h:], payload[split:])
	a[33] &= ^byte(8) // PSH only on last segment
	b[33] &^= 0x80    // CWR belongs to the first segment only
	binary.BigEndian.PutUint32(b[24:], binary.BigEndian.Uint32(p[24:])+uint32(split))
	binary.BigEndian.PutUint16(a[2:], uint16(len(a)))
	binary.BigEndian.PutUint16(b[2:], uint16(len(b)))
	checksumTransport(a)
	checksumTransport(b)
	return [][]byte{a, b}
}

// PacketDomain reads only a complete single-packet HTTP Host / TLS ClientHello SNI.
// ECH, QUIC, fragmented ClientHello, and system resolver traffic are not inferred.
func PacketDomain(p []byte) string {
	if len(p) > 16384 {
		return ""
	}
	if len(p) > 9 && p[0] == 22 && p[1] == 3 {
		return tlsDomain(p)
	}
	if !(bytes.HasPrefix(p, []byte("GET ")) || bytes.HasPrefix(p, []byte("POST ")) || bytes.HasPrefix(p, []byte("HEAD ")) || bytes.HasPrefix(p, []byte("CONNECT "))) {
		return ""
	}
	return httpDomain(string(p))
}

func httpDomain(s string) string {
	if !strings.Contains(s, "\r\n\r\n") {
		return ""
	}
	for _, l := range strings.Split(s, "\r\n")[1:] {
		if strings.HasPrefix(strings.ToLower(l), "host:") {
			v := strings.TrimSpace(l[5:])
			if i := strings.LastIndex(v, ":"); i >= 0 {
				v = v[:i]
			}
			d, _ := domain(v)
			// Copy only the hostname: a substring would retain the whole HTTP request,
			// including headers not needed for routing, after this packet returns.
			return strings.Clone(d)
		}
	}
	return ""
}
func tlsDomain(p []byte) string {
	start, n, ok := tlsSNI(p)
	if !ok {
		return ""
	}
	d, _ := domain(string(p[start : start+n]))
	return d
}
