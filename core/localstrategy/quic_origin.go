package localstrategy

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"time"
)

const QUICOriginMaxHello = 8192
const QUICOriginMaxDatagrams = 16
const QUICOriginDeadline = 2 * time.Second

// QUICOriginObservation describes an outbound ClientHello, never authenticated
// server identity, HTTP traffic or permission to route a browser flow locally.
// ECH (including GREASE), resumption and ambiguous framing publish no domain.
type QUICOriginObservation struct {
	Domain    string `json:"domain,omitempty"`
	Reason    string `json:"reason"`
	Datagrams int    `json:"datagrams"`
	Complete  bool   `json:"complete"`
}

// QUICOriginObserver only removes QUIC v1 Initial's PUBLIC packet protection.
// It has no TLS secrets and never processes Handshake, 0-RTT, 1-RTT or ECH inner
// data. The caller binds this object to one current process/tuple/policy scope,
// caps the number of objects, and expires incomplete observations promptly.
// Calls must be serialized. Packet input is immutable; no originals are queued.
type QUICOriginObserver struct {
	started         time.Time
	result          QUICOriginObservation
	dcid, scid      []byte
	data, present   []byte
	contiguous, end int
}

func (o *QUICOriginObserver) Finish(reason string) QUICOriginObservation {
	clear(o.data)
	clear(o.present)
	o.data, o.present, o.dcid, o.scid = nil, nil, nil, nil
	o.result.Domain = ""
	o.result.Reason, o.result.Complete = reason, true
	return o.result
}

func (o *QUICOriginObserver) Observe(datagram []byte, now time.Time) QUICOriginObservation {
	if o.result.Complete {
		return o.result
	}
	if o.result.Datagrams == 0 {
		o.started = now
	}
	if now.Before(o.started) || !now.Before(o.started.Add(QUICOriginDeadline)) {
		return o.Finish("QUIC_ORIGIN_TIMEOUT")
	}
	o.result.Datagrams++
	if o.result.Datagrams > QUICOriginMaxDatagrams || len(datagram) < 1200 || len(datagram) > 1472 {
		return o.Finish("QUIC_ORIGIN_LIMIT")
	}
	o.result.Reason = "QUIC_ORIGIN_INCOMPLETE"
	// Validate every coalesced packet before publishing a complete ClientHello.
	for len(datagram) > 0 {
		n, why := o.initial(datagram)
		if why != "" {
			return o.Finish(why)
		}
		datagram = datagram[n:]
	}
	if o.contiguous < 4 {
		return o.result
	}
	size := 4 + int(o.data[1])<<16 + int(o.data[2])<<8 + int(o.data[3])
	if o.data[0] != 1 || size > QUICOriginMaxHello {
		return o.Finish("QUIC_ORIGIN_HELLO_INVALID")
	}
	if o.contiguous < size {
		return o.result
	}
	if o.end != size {
		return o.Finish("QUIC_ORIGIN_EXTRA_CRYPTO")
	}
	host, why := quicOriginHello(o.data[:size], o.scid)
	if why != "" {
		return o.Finish(why)
	}
	o.Finish("QUIC_ORIGIN_VISIBLE_SNI")
	o.result.Domain = host
	return o.result
}

func quicOriginVarint(p []byte) (uint64, int, bool) {
	if len(p) == 0 {
		return 0, 0, false
	}
	n := 1 << uint(p[0]>>6)
	if len(p) < n {
		return 0, 0, false
	}
	v := uint64(p[0] & 63)
	for _, b := range p[1:n] {
		v = v<<8 | uint64(b)
	}
	return v, n, true
}

func (o *QUICOriginObserver) initial(p []byte) (int, string) {
	if len(p) < 7 || p[0]&0xc0 != 0xc0 {
		return 0, "QUIC_ORIGIN_HEADER_UNSUPPORTED"
	}
	if binary.BigEndian.Uint32(p[1:5]) != 1 {
		return 0, "QUIC_ORIGIN_VERSION_UNSUPPORTED"
	}
	if p[0]&0x30 != 0 {
		return 0, "QUIC_ORIGIN_PACKET_TYPE_UNSUPPORTED"
	}
	dl := int(p[5])
	if dl < 8 || dl > 20 || len(p) < 7+dl {
		return 0, "QUIC_ORIGIN_CID_INVALID"
	}
	dcid := p[6 : 6+dl]
	sl := int(p[6+dl])
	at := 7 + dl
	if sl > 20 || len(p) < at+sl {
		return 0, "QUIC_ORIGIN_CID_INVALID"
	}
	scid := p[at : at+sl]
	at += sl
	if o.dcid != nil && (!bytes.Equal(dcid, o.dcid) || !bytes.Equal(scid, o.scid)) {
		return 0, "QUIC_ORIGIN_CID_CHANGED"
	}
	token, n, ok := quicOriginVarint(p[at:])
	if !ok || token != 0 {
		return 0, "QUIC_ORIGIN_TOKEN_UNSUPPORTED"
	}
	at += n
	length, n, ok := quicOriginVarint(p[at:])
	if !ok {
		return 0, "QUIC_ORIGIN_LENGTH_INVALID"
	}
	at += n
	if length < 20 || length > uint64(len(p)-at) {
		return 0, "QUIC_ORIGIN_LENGTH_INVALID"
	}
	end := at + int(length)
	key, iv, hp, err := quicInitialKeys(dcid)
	if err != nil {
		return 0, "QUIC_ORIGIN_PROTECTION_FAILED"
	}
	block, _ := aes.NewCipher(hp)
	var mask [16]byte
	block.Encrypt(mask[:], p[at+4:at+20])
	first := p[0] ^ (mask[0] & 15)
	if first&0x0c != 0 {
		return 0, "QUIC_ORIGIN_RESERVED_BITS"
	}
	pnLen := int(first&3) + 1
	header := bytes.Clone(p[:at+pnLen])
	header[0] = first
	var pn uint64
	for i := 0; i < pnLen; i++ {
		header[at+i] ^= mask[i+1]
		pn = pn<<8 | uint64(header[at+i])
	}
	// A fresh flight must begin at PN0. Only the first 64 Initial numbers are
	// accepted, so truncated-number reconstruction/wrap cannot cross a flight.
	if pn >= 64 || o.dcid == nil && pn != 0 {
		return 0, "QUIC_ORIGIN_PACKET_NUMBER_UNSUPPORTED"
	}
	for i := 0; i < 8; i++ {
		iv[len(iv)-1-i] ^= byte(pn >> uint(8*i))
	}
	block, _ = aes.NewCipher(key)
	aead, _ := cipher.NewGCM(block)
	plain, err := aead.Open(nil, iv, p[at+pnLen:end], header)
	if err != nil {
		return 0, "QUIC_ORIGIN_PROTECTION_FAILED"
	}
	defer clear(plain)
	if o.dcid == nil {
		o.dcid = bytes.Clone(dcid)
		o.scid = bytes.Clone(scid)
	}
	for len(plain) > 0 {
		frame, n, ok := quicOriginVarint(plain)
		if !ok || n != 1 {
			return 0, "QUIC_ORIGIN_FRAME_INVALID"
		}
		plain = plain[n:]
		switch frame {
		case 0, 1: // PADDING, PING
		case 6:
			offset, n, ok := quicOriginVarint(plain)
			if !ok {
				return 0, "QUIC_ORIGIN_FRAME_INVALID"
			}
			plain = plain[n:]
			size, n, ok := quicOriginVarint(plain)
			if !ok {
				return 0, "QUIC_ORIGIN_FRAME_INVALID"
			}
			plain = plain[n:]
			if offset > QUICOriginMaxHello || size > QUICOriginMaxHello-offset || size > uint64(len(plain)) {
				return 0, "QUIC_ORIGIN_CRYPTO_LIMIT"
			}
			if o.data == nil {
				o.data = make([]byte, QUICOriginMaxHello)
				o.present = make([]byte, QUICOriginMaxHello)
			}
			for i, b := range plain[:int(size)] {
				at := int(offset) + i
				if o.present[at] != 0 && o.data[at] != b {
					return 0, "QUIC_ORIGIN_OVERLAP_CONFLICT"
				}
				o.data[at] = b
				o.present[at] = 1
			}
			o.end = max(o.end, int(offset+size))
			for o.contiguous < o.end && o.present[o.contiguous] != 0 {
				o.contiguous++
			}
			plain = plain[int(size):]
		default:
			return 0, "QUIC_ORIGIN_FRAME_UNSUPPORTED"
		}
	}
	return end, ""
}

func quicOriginHello(hello, scid []byte) (string, string) {
	// Reuse the existing strict SNI parser with an internal TLS record envelope.
	// That envelope is never injected or sent, and contains no TLS ciphertext.
	record := append([]byte{22, 3, 3, byte(len(hello) >> 8), byte(len(hello))}, hello...)
	defer clear(record)
	start, size, ok := tlsSNI(record)
	if !ok || len(hello) < 39 || hello[4] != 3 || hello[5] != 3 {
		return "", "QUIC_ORIGIN_HELLO_INVALID"
	}
	at := 39 + int(hello[38])
	if at+2 > len(hello) {
		return "", "QUIC_ORIGIN_HELLO_INVALID"
	}
	at += 2 + int(binary.BigEndian.Uint16(hello[at:]))
	if at+2 > len(hello) || hello[at] != 1 || hello[at+1] != 0 {
		return "", "QUIC_ORIGIN_HELLO_INVALID"
	}
	at += 2
	if at+2 > len(hello) {
		return "", "QUIC_ORIGIN_HELLO_INVALID"
	}
	at += 2
	seen := map[uint16]bool{}
	h3, tls13, sourceCID := false, false, false
	for at < len(hello) {
		if at+4 > len(hello) || len(seen) >= 128 {
			return "", "QUIC_ORIGIN_HELLO_INVALID"
		}
		kind, n := binary.BigEndian.Uint16(hello[at:]), int(binary.BigEndian.Uint16(hello[at+2:]))
		at += 4
		if seen[kind] || n > len(hello)-at {
			return "", "QUIC_ORIGIN_HELLO_INVALID"
		}
		seen[kind] = true
		value := hello[at : at+n]
		at += n
		switch kind {
		case 0xfe0d:
			return "", "QUIC_ORIGIN_ECH"
		case 41, 42:
			return "", "QUIC_ORIGIN_RESUMPTION_UNSUPPORTED"
		case 16:
			if len(value) < 2 || int(binary.BigEndian.Uint16(value))+2 != len(value) {
				return "", "QUIC_ORIGIN_HELLO_INVALID"
			}
			for rest := value[2:]; len(rest) > 0; {
				n := int(rest[0])
				rest = rest[1:]
				if n == 0 || n > len(rest) {
					return "", "QUIC_ORIGIN_HELLO_INVALID"
				}
				h3 = h3 || string(rest[:n]) == "h3"
				rest = rest[n:]
			}
		case 43:
			if len(value) < 3 || int(value[0])+1 != len(value) || value[0]%2 != 0 {
				return "", "QUIC_ORIGIN_HELLO_INVALID"
			}
			for i := 1; i < len(value); i += 2 {
				tls13 = tls13 || binary.BigEndian.Uint16(value[i:]) == 0x0304
			}
		case 57:
			params := map[uint64]bool{}
			for len(value) > 0 {
				id, n, ok := quicOriginVarint(value)
				if !ok || params[id] || len(params) >= 64 {
					return "", "QUIC_ORIGIN_PARAMETERS_INVALID"
				}
				value = value[n:]
				params[id] = true
				size, n, ok := quicOriginVarint(value)
				if !ok {
					return "", "QUIC_ORIGIN_PARAMETERS_INVALID"
				}
				value = value[n:]
				if size > uint64(len(value)) {
					return "", "QUIC_ORIGIN_PARAMETERS_INVALID"
				}
				if id == 15 {
					if !bytes.Equal(value[:int(size)], scid) {
						return "", "QUIC_ORIGIN_CID_CHANGED"
					}
					sourceCID = true
				}
				value = value[int(size):]
			}
		}
	}
	if !h3 || !tls13 || !sourceCID {
		return "", "QUIC_ORIGIN_PROTOCOL_UNSUPPORTED"
	}
	return string(record[start : start+size]), ""
}
