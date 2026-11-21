package browserproxy

import (
	"encoding/hex"
	"sync"
)

// TLSWireObserver is passive and bounded: record headers, four handshake length
// bytes and a two-byte plaintext alert only. It never retains ClientHello data,
// randoms, session IDs, ECH, certificates, HTTP, keys or application payload.
// Call ObserveClient only AFTER a successful upstream Write (using p[:n]).
// ObserveOrigin sees bytes returned by that same upstream, BEFORE client delivery.
// Neither observation proves the bytes reached the remote TCP peer or HTTP PASS.
type TLSWireObserver struct {
	mu             sync.Mutex
	client, origin tlsWireDirection
}
type TLSWireRecord struct {
	Type     uint8  `json:"type"`
	Version  uint16 `json:"version"`
	Length   uint16 `json:"payload_length"`
	Complete bool   `json:"complete"`
}
type TLSWireSide struct {
	ApplicationRecords, ApplicationBytes uint64
	TotalRecords                         uint64
	ServerHelloEndBytes                  uint64          `json:"server_hello_end_bytes,omitempty"`
	ServerHelloComplete                  bool            `json:"server_hello_complete,omitempty"`
	Bytes                                uint64          `json:"bytes"`
	Records                              []TLSWireRecord `json:"records"`
	ClientHelloBytes                     uint32          `json:"client_hello_handshake_bytes,omitempty"`
	State                                string          `json:"state"`
	Prefix                               string          `json:"first_16_hex_masked,omitempty"`
	AlertLevel                           uint8           `json:"alert_level,omitempty"`
	AlertDescription                     uint8           `json:"alert_description,omitempty"`
	Bounded                              bool            `json:"bounded"`
}
type TLSWireEvidence struct {
	Client TLSWireSide `json:"client_written"`
	Origin TLSWireSide `json:"origin_read"`
}
type tlsWireDirection struct {
	bytes                                              uint64
	header                                             [5]byte
	headerN                                            int
	records                                            [8]TLSWireRecord
	count                                              int
	remaining                                          int
	current                                            TLSWireRecord
	totalRecords, applicationRecords, applicationBytes uint64
	meta                                               [4]byte
	metaN                                              int
	hello                                              uint32
	handshakeSeen                                      uint32
	serverHelloEnd                                     uint64
	invalid, bounded                                   bool
	firstHeader                                        [5]byte
	alert                                              [2]byte
	alertN                                             int
}

func (o *TLSWireObserver) ObserveClient(p []byte) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.client.observe(p, true)
}
func (o *TLSWireObserver) ObserveOrigin(p []byte) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.origin.observe(p, false)
}
func (o *TLSWireObserver) Snapshot() TLSWireEvidence {
	o.mu.Lock()
	defer o.mu.Unlock()
	return TLSWireEvidence{Client: o.client.snapshot(), Origin: o.origin.snapshot()}
}
func (d *tlsWireDirection) observe(p []byte, client bool) {
	d.bytes += uint64(len(p))
	for len(p) > 0 && !d.invalid {
		if d.remaining == 0 {
			if d.count == len(d.records) {
				d.bounded = true
			}
			n := copy(d.header[d.headerN:], p)
			d.headerN += n
			p = p[n:]
			if d.headerN < 5 {
				break
			}
			h := d.header
			// Invalid/cleartext prefixes must NEVER be hex-dumped as TLS metadata.
			length := int(h[3])<<8 | int(h[4])
			if h[0] < 20 || h[0] > 23 || h[1] != 3 || h[2] > 4 || length > 18432 {
				d.invalid = true
				break
			}
			d.current = TLSWireRecord{Type: h[0], Version: uint16(h[1])<<8 | uint16(h[2]), Length: uint16(length), Complete: length == 0}
			if d.count < len(d.records) {
				d.records[d.count] = d.current
				d.count++
			}
			d.totalRecords++
			d.remaining = length
			d.headerN = 0
			if d.totalRecords == 1 {
				d.firstHeader = h
			}
			if length == 0 {
				if d.current.Type == 23 {
					d.applicationRecords++
				}
				continue
			}
		}
		n := len(p)
		if n > d.remaining {
			n = d.remaining
		}
		if d.firstHeader[0] == 22 && d.current.Type == 22 {
			beforeHandshake := d.handshakeSeen
			d.handshakeSeen += uint32(n)
			for i := 0; i < n && d.metaN < 4; i++ {
				d.meta[d.metaN] = p[i]
				d.metaN++
			}
			if client && d.metaN == 4 && d.meta[0] == 1 {
				d.hello = 4 + (uint32(d.meta[1]) << 16) + (uint32(d.meta[2]) << 8) + uint32(d.meta[3])
			}
			if !client && d.metaN == 4 && d.meta[0] == 2 && d.serverHelloEnd == 0 {
				expected := 4 + (uint32(d.meta[1]) << 16) + (uint32(d.meta[2]) << 8) + uint32(d.meta[3])
				if expected >= 42 && beforeHandshake < expected && d.handshakeSeen >= expected {
					d.serverHelloEnd = d.bytes - uint64(len(p)) + uint64(expected-beforeHandshake)
				}
			}
		}
		if d.totalRecords == 1 {
			if !client && d.firstHeader[0] == 21 && d.current.Length == 2 {
				for i := 0; i < n && d.alertN < 2; i++ {
					d.alert[d.alertN] = p[i]
					d.alertN++
				}
			}
		}
		d.remaining -= n
		p = p[n:]
		if d.remaining == 0 {
			if d.totalRecords <= uint64(len(d.records)) {
				d.records[d.count-1].Complete = true
			}
			d.current.Complete = true
			if d.current.Type == 23 {
				d.applicationRecords++
				d.applicationBytes += uint64(d.current.Length)
			}
		}
	}
}
func (d *tlsWireDirection) snapshot() TLSWireSide {
	s := TLSWireSide{ApplicationRecords: d.applicationRecords, ApplicationBytes: d.applicationBytes, TotalRecords: d.totalRecords, Bytes: d.bytes, Records: append([]TLSWireRecord{}, d.records[:d.count]...), ClientHelloBytes: d.hello, Bounded: d.bounded, State: "NOT_OBSERVED"}
	if d.metaN == 4 && d.meta[0] == 2 {
		expected := 4 + (uint32(d.meta[1]) << 16) + (uint32(d.meta[2]) << 8) + uint32(d.meta[3])
		// ServerHello has at least version(2), random(32), session-id length(1),
		// cipher suite(2), compression(1). A zero/tiny handshake is not progress.
		s.ServerHelloComplete = expected >= 42 && d.handshakeSeen >= expected
		s.ServerHelloEndBytes = d.serverHelloEnd
	}
	if d.bytes == 0 {
		return s
	}
	s.State = "TLS_HEADER_INCOMPLETE"
	if d.invalid {
		s.State = "NON_TLS_OR_INVALID_HEADER"
		return s
	}
	if d.count == 0 {
		return s
	}
	s.State = "TLS_RECORD_INCOMPLETE"
	if d.records[0].Complete {
		s.State = "TLS_RECORD_COMPLETE"
	}
	if d.bytes == 5 && d.records[0].Length > 0 {
		s.State = "TLS_HEADER_ONLY"
	}
	// A 16-byte window, xx masks everything except the validated first header
	// and a COMPLETE two-byte plaintext alert. TLS 1.3 encrypted alerts stay masked.
	n := int(d.bytes)
	if n > 16 {
		n = 16
	}
	prefix := hex.EncodeToString(d.firstHeader[:])
	for i := 5; i < n; i++ {
		prefix += "xx"
	}
	if d.alertN == 2 && (d.alert[0] == 1 || d.alert[0] == 2) {
		s.State = "TLS_PLAINTEXT_ALERT_COMPLETE"
		s.AlertLevel = d.alert[0]
		s.AlertDescription = d.alert[1]
		prefix = hex.EncodeToString(d.firstHeader[:]) + hex.EncodeToString(d.alert[:])
		for i := 7; i < n; i++ {
			prefix += "xx"
		}
	}
	s.Prefix = prefix
	return s
}
