package localstrategy

import (
	"bytes"
	"encoding/binary"
	"time"
)

const MaxHelloBytes = 32 * 1024
const MaxHelloSegments = 32
const HelloDeadline = 2 * time.Second

// HelloBuffer belongs to an existing bounded TCP flow. Only original packets
// are retained, never a synthetic TCP segment. Access is serialized by capture.
type HelloBuffer struct {
	packets     [][]byte
	started     time.Time
	bytes, seen int
	outOfOrder  bool
	diagnostic  Inspection
}
type BufferedResult struct {
	Originals [][]byte
	Result    Result
}

func (b *HelloBuffer) Pending() bool { return len(b.packets) > 0 }
func (b *HelloBuffer) Expired(now time.Time) bool {
	return b.Pending() && !now.Before(b.started.Add(HelloDeadline))
}
func (b *HelloBuffer) Inspection() *Inspection { d := b.diagnostic; return &d }
func (b *HelloBuffer) release(reason, detail string, now time.Time) BufferedResult {
	b.diagnostic.Reason = reason
	b.diagnostic.Detail = detail
	b.diagnostic.ReassemblyMS = now.Sub(b.started).Milliseconds()
	d := b.Inspection()
	packets := b.packets
	b.packets = nil
	b.bytes = 0 // drop every retained payload reference immediately
	return BufferedResult{Originals: packets, Result: Result{Inspection: d}}
}
func (b *HelloBuffer) Flush(st *State, reason string, now time.Time) BufferedResult {
	if st != nil {
		st.done = true
	}
	return b.release(reason, "buffer released unchanged; no transform committed", now)
}

// Eligibility deliberately precedes domain matching. Domain exclusions are
// evaluated normally by Process once an observable outer SNI is available.
func (e *LocalStrategyEngine) bufferEligible(st *State, m Metadata) bool {
	s := e.current.Load()
	if m.Protocol != "tcp" || !m.Destination.Addr().Is4() || !st.synSeen || st.done || st.matched || st.failed || e.suspended.Load() || !s.config.Enabled || !refreshApplicationState(st, m, s) {
		return false
	}
	for _, c := range s.profiles {
		if !c.Enabled || c.Protocol != "tcp" || !appMatch(c.Application, m.Application) || (m.StrategyID != "" && c.ID != m.StrategyID) || c.excludes.IPs.Contains(m.Destination.Addr()) {
			continue
		}
		for _, port := range c.Ports {
			if port == m.Destination.Port() {
				return true
			}
		}
	}
	return false
}

// BufferTCP returns accepted=false for packets outside the bounded ClientHello
// path. The caller sends those normally, after flushing pending data on FIN/RST
// or unsupported framing. accepted=true means the caller must retain its send
// context until this batch completes or Flush is called.
func (e *LocalStrategyEngine) BufferTCP(p []byte, st *State, b *HelloBuffer, m Metadata, now time.Time) (accepted bool, out *BufferedResult) {
	if st == nil || b == nil {
		return false, nil
	}
	data, ok := packetPayload(p, "tcp")
	if !ok {
		if b.Pending() {
			v := b.Flush(st, "NO_TRANSFORM", now)
			return false, &v
		}
		return false, nil
	}
	if len(data) == 0 {
		return false, nil
	}
	http80 := e.http80Profile(m)
	if !b.Pending() {
		if !e.bufferEligible(st, m) || !http80 && data[0] != 22 && binary.BigEndian.Uint32(p[24:]) == st.synSequence+1 {
			return false, nil
		}
		b.started = now
		b.seen = 0
		b.outOfOrder = false
		b.diagnostic = Inspection{Reason: "REASSEMBLY_STARTED", Detail: "bounded outbound ClientHello; no payload logging"}
	}
	if b.Pending() && now.After(b.started.Add(HelloDeadline)) {
		v := b.Flush(st, "REASSEMBLY_TIMEOUT", now)
		return false, &v
	}
	b.seen++
	// Enforce the bound BEFORE copying. On limit the current packet was not
	// accepted; the caller flushes the old originals then sends this one directly.
	maxPacket := 1500
	if http80 {
		maxPacket = MaxHelloBytes
	}
	s := e.current.Load()
	for i := range s.profiles {
		c := &s.profiles[i]
		if c.ID == m.StrategyID && c.Match(m) && len(c.Actions) == 1 && c.Actions[0].Native != nil {
			maxPacket = MaxHelloBytes
		}
	}
	if len(b.packets) >= MaxHelloSegments || b.bytes+len(data) > MaxHelloBytes || len(p) > maxPacket {
		v := b.Flush(st, "REASSEMBLY_LIMIT", now)
		return false, &v
	}
	q := append([]byte(nil), p...)
	b.packets = append(b.packets, q)
	b.bytes += len(data)
	b.diagnostic.SegmentsSeen = b.seen
	b.diagnostic.SegmentsBuffered = len(b.packets)
	b.diagnostic.BytesBuffered = b.bytes
	b.diagnostic.PayloadBytes = b.bytes
	b.diagnostic.ReassemblyMS = now.Sub(b.started).Milliseconds()
	if !e.bufferEligible(st, m) {
		v := b.Flush(st, "NO_TRANSFORM", now)
		return true, &v
	}
	// A packet observed on the deadline participates in the final evaluation.
	stream := make([]byte, MaxHelloBytes)
	present := make([]bool, MaxHelloBytes)
	end := 0
	contiguous := 0
	for _, packet := range b.packets {
		payload, _ := packetPayload(packet, "tcp")
		offset := int(int32(binary.BigEndian.Uint32(packet[24:]) - (st.synSequence + 1)))
		if offset < 0 || offset+len(payload) > MaxHelloBytes {
			v := b.Flush(st, "REASSEMBLY_LIMIT", now)
			return true, &v
		}
		if offset > contiguous {
			b.outOfOrder = true
		}
		for i, v := range payload {
			at := offset + i
			if present[at] && stream[at] != v {
				v := b.Flush(st, "REASSEMBLY_OUT_OF_ORDER", now)
				v.Result.Inspection.Detail = "conflicting TCP overlap; ambiguous stream released unchanged"
				return true, &v
			}
			stream[at] = v
			present[at] = true
		}
		if offset+len(payload) > end {
			end = offset + len(payload)
		}
		for contiguous < end && present[contiguous] {
			contiguous++
		}
	}
	b.diagnostic.OutOfOrder = b.outOfOrder
	hello, offsets, expected, reason := assembleHello(stream[:contiguous])
	if http80 {
		host, _, size, complete := HTTP80Host(stream[:contiguous])
		hello, offsets, expected, reason = nil, nil, 0, ""
		if complete && host == "" {
			reason = "HTTP80_HEADER_UNSUPPORTED"
		} else if complete {
			hello = stream[:size]
			offsets = make([]int, size)
			for i := range offsets {
				offsets[i] = i
			}
		}
	}
	b.diagnostic.ExpectedClientHelloBytes = expected
	b.diagnostic.HandshakeBytes = expected
	if contiguous >= 5 && !http80 {
		b.diagnostic.RecordBytes = 5 + int(binary.BigEndian.Uint16(stream[3:5]))
	}
	if reason != "" {
		v := b.Flush(st, reason, now)
		return true, &v
	}
	if hello == nil {
		if b.Expired(now) {
			v := b.Flush(st, "REASSEMBLY_TIMEOUT", now)
			return true, &v
		}
		b.diagnostic.Reason = "REASSEMBLY_WAITING"
		if b.outOfOrder {
			b.diagnostic.Reason = "REASSEMBLY_OUT_OF_ORDER"
		}
		return true, nil
	}
	st.logicalHello = hello
	st.helloOffsets = offsets
	st.helloPackets = b.packets
	r := e.Process(b.packets[0], st, m)
	st.logicalHello = nil
	st.helloOffsets = nil
	st.helloPackets = nil
	d := b.diagnostic
	d.PayloadBytes = b.bytes
	d.HandshakeBytes = len(hello)
	d.Reason = "REASSEMBLY_COMPLETE"
	d.Detail = "ClientHello assembled; outer SNI only; original segment boundaries retained"
	if http80 {
		d.Reason, d.Detail = "HTTP80_HEADER_REASSEMBLED", "bounded HTTP Host; original bytes and segment context retained"
		d.HandshakeBytes = 0
	}
	d.ReassemblyMS = now.Sub(b.started).Milliseconds()
	if r.Inspection != nil {
		d.OriginalPacketBytes = r.Inspection.OriginalPacketBytes
		d.TCPHeaderBytes = r.Inspection.TCPHeaderBytes
		d.TimestampOption = r.Inspection.TimestampOption
		d.SYNSeen = r.Inspection.SYNSeen
		d.HandshakeConfirmed = r.Inspection.HandshakeConfirmed
		d.ServerTTL = r.Inspection.ServerTTL
		d.Domain = r.Inspection.Domain
		if !r.Modified {
			d.Detail = r.Inspection.Detail
			d.Reason = r.Inspection.Reason
		}
	}
	if d.Domain != "" && !http80 {
		d.ReassembledSNI = true
		d.ObservedSNI = d.Domain
		d.SNIStatus = "REASSEMBLED_SNI"
	}
	r.Inspection = &d
	v := BufferedResult{Originals: b.packets, Result: r}
	b.packets = nil
	b.bytes = 0
	return true, &v
}

// assembleHello parses TLS framing separately from the logical handshake. The
// synthetic record is parser input ONLY, never a packet or bytes sent upstream.
// offsets map parser offsets to original TCP stream offsets, including every
// intervening TLS record header. No ECH inner name is inspected.
func assembleHello(stream []byte) (hello []byte, offsets []int, expected int, reason string) {
	handshake := []byte{}
	mapping := []int{}
	pos := 0
	need := 0
	for pos < len(stream) {
		if len(stream)-pos < 5 {
			return nil, nil, need, ""
		}
		if stream[pos] != 22 || stream[pos+1] != 3 || stream[pos+2] < 1 || stream[pos+2] > 3 {
			return nil, nil, need, "NO_TRANSFORM"
		}
		n := int(binary.BigEndian.Uint16(stream[pos+3:]))
		if n == 0 || n > 16384 || pos+5+n > MaxHelloBytes {
			return nil, nil, need, "REASSEMBLY_LIMIT"
		}
		end := pos + 5 + n
		available := end
		if available > len(stream) {
			available = len(stream)
		}
		for i := pos + 5; i < available; i++ {
			handshake = append(handshake, stream[i])
			mapping = append(mapping, i)
		}
		if len(handshake) >= 4 {
			if handshake[0] != 1 {
				return nil, nil, 0, "NO_TRANSFORM"
			}
			need = 4 + (int(handshake[1])<<16 | int(handshake[2])<<8 | int(handshake[3]))
			if need < 38 || need+5 > MaxHelloBytes {
				return nil, nil, need + 5, "REASSEMBLY_LIMIT"
			}
			if len(handshake) >= need {
				hello = append([]byte{22, 3, 3, byte(need >> 8), byte(need)}, handshake[:need]...)
				offsets = append([]int{0, 1, 2, 3, 4}, mapping[:need]...)
				return hello, offsets, need + 5, ""
			}
		}
		if end > len(stream) {
			return nil, nil, need + 5, ""
		}
		pos = end
	}
	return nil, nil, need + 5, ""
}

// InspectHelloStream reuses the bounded record/handshake assembler on an ordered
// TCP byte stream. Only outer SNI is returned; ECH is never decrypted or guessed.
func InspectHelloStream(stream []byte) (domain, reason string, complete bool) {
	if len(stream) > MaxHelloBytes {
		return "", "REASSEMBLY_LIMIT", true
	}
	if len(stream) > 0 && stream[0] != 22 {
		if bytes.Contains(stream, []byte("\r\n\r\n")) {
			d, _, _, _ := httpHeaderHost(stream, true)
			if d != "" {
				if h, _, _, _ := HTTP80Host(stream); h == "" {
					return d, "HTTP_HOST_OTHER_PORT", true
				}
				return d, "HTTP_HOST", true
			}
			return "", "DOMAIN_NOT_OBSERVED", true
		}
		return "", "CLIENTHELLO_INCOMPLETE", false
	}
	hello, _, _, why := assembleHello(stream)
	if why != "" {
		return "", why, true
	}
	if hello == nil {
		return "", "CLIENTHELLO_INCOMPLETE", false
	}
	d := tlsDomain(hello)
	if helloHasECH(hello) {
		return d, "ECH_OUTER_SNI_ONLY", true
	}
	if d == "" {
		return "", "SNI_NOT_FOUND", true
	}
	return d, "REASSEMBLY_COMPLETE", true
}

// Presence is observable; whether an ECH extension is real or GREASE is not
// guessed. A deferred domain policy must use its explicit opaque-name fallback.
func helloHasECH(p []byte) bool {
	if len(p) < 44 {
		return false
	}
	i := 44 + int(p[43])
	if i+2 > len(p) {
		return false
	}
	i += 2 + int(binary.BigEndian.Uint16(p[i:]))
	if i >= len(p) {
		return false
	}
	i += 1 + int(p[i])
	if i+2 > len(p) {
		return false
	}
	end := i + 2 + int(binary.BigEndian.Uint16(p[i:]))
	i += 2
	if end > len(p) {
		return false
	}
	for i+4 <= end {
		k := binary.BigEndian.Uint16(p[i:])
		n := int(binary.BigEndian.Uint16(p[i+2:]))
		i += 4
		if i+n > end {
			return false
		}
		if k == 0xfe0d {
			return true
		}
		i += n
	}
	return false
}
