package localstrategy

import (
	"encoding/binary"
	"errors"
	"sort"
	"strconv"
	"strings"
)

// Actions are a finite packet plan, not a scripting language. Legacy <=5;
// legacy browser-catalog <=20/input; typed native TCP443 <=64/first flight.
type Action struct {
	Native          *NativeTCPPlan `json:"native_tcp,omitempty"`
	SequenceOverlap uint16         `json:"seq_overlap,omitempty"`
	// Catalog-only options. Legacy DIRECT+ retains its original five-packet ceiling.
	Markers   []string `json:"markers,omitempty"`
	FakeModel string   `json:"fake_model,omitempty"`
	Fooling   string   `json:"fooling,omitempty"`
	AutoTTL   bool     `json:"auto_ttl,omitempty"`
	Repeats   uint8    `json:"repeats,omitempty"` // TCP only: default1, maximum2; total output remains <=5.
	Kind      string   `json:"kind"`
	Positions []uint16 `json:"positions,omitempty"`
	Anchor    string   `json:"anchor,omitempty"` // empty=payload, sni=complete SNI offset
	TTL       uint8    `json:"ttl,omitempty"`
}

func validateChain(p Profile) error {
	if len(p.Actions) == 1 && p.Actions[0].Kind == "native-tcp443" {
		if p.Preset != "browser-catalog" || !catalogProfile(p) || p.Actions[0].Native == nil {
			return errors.New("native recipe requires bounded browser catalog")
		}
		for _, port := range p.Ports {
			if port != 443 {
				return errors.New("native recipe is TCP443 only")
			}
		}
		return p.Actions[0].Native.validate()
	}
	for _, a := range p.Actions {
		if a.Native != nil {
			return errors.New("native recipe mixed with legacy actions")
		}
	}

	if p.Protocol != "tcp" || len(p.Actions) < 1 || len(p.Actions) > 3 || p.SplitPosition != 0 {
		return errors.New("invalid TCP chain")
	}
	split, fake, reverse := false, false, false
	catalog := p.Preset == "browser-catalog"
	if catalog && !catalogProfile(p) {
		return errors.New("catalog requires selected browser TCP80/443 and one ClientHello cutoff")
	}
	ceiling, maxRepeats := 5, uint8(2)
	if catalog {
		ceiling = 20
		maxRepeats = 16
	}
	for i, a := range p.Actions {
		switch a.Kind {
		case "fake-tls":
			if fake || i != 0 || a.TTL < 2 || a.TTL > 16 || a.Repeats > maxRepeats || len(a.Positions) > 0 || len(a.Markers) > 0 || a.Anchor != "" || a.SequenceOverlap != 0 {
				return errors.New("fake TLS requires explicit TTL 2..16 and first position")
			}

			if (a.FakeModel != "" || a.Fooling != "" || a.AutoTTL) && !catalog {
				return errors.New("catalog fake requires browser-catalog scope")
			}
			if a.FakeModel != "" && a.FakeModel != "tls13-google" && a.FakeModel != "tls13-yandex" {
				return errors.New("unknown own fake model")
			}
			if a.Fooling != "" && a.Fooling != "badseq" && a.Fooling != "ts" && a.Fooling != "ts,md5sig" && a.Fooling != "md5sig" {
				return errors.New("unknown fooling")
			}
			fake = true
		case "tcp-multisplit":
			if a.Repeats != 0 || split || reverse || a.TTL != 0 || len(a.Positions)+len(a.Markers) < 1 || len(a.Positions)+len(a.Markers) > 3 || (a.Anchor != "" && a.Anchor != "sni") {
				return errors.New("invalid bounded split")
			}

			if len(a.Markers) > 0 && (!catalog || len(a.Positions) > 0 || a.Anchor != "") {
				return errors.New("invalid catalog markers")
			}
			for _, marker := range a.Markers {
				if marker != "1" && marker != "2" && marker != "midsld" && marker != "sni+1" && marker != "sniext+1" {
					return errors.New("unknown marker")
				}
			}
			if a.FakeModel != "" || a.Fooling != "" || a.AutoTTL || a.SequenceOverlap > 1024 || a.SequenceOverlap != 0 && !catalog {
				return errors.New("fake options on split")
			}
			last := uint16(0)
			for _, v := range a.Positions {
				if v == 0 || v > 512 || v <= last {
					return errors.New("split positions must increase within 1..512")
				}
				last = v
			}
			split = true
		case "tcp-disorder":
			if a.Repeats != 0 || !split || reverse || i != len(p.Actions)-1 || len(a.Positions) > 0 || a.TTL != 0 || a.Anchor != "" || len(a.Markers) > 0 || a.FakeModel != "" || a.Fooling != "" || a.AutoTTL || a.SequenceOverlap != 0 {
				return errors.New("disorder requires prior split")
			}
			reverse = true
		default:
			return errors.New("unknown chain action")
		}
	}
	outputs := 1
	fakes := 0
	for _, a := range p.Actions {
		if a.Kind == "fake-tls" {
			fakes = int(a.Repeats)
			if fakes == 0 {
				fakes = 1
			}
		}
		if a.Kind == "tcp-multisplit" {
			outputs = len(a.Positions) + len(a.Markers) + 1
		}
	}
	if outputs+fakes > ceiling {
		return errors.New("TCP chain output exceeds scoped packet ceiling")
	}
	return nil
}
func ChainLabel(actions []Action) string {
	parts := []string{}
	for _, a := range actions {
		label := a.Kind
		if a.Kind == "fake-tls" && a.Repeats > 1 {
			label += " x" + strconv.Itoa(int(a.Repeats))
		}
		if a.SequenceOverlap != 0 {
			label += " seqovl=" + strconv.Itoa(int(a.SequenceOverlap))
		}
		parts = append(parts, label)
	}
	return strings.Join(parts, " + ")
}

// tlsSNI locates only a COMPLETE single-record ClientHello. No QUIC decryption,
// ECH inner-name attribution or guessing. BufferTCP may supply a bounded logical
// parser record assembled from multiple wire records; it is never emitted.
func tlsSNI(p []byte) (int, int, bool) {
	if len(p) < 44 || p[0] != 22 || p[1] != 3 || p[2] < 1 || p[2] > 3 || p[5] != 1 || p[9] != 3 || p[10] < 1 || p[10] > 3 || p[43] > 32 {
		return 0, 0, false
	}
	end := 5 + int(binary.BigEndian.Uint16(p[3:]))
	if end > len(p) || end < 44 {
		return 0, 0, false
	}
	handshake := int(p[6])<<16 | int(p[7])<<8 | int(p[8])
	if handshake+9 != end {
		return 0, 0, false
	}
	i := 43
	take := func(n int) bool {
		if n < 0 || i+n > end {
			return false
		}
		i += n
		return true
	}
	if !take(1) || !take(int(p[43])) || !take(2) {
		return 0, 0, false
	}
	n := int(binary.BigEndian.Uint16(p[i-2:]))
	if n < 2 || n%2 != 0 || !take(n) || !take(1) {
		return 0, 0, false
	}
	n = int(p[i-1])
	if n < 1 || !take(n) || !take(2) {
		return 0, 0, false
	}
	n = int(binary.BigEndian.Uint16(p[i-2:]))
	if n != end-i {
		return 0, 0, false
	}
	start, size := 0, 0
	for i+4 <= end {
		k := binary.BigEndian.Uint16(p[i:])
		n = int(binary.BigEndian.Uint16(p[i+2:]))
		i += 4
		if i+n > end {
			return 0, 0, false
		}
		// Match only the observable outer SNI. ECH inner names are never read
		// or inferred; a public_name outside the explicit set stays DIRECT.
		if k == 0 {
			if start != 0 || n < 5 || int(binary.BigEndian.Uint16(p[i:]))+2 != n || p[i+2] != 0 {
				return 0, 0, false
			}
			size = int(binary.BigEndian.Uint16(p[i+3:]))
			if size+5 != n {
				return 0, 0, false
			}
			start = i + 5
		}
		i += n
	}
	if i != end || start == 0 {
		return 0, 0, false
	}
	if _, err := domain(string(p[start : start+size])); err != nil {
		return 0, 0, false
	}
	return start, size, true
}

// Own deterministic TLS1.2 ClientHello, not copied upstream data. Deliberately
// innocuous example.org SNI; fake is always entirely OLD sequence space.
func fakeHello() []byte {
	host := []byte("www.example.org")
	body := append([]byte{3, 3}, make([]byte, 32)...)
	body = append(body, 0, 0, 2, 0, 0x2f, 1, 0)
	ext := []byte{0, 0, 0, byte(5 + len(host)), 0, byte(3 + len(host)), 0, 0, byte(len(host))}
	ext = append(ext, host...)
	body = append(body, byte(len(ext)>>8), byte(len(ext)))
	body = append(body, ext...)
	handshake := append([]byte{1, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}, body...)
	return append([]byte{22, 3, 1, byte(len(handshake) >> 8), byte(len(handshake))}, handshake...)
}
func oldSequenceFake(p []byte, st *State, ttl uint8) []byte {
	payload, ok := packetPayload(p, "tcp")
	if !ok || p[33]&0x10 == 0 || !st.synSeen || !st.handshakeConfirmed || st.inspected != 1 || st.fakeSent || binary.BigEndian.Uint32(p[24:]) != st.synSequence+1 || binary.BigEndian.Uint32(p[28:]) != st.serverSequence+1 || p[8] <= ttl {
		return nil
	}
	hello := payload
	if st.logicalHello != nil {
		hello = st.logicalHello
	}
	if _, _, ok = tlsSNI(hello); !ok {
		return nil
	}
	data := fakeHello()
	q := make([]byte, 40+len(data))
	copy(q, p[:40])
	copy(q[40:], data)
	q[32] = 0x50
	q[33] = 0x18 // no SYN/FIN/RST/URG or options/negotiation changes
	q[8] = ttl
	binary.BigEndian.PutUint16(q[2:], uint16(len(q)))
	binary.BigEndian.PutUint16(q[4:], binary.BigEndian.Uint16(p[4:])+1)
	// Inclusive fake end = SYN ISN; RCV.NXT is at least SYN ISN+1.
	// Modulo arithmetic is TCP serial arithmetic, including ISN wraparound.
	binary.BigEndian.PutUint32(q[24:], st.synSequence+1-uint32(len(data)))
	checksumTransport(q)
	return q
}
func chainPackets(p []byte, st *State, c *compiled) Result {
	payload, ok := packetPayload(p, "tcp")
	if !ok || p[33]&0x10 == 0 || len(payload) == 0 || len(p) > 1500 {
		return Result{}
	}
	var real [][]byte
	var fake []byte
	var ttl uint8
	repeats := 1
	for _, a := range c.Actions {
		switch a.Kind {
		case "fake-tls":
			fake = catalogFake(p, st, a)
			if fake == nil {
				return Result{}
			} // uncertain handshake => entire plan fail-open
			ttl = fake[8]
			if a.Repeats > 0 {
				repeats = int(a.Repeats)
			}
		case "tcp-multisplit":
			if len(a.Markers) > 0 {
				cuts, ok := catalogCuts(a, payload)
				if !ok {
					return Result{}
				}
				real = splitPayload(p, payload, cuts)
				if len(real) == 0 {
					return Result{}
				}
				continue
			}
			offset := 0
			if a.Anchor == "sni" {
				var ok bool
				offset, _, ok = tlsSNI(payload)
				if !ok {
					return Result{}
				}
			}
			positions := []int{0}
			for _, v := range a.Positions {
				pos := offset + int(v)
				if pos <= 0 || pos >= len(payload) {
					return Result{}
				}
				positions = append(positions, pos)
			}
			positions = append(positions, len(payload))
			sort.Ints(positions)
			h := len(p) - len(payload)
			real = nil
			for i := 0; i+1 < len(positions); i++ {
				lo, hi := positions[i], positions[i+1]
				q := make([]byte, h+hi-lo)
				copy(q, p[:h])
				copy(q[h:], payload[lo:hi])
				if i+2 < len(positions) {
					q[33] &^= 8
				}
				if i > 0 {
					q[33] &^= 0x80
				}
				binary.BigEndian.PutUint32(q[24:], binary.BigEndian.Uint32(p[24:])+uint32(lo))
				binary.BigEndian.PutUint16(q[2:], uint16(len(q)))
				checksumTransport(q)
				real = append(real, q)
			}
		case "tcp-disorder":
			for i, j := 0, len(real)-1; i < j; i, j = i+1, j-1 {
				real[i], real[j] = real[j], real[i]
			}
		}
	}
	if len(real) == 0 {
		q := append([]byte(nil), p...)
		checksumTransport(q)
		real = [][]byte{q}
	}
	for _, a := range c.Actions {
		if a.SequenceOverlap != 0 {
			if !applySequenceOverlap(real, st, a.SequenceOverlap) {
				return Result{}
			}
		}
	}

	if fake != nil {
		st.fakeSent = true
		copies := make([][]byte, repeats)
		for i := range copies {
			copies[i] = append([]byte(nil), fake...)
			binary.BigEndian.PutUint16(copies[i][4:], binary.BigEndian.Uint16(fake[4:])+uint16(i))
			checksumTransport(copies[i])
		}
		real = append(copies, real...)
	}
	return Result{Packets: real, Modified: len(real) > 1, FakePackets: uint64(repeats) * boolCount(fake != nil), FakeTTL: ttl, Chain: ChainLabel(c.Actions), Preset: c.Preset}
}
func boolCount(v bool) uint64 {
	if v {
		return 1
	}
	return 0
}

func observeSYN(p []byte, st *State) {
	if len(p) < 40 || p[0] != 0x45 || p[9] != 6 || int(binary.BigEndian.Uint16(p[2:])) != len(p) || binary.BigEndian.Uint16(p[6:])&0x3fff != 0 || p[33]&0x3f != 2 {
		return
	}
	h := 20 + int(p[32]>>4)*4
	if h != len(p) || h < 40 {
		return
	} // SYN payload/Fast Open is not eligible for fake
	seq := binary.BigEndian.Uint32(p[24:])
	if st.synSeen && st.synSequence != seq {
		st.Disable()
		return
	}
	st.synSeen = true
	st.synSequence = seq
}

// Called only for an exact reverse-tuple inbound SYN/ACK observed by the existing
// TCP capture handle. It grants no route decision and stores no packet payload.
func (s *State) ConfirmHandshake(clientACK, serverSequence uint32) {
	if s.synSeen && !s.failed && clientACK == s.synSequence+1 {
		s.handshakeConfirmed = true
		s.serverSequence = serverSequence
	}
}
