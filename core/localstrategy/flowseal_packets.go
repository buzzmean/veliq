package localstrategy

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"sort"
	"strings"
)

// Rebuild just IPv4/TCP headers, preserving the original stream context. Fake
// fooling changes only the requested fields; TS/MD5 no longer imply badseq.
func nativeTCPPacket(base, data []byte, offset int, fake bool, plan *NativeTCPPlan) []byte {
	if len(base) < 40 || base[0] != 0x45 || base[9] != 6 {
		return nil
	}
	h := 20 + int(base[32]>>4)*4
	if h < 40 || h > len(base) {
		return nil
	}
	options := append([]byte(nil), base[40:h]...)
	if fake {
		if strings.Contains(plan.Fooling, "ts") {
			for i := 0; i < len(options); {
				if options[i] == 0 {
					break
				}
				if options[i] == 1 {
					i++
					continue
				}
				if i+1 >= len(options) || int(options[i+1]) < 2 || i+int(options[i+1]) > len(options) {
					return nil
				}
				if options[i] == 8 && options[i+1] == 10 {
					v := binary.BigEndian.Uint32(options[i+2:])
					binary.BigEndian.PutUint32(options[i+2:], v+uint32(plan.TimestampDelta))
				}
				i += int(options[i+1])
			}
		}
		if strings.Contains(plan.Fooling, "md5sig") {
			// End-of-list padding must not hide the newly appended option.
			end := len(options)
			for i := 0; i < len(options); {
				if options[i] == 0 {
					end = i
					break
				}
				if options[i] == 1 {
					i++
					continue
				}
				if i+1 >= len(options) || options[i+1] < 2 || i+int(options[i+1]) > len(options) {
					return nil
				}
				i += int(options[i+1])
			}
			options = options[:end]
			signature := make([]byte, 16)
			if _, e := rand.Read(signature); e != nil {
				return nil
			}
			options = append(options, 19, 18)
			options = append(options, signature...)
		}
	}
	for len(options)%4 != 0 {
		options = append(options, 1)
	}
	if len(options) > 40 || 40+len(options)+len(data) > 1500 {
		return nil
	}
	q := make([]byte, 40+len(options)+len(data))
	copy(q, base[:40])
	copy(q[40:], options)
	copy(q[40+len(options):], data)
	q[32] = uint8((20+len(options))/4) << 4
	seq := binary.BigEndian.Uint32(base[24:]) + uint32(offset)
	ack := binary.BigEndian.Uint32(base[28:])
	if fake && plan.Fooling == "badseq" {
		seq += uint32(plan.BadSequence)
		ack += uint32(plan.BadACK)
	}
	binary.BigEndian.PutUint32(q[24:], seq)
	binary.BigEndian.PutUint32(q[28:], ack)
	if plan.ZeroIPID {
		q[4], q[5] = 0, 0
	}
	binary.BigEndian.PutUint16(q[2:], uint16(len(q)))
	checksumTransport(q)
	return q
}
func nativeModel(model NativeFakeModel, hello []byte) []byte {
	switch model.Kind {
	case "zeros4":
		return make([]byte, 4)
	case "stun", "stun2":
		p := make([]byte, 20)
		if model.Kind == "stun2" {
			p = make([]byte, 28)
			binary.BigEndian.PutUint16(p[2:], 8)
		}
		p[1] = 1
		binary.BigEndian.PutUint32(p[4:], 0x2112a442)
		nonce := sha256.Sum256([]byte("VELIQ public STUN model:" + model.Kind))
		copy(p[8:20], nonce[:12])
		return p
	case "tls":
		fill := rand.Read
		if !model.Randomize {
			counter := uint32(0)
			fill = func(p []byte) (int, error) {
				for i := 0; i < len(p); {
					key := []byte("VELIQ public fake model:" + model.Host)
					key = binary.BigEndian.AppendUint32(key, counter)
					counter++
					sum := sha256.Sum256(key)
					i += copy(p[i:], sum[:])
				}
				return len(p), nil
			}
		}
		p := ownCatalogHelloRandom(model.Host, 1250, fill)
		if p == nil {
			return nil
		}

		if model.DuplicateSID && len(hello) > 44 {
			n := int(hello[43])
			if n == 32 && len(hello) >= 44+n {
				copy(p[44:76], hello[44:76])
			}
		}
		return p
	}
	return nil
}
func nativeHostPattern(host string, n int) []byte {
	if n < 1 || len(host) == 0 {
		return nil
	}
	if n <= len(host) {
		return []byte(host[len(host)-n:])
	}
	p := make([]byte, n)
	if _, e := rand.Read(p); e != nil {
		return nil
	}
	for i := range p {
		p[i] = 'a' + p[i]%26
	}
	copy(p[n-len(host):], host)
	p[n-len(host)-1] = '.'
	return p
}

// Recipes operate over original TCP packets (not a rewritten TLS record). The
// existing reassembler maps parser offsets back to untouched wire positions.
func nativeTCPData(packet []byte, st *State, c *compiled, plan *NativeTCPPlan) Result {
	if !st.synSeen || !st.handshakeConfirmed || st.inspected != 1 {
		return Result{}
	}
	state := *st
	if len(state.helloPackets) == 0 {
		payload, ok := packetPayload(packet, "tcp")
		if !ok {
			return Result{}
		}
		state.helloPackets = [][]byte{packet}
		state.logicalHello = payload
		state.helloOffsets = make([]int, len(payload))
		for i := range state.helloOffsets {
			state.helloOffsets[i] = i
		}
	}
	physicalCount := len(state.helloPackets)
	var canonical [][]byte
	var physicalOrigins []int
	for index, original := range state.helloPackets {
		h := 20 + int(original[32]>>4)*4
		if h < 40 || h > len(original) {
			return Result{}
		}
		data := original[h:]
		limit := 1500 - h
		// Faked-split wraps real segments in fake segments with a TCP MD5 option.
		// Reserve its padded header space before segmentation, including LSO input.
		if strings.Contains(plan.Fooling, "md5sig") && (strings.Contains(plan.Mode, "fakedsplit") || strings.Contains(plan.Mode, "fakeddisorder")) {
			limit -= 20
		}
		if limit < 1 {
			return Result{}
		}
		for lo := 0; lo < len(data); lo += limit {
			hi := lo + limit
			if hi > len(data) {
				hi = len(data)
			}
			part := nativeTCPPacket(original, data[lo:hi], lo, false, plan)
			if part == nil {
				return Result{}
			}
			if hi < len(data) {
				part[33] &^= 8
				checksumTransport(part)
			}
			canonical = append(canonical, part)
			physicalOrigins = append(physicalOrigins, index)
		}
	}
	state.helloPackets = canonical
	order := make([]int, len(state.helloPackets))
	for i := range order {
		order[i] = i
	}
	sort.Slice(order, func(i, j int) bool {
		return int32(binary.BigEndian.Uint32(state.helloPackets[order[i]][24:])-st.synSequence-1) < int32(binary.BigEndian.Uint32(state.helloPackets[order[j]][24:])-st.synSequence-1)
	})
	first := state.helloPackets[order[0]]
	if strings.Contains(plan.Fooling, "ts") && !strings.Contains(plan.Fooling, "md5sig") && !nativeHasTimestamp(first) {
		return Result{Inspection: &Inspection{Reason: "TIMESTAMP_OPTION_REQUIRED", Detail: "pure TS fake requires timestamp negotiation; no in-window fake emitted"}}
	}

	realPlan := *c
	realPlan.Strategy = "chain"
	realPlan.Actions = nil
	mode := plan.Mode
	if strings.Contains(mode, "hostfakesplit") {
		a, n, ok := tlsSNI(state.logicalHello)
		if !ok || n < 1 || a+n > len(state.helloOffsets) {
			return Result{}
		}
		positions := []uint16{uint16(a)}
		if a+n < len(state.helloOffsets) {
			positions = append(positions, uint16(a+n))
		}
		realPlan.Actions = []Action{{Kind: "tcp-multisplit", Positions: positions}}
	} else if strings.Contains(mode, "split") || strings.Contains(mode, "disorder") {
		markers := plan.Markers
		if strings.Contains(mode, "fakedsplit") || strings.Contains(mode, "fakeddisorder") {
			// winws chooses the first resolvable non-absolute marker, then absolute,
			// with one-byte split when no configured position resolves.
			markers = []string{"1"}
			for _, m := range plan.Markers {
				if m != "1" && m != "2" {
					markers = []string{m}
					break
				}
			}
			if len(markers) == 1 && markers[0] == "1" && len(plan.Markers) > 0 {
				markers = []string{plan.Markers[0]}
			}
		}
		if len(markers) > 0 {
			realPlan.Actions = []Action{{Kind: "tcp-multisplit", Markers: markers, SequenceOverlap: plan.SequenceOverlap}}
		}
	}
	real := chainStream(&state, &realPlan)
	if len(real.Packets) == 0 {
		return Result{}
	}
	out := Result{ModifiedOrigins: make([]bool, physicalCount), InputPackets: physicalCount, Preset: c.Preset, Chain: "native:" + mode}
	add := func(q []byte, origin int, fake bool) bool {
		if q == nil || len(out.Packets) >= NativeTCPPacketLimit {
			return false
		}
		if plan.ZeroIPID {
			q = append([]byte(nil), q...)
			q[4], q[5] = 0, 0
			checksumTransport(q)
		}
		out.PacketFake = append(out.PacketFake, fake)
		out.Packets = append(out.Packets, q)
		origin = physicalOrigins[origin]
		out.PacketOrigins = append(out.PacketOrigins, origin)
		out.ModifiedOrigins[origin] = true
		if fake {
			out.FakePackets++
			out.FakeTTL = q[8]
		}
		return true
	}
	repeat := func(q []byte, origin int) bool {
		for j := 0; j < int(plan.Repeats); j++ {
			if !add(append([]byte(nil), q...), origin, true) {
				return false
			}
		}
		return true
	}
	if strings.HasPrefix(mode, "fake") && strings.Split(mode, ",")[0] == "fake" {
		sequence := 0
		for _, model := range plan.Models {
			data := nativeModel(model, state.logicalHello)
			if data == nil {
				return Result{}
			}
			q := nativeTCPPacket(first, data, sequence, true, plan)
			if q == nil || !repeat(q, order[0]) {
				return Result{}
			}
			sequence += len(data)
		}
	}
	indices := make([]int, len(real.Packets))
	for i := range indices {
		indices[i] = i
	}
	if strings.Contains(mode, "disorder") {
		for i, j := 0, len(indices)-1; i < j; i, j = i+1, j-1 {
			indices[i], indices[j] = indices[j], indices[i]
		}
	}
	if strings.Contains(mode, "hostfakesplit") {
		start, size, _ := tlsSNI(state.logicalHello)
		lo, hi := state.helloOffsets[start], state.helloOffsets[start+size-1]+1
		host := plan.Host
		if host == "" {
			host = "www.google.com"
		}
		data := nativeHostPattern(host, hi-lo)
		q := nativeTCPPacket(first, data, lo, true, plan)
		// before host; fake; optional after host; real host; fake; optional after.
		before, inside, after := []int{}, []int{}, []int{}
		for i, p := range real.Packets {
			o := int(uint32(binary.BigEndian.Uint32(p[24:]) - st.synSequence - 1))
			if o < lo {
				before = append(before, i)
			} else if o < hi {
				inside = append(inside, i)
			} else {
				after = append(after, i)
			}
		}
		emit := func(rows []int) bool {
			for _, i := range rows {
				if !add(real.Packets[i], real.PacketOrigins[i], false) {
					return false
				}
			}
			return true
		}
		if !emit(before) || q == nil || !repeat(q, order[0]) {
			return Result{}
		}
		if plan.AlternateOrder && !emit(after) {
			return Result{}
		}
		if !emit(inside) {
			return Result{}
		}
		if !plan.AlternateOrder && !repeat(q, order[0]) {
			return Result{}
		}
		if !plan.AlternateOrder && !emit(after) {
			return Result{}
		}
	} else {
		surrounded := strings.Contains(mode, "fakedsplit") || strings.Contains(mode, "fakeddisorder")
		for _, i := range indices {
			p := real.Packets[i]
			origin := real.PacketOrigins[i]
			var fake []byte
			if surrounded {
				data, ok := packetPayload(p, "tcp")
				if !ok {
					return Result{}
				}
				fake = nativeTCPPacket(p, make([]byte, len(data)), 0, true, plan)
				if fake == nil || !repeat(fake, origin) {
					return Result{}
				}
			}
			if !add(p, origin, false) {
				return Result{}
			}
			if surrounded && !repeat(fake, origin) {
				return Result{}
			}
		}
	}
	out.Modified = real.Modified || out.FakePackets > 0
	if out.FakePackets > 0 {
		st.fakeSent = true
	}
	return out
}

// A SYN-data recipe replaces just a new empty non-TFO SYN. The TCP sequence
// number is unchanged. Normal data/established connections never enter here.
func nativeTCPSYN(p []byte, st *State, c *compiled, plan *NativeTCPPlan) Result {
	if !strings.Contains(plan.Mode, "syndata") || st.applied || len(p) < 40 || p[33]&0x3f != 2 {
		return Result{}
	}
	h := 20 + int(p[32]>>4)*4
	if h != len(p) {
		return Result{}
	}
	for i := 40; i < h; {
		if p[i] == 0 {
			break
		}
		if p[i] == 1 {
			i++
			continue
		}
		if i+1 >= h || p[i+1] < 2 || i+int(p[i+1]) > h {
			return Result{}
		}
		if p[i] == 34 {
			return Result{}
		}
		i += int(p[i+1])
	}
	q := nativeTCPPacket(p, make([]byte, 16), 0, false, plan)
	if q == nil {
		return Result{}
	}
	packets := make([][]byte, plan.Repeats)
	for i := range packets {
		packets[i] = append([]byte(nil), q...)
	}
	st.applied = true
	return Result{Strategy: c.ID, Packets: packets, Modified: true, First: true, FakePackets: uint64(len(packets)), FakeTTL: q[8], Preset: c.Preset, Chain: "native:syndata", Inspection: &Inspection{SYNSeen: true, Reason: "SYN_DATA_PLANNED", Detail: "new empty SYN; no TCP fast-open; no application payload"}}
}

func nativeHasTimestamp(p []byte) bool {
	if len(p) < 40 {
		return false
	}
	h := 20 + int(p[32]>>4)*4
	if h > len(p) {
		return false
	}
	for i := 40; i < h; {
		if p[i] == 0 {
			return false
		}
		if p[i] == 1 {
			i++
			continue
		}
		if i+1 >= h || p[i+1] < 2 || i+int(p[i+1]) > h {
			return false
		}
		if p[i] == 8 && p[i+1] == 10 {
			return true
		}
		i += int(p[i+1])
	}
	return false
}
