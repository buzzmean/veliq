package localstrategy

import (
	"encoding/binary"
	"sort"
)

// chainStream cuts real original packets at logical stream positions. Every
// output keeps the original options/ACK/window/address context and is no larger
// than that original; sequence numbers change only by the local cut offset.
func chainStream(st *State, c *compiled) Result {
	if len(st.helloPackets) == 0 {
		return Result{}
	}
	actions := c.Actions
	if c.Strategy == "tcp-split-1" {
		actions = []Action{{Kind: "tcp-multisplit", Positions: []uint16{1}}}
	} else if c.Strategy == "tcp-split-5" {
		actions = []Action{{Kind: "tcp-multisplit", Positions: []uint16{5}}}
	} else if c.Strategy == "tcp-split" {
		actions = []Action{{Kind: "tcp-multisplit", Positions: []uint16{c.SplitPosition}}}
	} else if c.Strategy != "chain" {
		return Result{}
	}
	base := st.synSequence + 1
	order := make([]int, len(st.helloPackets))
	for i := range order {
		order[i] = i
	}
	sort.SliceStable(order, func(i, j int) bool {
		return int32(binary.BigEndian.Uint32(st.helloPackets[order[i]][24:])-base) < int32(binary.BigEndian.Uint32(st.helloPackets[order[j]][24:])-base)
	})
	first := st.helloPackets[order[0]]
	if binary.BigEndian.Uint32(first[24:]) != base {
		return Result{}
	}
	cuts := []int{}
	reverse := false
	var fake []byte
	var ttl uint8
	repeats := 1
	for _, a := range actions {
		switch a.Kind {
		case "fake-tls":
			fake = catalogFake(first, st, a)
			if fake == nil {
				return Result{}
			}
			ttl = fake[8]
			if a.Repeats > 0 {
				repeats = int(a.Repeats)
			}
		case "tcp-multisplit":
			if len(a.Markers) > 0 {
				positions, ok := catalogCuts(a, st.logicalHello)
				if !ok {
					return Result{}
				}
				for _, pos := range positions {
					if pos <= 0 || pos >= len(st.helloOffsets) {
						return Result{}
					}
					cuts = append(cuts, st.helloOffsets[pos])
				}
				continue
			}
			start := 0
			if a.Anchor == "sni" {
				var ok bool
				start, _, ok = tlsSNI(st.logicalHello)
				if !ok {
					return Result{}
				}
			}
			for _, v := range a.Positions {
				pos := start + int(v)
				if pos <= 0 || pos >= len(st.helloOffsets) {
					return Result{}
				}
				cuts = append(cuts, st.helloOffsets[pos])
			}
		case "tcp-disorder":
			reverse = true
		}
	}
	out := Result{InputPackets: len(st.helloPackets), ModifiedOrigins: make([]bool, len(st.helloPackets)), Chain: ChainLabel(actions), Preset: c.Preset, FakeTTL: ttl}
	changed := false
	for _, index := range order {
		p := st.helloPackets[index]
		payload, ok := packetPayload(p, "tcp")
		if !ok || len(p) > 1500 || p[33]&0x10 == 0 {
			return Result{}
		}
		off := int(int32(binary.BigEndian.Uint32(p[24:]) - base))
		positions := []int{0}
		for _, cut := range cuts {
			if cut > off && cut < off+len(payload) {
				positions = append(positions, cut-off)
			}
		}
		sort.Ints(positions)
		positions = append(positions, len(payload))
		h := len(p) - len(payload)
		if len(positions) > 2 {
			changed = true
			out.ModifiedOrigins[index] = true
		}
		for i := 0; i+1 < len(positions); i++ {
			lo, hi := positions[i], positions[i+1]
			q := make([]byte, h+hi-lo)
			copy(q, p[:h])
			copy(q[h:], payload[lo:hi])
			if hi < len(payload) {
				q[33] &^= 8
			}
			if lo > 0 {
				q[33] &^= 0x80
			}
			binary.BigEndian.PutUint32(q[24:], binary.BigEndian.Uint32(p[24:])+uint32(lo))
			binary.BigEndian.PutUint16(q[2:], uint16(len(q)))
			checksumTransport(q)
			out.Packets = append(out.Packets, q)
			out.PacketOrigins = append(out.PacketOrigins, index)
		}
	}
	for _, a := range actions {
		if a.SequenceOverlap != 0 {
			if !applySequenceOverlap(out.Packets, st, a.SequenceOverlap) {
				return Result{}
			}
			changed = true
		}
	}

	if reverse {
		for i := range out.ModifiedOrigins {
			out.ModifiedOrigins[i] = true
		}
		for i, j := 0, len(out.Packets)-1; i < j; i, j = i+1, j-1 {
			out.Packets[i], out.Packets[j] = out.Packets[j], out.Packets[i]
			out.PacketOrigins[i], out.PacketOrigins[j] = out.PacketOrigins[j], out.PacketOrigins[i]
		}
		changed = true
	}
	if fake != nil {
		copies := make([][]byte, repeats)
		origins := make([]int, repeats)
		for i := range copies {
			copies[i] = append([]byte(nil), fake...)
			binary.BigEndian.PutUint16(copies[i][4:], binary.BigEndian.Uint16(fake[4:])+uint16(i))
			checksumTransport(copies[i])
			origins[i] = order[0]
		}
		out.Packets = append(copies, out.Packets...)
		out.PacketOrigins = append(origins, out.PacketOrigins...)
		out.FakePackets = uint64(repeats)
		out.ModifiedOrigins[order[0]] = true
		st.fakeSent = true
		changed = true
	}
	out.Modified = changed
	return out
}
