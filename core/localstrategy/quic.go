package localstrategy

import (
	"encoding/binary"
	"net/netip"
	"time"
)

// Recognize a bounded IPv4 QUIC v1 Initial, not a hostname. App-wide UDP/443
// fallback is explicitly opt-in in the preset. Existing non-Initial UDP flows,
// non-443 voice and malformed/unsupported packets remain native DIRECT.
func (e *LocalStrategyEngine) processQUIC(p []byte, st *State, m Metadata, s *snapshot) (Result, bool) {
	payload, ok := packetPayload(p, "udp")
	first := !st.udpSeen
	st.udpSeen = true
	if !ok || m.Destination.Port() != 443 || st.failed {
		return Result{}, false
	}
	var dest [4]byte
	copy(dest[:], p[16:20])
	if netip.AddrPortFrom(netip.AddrFrom4(dest), binary.BigEndian.Uint16(p[22:])) != m.Destination {
		return Result{}, false
	}
	now := time.Now()
	if first && validQUICInitial(payload) {
		for _, c := range s.profiles {
			if c.Enabled && c.QuicFallback && !c.excludes.IPs.Contains(m.Destination.Addr()) && appMatch(c.Application, m.Application) && (m.StrategyID == "" || m.StrategyID == c.ID) {
				st.quicUntil = now.Add(3 * time.Second)
				st.quicStrategy = c.ID
				st.quicPreset = c.Preset
				st.generation = s.generation
				break
			}
		}
	}
	if now.Before(st.quicUntil) && st.quicDrops < 8 {
		st.quicDrops++
		return Result{Suppress: true, Strategy: st.quicStrategy, Preset: st.quicPreset, Chain: "HTTP/3/QUIC → TCP fallback"}, true
	}
	return Result{}, false
}

func validQUICInitial(p []byte) bool {
	if len(p) < 1200 || p[0]&0xf0 != 0xc0 || binary.BigEndian.Uint32(p[1:]) != 1 {
		return false
	}
	i := 5
	take := func(n int) bool {
		if n < 0 || i+n > len(p) {
			return false
		}
		i += n
		return true
	}
	dcid := int(p[i])
	i++
	if dcid < 8 || dcid > 20 || !take(dcid) || !take(1) {
		return false
	}
	scid := int(p[i-1])
	if scid > 20 || !take(scid) {
		return false
	}
	read := func() (uint64, bool) {
		if i >= len(p) {
			return 0, false
		}
		n := 1 << uint(p[i]>>6)
		if i+n > len(p) {
			return 0, false
		}
		v := uint64(p[i] & 63)
		for j := 1; j < n; j++ {
			v = v<<8 | uint64(p[i+j])
		}
		i += n
		return v, true
	}
	token, ok := read()
	if !ok || token > uint64(len(p)-i) || !take(int(token)) {
		return false
	}
	n, ok := read()
	return ok && n >= 17 && n <= uint64(len(p)-i)
}
