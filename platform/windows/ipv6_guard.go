package windowsplatform

import (
	"encoding/binary"
	"errors"
	"net/netip"
	"sync"
	"time"
)

// ParseIPv6Transport supports bounded extension chains, never parses TLS/QUIC.
// Fragments/jumbograms remain unsupported and are not mistaken for complete flows.
func ParseIPv6Transport(p []byte) (Tuple, byte, error) {
	if len(p) < 40 || p[0]>>4 != 6 || int(binary.BigEndian.Uint16(p[4:6]))+40 != len(p) {
		return Tuple{}, 0, errors.New("invalid IPv6 packet")
	}
	next, offset := p[6], 40
	for depth := 0; depth < 8; depth++ {
		if next == 6 || next == 17 {
			minimum := 8
			proto := "udp"
			flags := byte(0)
			if next == 6 {
				minimum = 20
				proto = "tcp"
			}
			if offset+minimum > len(p) {
				return Tuple{}, 0, errors.New("truncated IPv6 transport")
			}
			if next == 6 {
				h := int(p[offset+12]>>4) * 4
				if h < 20 || offset+h > len(p) {
					return Tuple{}, 0, errors.New("invalid TCP header")
				}
				flags = p[offset+13]
			} else if int(binary.BigEndian.Uint16(p[offset+4:offset+6])) != len(p)-offset {
				return Tuple{}, 0, errors.New("invalid UDP length")
			}
			var s, d [16]byte
			copy(s[:], p[8:24])
			copy(d[:], p[24:40])
			return Tuple{proto, netip.AddrPortFrom(netip.AddrFrom16(s), binary.BigEndian.Uint16(p[offset:offset+2])), netip.AddrPortFrom(netip.AddrFrom16(d), binary.BigEndian.Uint16(p[offset+2:offset+4]))}, flags, nil
		}
		if next != 0 && next != 43 && next != 60 {
			return Tuple{}, 0, errors.New("unsupported IPv6 extension/fragment")
		}
		if offset+2 > len(p) {
			return Tuple{}, 0, errors.New("truncated IPv6 extension")
		}
		size := (int(p[offset+1]) + 1) * 8
		next = p[offset]
		offset += size
		if offset > len(p) {
			return Tuple{}, 0, errors.New("invalid IPv6 extension")
		}
	}
	return Tuple{}, 0, errors.New("IPv6 extension chain too long")
}

type ipv6Pin struct {
	block    bool
	last     time.Time
	identity ProcessIdentity
}
type IPv6Guard struct {
	mu   sync.Mutex
	pins map[Tuple]ipv6Pin
}

func (g *IPv6Guard) Cleanup(now time.Time) {
	g.mu.Lock()
	defer g.mu.Unlock()
	for t, p := range g.pins {
		if now.Sub(p.last) > 2*time.Minute {
			delete(g.pins, t)
		}
	}
}
func (g *IPv6Guard) Block(id ProcessIdentity, t Tuple, flags byte, d Decision, self uint32, now time.Time) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.pins == nil {
		g.pins = map[Tuple]ipv6Pin{}
	}
	if p, ok := g.pins[t]; ok {
		if p.identity.PID == id.PID && p.identity.CreationTime == id.CreationTime && p.identity.Path == id.Path {
			p.last = now
			// A new SYN may reuse this socket tuple. During an existing CS2
			// connection, a DNS cache refresh must not interrupt the stream.
			if t.Protocol != "tcp" || !d.CS2Auto || !d.NewConnectionsOnly || flags&0x12 == 0x02 {
				p.block = id.PID != self && requiresInterception(d)
			}
			g.pins[t] = p
			return p.block
		}
		delete(g.pins, t)
	}
	block := id.PID != 0 && id.CreationTime != 0 && id.Path != "" && id.PID != self && requiresInterception(d)
	if len(g.pins) >= 8192 {
		return block
	}
	g.pins[t] = ipv6Pin{block, now, id}
	return block
}
