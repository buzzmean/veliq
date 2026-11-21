package e2eprobe

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"github.com/buzzmean/neexitlag/core/routing"
	"net/netip"
	"sync"
)

// Adapts the existing real nonce measurement to the authenticated remote echo.
// The measured path and timer are unchanged. No delay or telemetry is synthesized.
type probeFlow struct {
	routing.Datagram
	key      []byte
	mu       sync.Mutex
	payload  []byte
	run      [16]byte
	sequence uint32
	// Recent probes, so a reply that arrives after the next probe was sent can still
	// be handed back (the engine decides whether it is late or current).
	recent map[[20]byte][]byte
	order  [][20]byte
}

func ProbeOpener(open func(context.Context, netip.AddrPort) (routing.Datagram, error), key []byte) func(context.Context, netip.AddrPort) (routing.Datagram, error) {
	return func(ctx context.Context, target netip.AddrPort) (routing.Datagram, error) {
		d, e := open(ctx, target)
		if e != nil {
			return nil, e
		}
		return &probeFlow{Datagram: d, key: append([]byte(nil), key...)}, nil
	}
}
func (p *probeFlow) Send(b []byte) error {
	if len(b) != 32 {
		return errors.New("authenticated measurement expects 32-byte nonce; not an MTU probe")
	}
	p.mu.Lock()
	p.payload = append([]byte(nil), b...)
	copy(p.run[:], b[:16])
	p.sequence = binary.BigEndian.Uint32(b[16:20])
	packet := Packet{Run: p.run, Sequence: p.sequence}
	var id [20]byte
	copy(id[:], b[:20])
	if p.recent == nil {
		p.recent = make(map[[20]byte][]byte)
	}
	if len(p.order) >= 16 {
		delete(p.recent, p.order[0])
		p.order = p.order[1:]
	}
	p.recent[id] = append([]byte(nil), b...)
	p.order = append(p.order, id)
	p.mu.Unlock()
	return p.Datagram.Send(Encode(packet, p.key))
}
func (p *probeFlow) Receive(ctx context.Context) ([]byte, error) {
	for {
		b, e := p.Datagram.Receive(ctx)
		if e != nil {
			return nil, e
		}
		packet, e := Decode(b, p.key)
		if e != nil || !packet.Reply {
			continue
		}
		var id [20]byte
		copy(id[:16], packet.Run[:])
		binary.BigEndian.PutUint32(id[16:], packet.Sequence)
		p.mu.Lock()
		payload, valid := p.recent[id]
		payload = bytes.Clone(payload)
		p.mu.Unlock()
		if valid {
			return payload, nil
		}
	}
}
