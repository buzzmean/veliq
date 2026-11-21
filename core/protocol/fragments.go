package protocol

import (
	"encoding/binary"
	"sync"
	"time"
)

const SmallPayload = 1100
const FragmentHeader = 13

// EncodeDatagrams preserves v1 for <=1100 bytes. Larger IPv4/1500-MTU UDP
// payloads use v2 fragments, without reliability, retries or stream tunneling.
func EncodeDatagrams(id, sequence uint32, p []byte) ([][]byte, error) {
	if len(p) <= SmallPayload {
		b, e := Encode(id, p)
		return [][]byte{b}, e
	}
	if id == 0 || sequence == 0 || len(p) > MaxPayload {
		return nil, ErrFrame
	}
	var out [][]byte
	for off := 0; off < len(p); {
		end := off + SmallPayload - FragmentHeader
		if end > len(p) {
			end = len(p)
		}
		b := make([]byte, FragmentHeader+end-off)
		b[0] = 2
		binary.BigEndian.PutUint32(b[1:5], id)
		binary.BigEndian.PutUint32(b[5:9], sequence)
		binary.BigEndian.PutUint16(b[9:11], uint16(len(p)))
		binary.BigEndian.PutUint16(b[11:13], uint16(off))
		copy(b[13:], p[off:end])
		out = append(out, b)
		off = end
	}
	return out, nil
}

type fragmentKey struct{ id, sequence uint32 }
type partialDatagram struct {
	data  []byte
	parts uint8
	at    time.Time
}

// Reassembly is bounded to 64 partial datagrams/session, each <=1472 bytes,
// with a fixed 2s lifetime. Only two canonical fragments are accepted. No packet
// is forwarded until both arrive; loss remains loss. No payload is logged.
type Reassembly struct {
	mu      sync.Mutex
	partial map[fragmentKey]partialDatagram
}

func (r *Reassembly) Decode(b []byte, now time.Time) (uint32, []byte, error) {
	if len(b) == 0 || b[0] != 2 {
		return Decode(b)
	}
	if len(b) < FragmentHeader+1 || len(b) > SmallPayload {
		return 0, nil, ErrFrame
	}
	id, seq := binary.BigEndian.Uint32(b[1:5]), binary.BigEndian.Uint32(b[5:9])
	size, off := int(binary.BigEndian.Uint16(b[9:11])), int(binary.BigEndian.Uint16(b[11:13]))
	chunk := SmallPayload - FragmentHeader
	if id == 0 || seq == 0 || size <= SmallPayload || size > MaxPayload || (off != 0 && off != chunk) || off >= size {
		return 0, nil, ErrFrame
	}
	end := off + len(b) - FragmentHeader
	want := off + chunk
	if want > size {
		want = size
	}
	if end != want {
		return 0, nil, ErrFrame
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.partial == nil {
		r.partial = map[fragmentKey]partialDatagram{}
	}
	for k, p := range r.partial {
		if now.Sub(p.at) >= 2*time.Second {
			delete(r.partial, k)
		}
	}
	key := fragmentKey{id, seq}
	p, ok := r.partial[key]
	if !ok {
		if len(r.partial) >= 64 {
			return 0, nil, ErrFrame
		}
		p = partialDatagram{data: make([]byte, size), at: now}
	} else if len(p.data) != size {
		delete(r.partial, key)
		return 0, nil, ErrFrame
	}
	bit := uint8(1)
	if off != 0 {
		bit = 2
	}
	if p.parts&bit != 0 {
		for i, v := range b[FragmentHeader:] {
			if p.data[off+i] != v {
				delete(r.partial, key)
				return 0, nil, ErrFrame
			}
		}
		return id, nil, nil
	}
	copy(p.data[off:end], b[FragmentHeader:])
	p.parts |= bit
	if p.parts == 3 {
		delete(r.partial, key)
		return id, p.data, nil
	}
	r.partial[key] = p
	return id, nil, nil
}
