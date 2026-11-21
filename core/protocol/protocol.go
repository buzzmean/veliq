// Package protocol defines the versioned relay wire format.
package protocol

import (
	"encoding/binary"
	"errors"
	"io"
	"net/netip"
)

const Version byte = 1
const HeaderSize = 5
const MaxPayload = 1472
const OpenSize = 24
const UDP byte = 1
const TCP byte = 2

var ErrFrame = errors.New("invalid protocol frame")

type Open struct {
	Kind        byte
	ID          uint32
	Destination netip.AddrPort
}

func (o Open) Write(w io.Writer) error {
	if (o.Kind != UDP && o.Kind != TCP) || o.ID == 0 || !o.Destination.IsValid() || o.Destination.Port() == 0 || o.Destination.Addr().Zone() != "" {
		return ErrFrame
	}
	var b [OpenSize]byte
	b[0] = Version
	b[1] = o.Kind
	binary.BigEndian.PutUint32(b[2:6], o.ID)
	a := o.Destination.Addr().As16()
	copy(b[6:22], a[:])
	binary.BigEndian.PutUint16(b[22:], o.Destination.Port())
	n, e := w.Write(b[:])
	if e == nil && n != len(b) {
		return io.ErrShortWrite
	}
	return e
}
func ReadOpen(r io.Reader) (Open, error) {
	var b [OpenSize]byte
	if _, e := io.ReadFull(r, b[:]); e != nil {
		return Open{}, e
	}
	if b[0] != Version || (b[1] != UDP && b[1] != TCP) {
		return Open{}, ErrFrame
	}
	var a [16]byte
	copy(a[:], b[6:22])
	o := Open{b[1], binary.BigEndian.Uint32(b[2:6]), netip.AddrPortFrom(netip.AddrFrom16(a).Unmap(), binary.BigEndian.Uint16(b[22:]))}
	if o.ID == 0 || o.Destination.Port() == 0 {
		return Open{}, ErrFrame
	}
	return o, nil
}
func Encode(id uint32, p []byte) ([]byte, error) {
	if id == 0 || len(p) > MaxPayload {
		return nil, ErrFrame
	}
	b := make([]byte, HeaderSize+len(p))
	b[0] = Version
	binary.BigEndian.PutUint32(b[1:5], id)
	copy(b[5:], p)
	return b, nil
}
func Decode(b []byte) (uint32, []byte, error) {
	if len(b) < HeaderSize || len(b) > HeaderSize+MaxPayload || b[0] != Version {
		return 0, nil, ErrFrame
	}
	id := binary.BigEndian.Uint32(b[1:5])
	if id == 0 {
		return 0, nil, ErrFrame
	}
	return id, b[5:], nil
}
