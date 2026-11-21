package protocol

import (
	"encoding/binary"
	"errors"
	"io"
)

const TicketALPN = "neexitlag/2"
const MaxTicket = 8192

func WriteTicket(w io.Writer, raw []byte) error {
	if len(raw) == 0 || len(raw) > MaxTicket {
		return errors.New("invalid ticket length")
	}
	var n [4]byte
	binary.BigEndian.PutUint32(n[:], uint32(len(raw)))
	if _, e := w.Write(n[:]); e != nil {
		return e
	}
	_, e := w.Write(raw)
	return e
}
func ReadTicket(r io.Reader) ([]byte, error) {
	var n [4]byte
	if _, e := io.ReadFull(r, n[:]); e != nil {
		return nil, e
	}
	size := binary.BigEndian.Uint32(n[:])
	if size == 0 || size > MaxTicket {
		return nil, errors.New("invalid ticket length")
	}
	b := make([]byte, size)
	_, e := io.ReadFull(r, b)
	return b, e
}
