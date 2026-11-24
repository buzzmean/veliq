package gameudp

import (
	"crypto/rand"
	"encoding/binary"
)

// STUNPayload is an unauthenticated Binding request header. It does not contact
// a STUN service or retain identity, traffic contents, or a discovered address.
func STUNPayload() ([]byte, error) {
	p := make([]byte, 20)
	binary.BigEndian.PutUint16(p, 1)
	binary.BigEndian.PutUint32(p[4:], 0x2112a442)
	if _, err := rand.Read(p[8:]); err != nil {
		return nil, err
	}
	return p, nil
}
func IsSTUNBinding(p []byte) bool {
	return len(p) == 20 && binary.BigEndian.Uint16(p) == 1 && binary.BigEndian.Uint16(p[2:]) == 0 && binary.BigEndian.Uint32(p[4:]) == 0x2112a442
}
