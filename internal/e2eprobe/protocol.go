// Package e2eprobe is a bounded authenticated echo protocol for real route acceptance.
package e2eprobe

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"net/netip"
	"os"
	"strings"
)

const Size = 128

var magic = []byte("NEXE2E01")

type Packet struct {
	Run      [16]byte
	Sequence uint32
	Peer     netip.AddrPort
	Reply    bool
}

func Token(path string) ([]byte, error) {
	b, e := os.ReadFile(path)
	if e != nil {
		return nil, e
	}
	b = []byte(strings.TrimSpace(string(b)))
	if len(b) < 24 || len(b) > 128 {
		return nil, errors.New("echo token requires 24..128 characters")
	}
	return b, nil
}
func Encode(p Packet, key []byte) []byte {
	b := make([]byte, Size)
	copy(b, magic)
	copy(b[8:24], p.Run[:])
	binary.BigEndian.PutUint32(b[24:28], p.Sequence)
	if p.Reply && p.Peer.IsValid() && p.Peer.Addr().Is4() {
		ip := p.Peer.Addr().As4()
		copy(b[28:32], ip[:])
		binary.BigEndian.PutUint16(b[32:34], p.Peer.Port())
		b[34] = 1
	}
	mac := hmac.New(sha256.New, key)
	mac.Write(b[:96])
	copy(b[96:], mac.Sum(nil))
	return b
}
func Decode(b, key []byte) (Packet, error) {
	var p Packet
	if len(b) != Size || string(b[:8]) != string(magic) {
		return p, errors.New("invalid echo packet")
	}
	mac := hmac.New(sha256.New, key)
	mac.Write(b[:96])
	if !hmac.Equal(mac.Sum(nil), b[96:]) || b[34] > 1 {
		return p, errors.New("invalid echo authentication")
	}
	copy(p.Run[:], b[8:24])
	p.Sequence = binary.BigEndian.Uint32(b[24:28])
	p.Reply = b[34] == 1
	if p.Reply {
		var a [4]byte
		copy(a[:], b[28:32])
		p.Peer = netip.AddrPortFrom(netip.AddrFrom4(a), binary.BigEndian.Uint16(b[32:34]))
		if p.Peer.Port() == 0 {
			return p, errors.New("invalid observed source")
		}
	}
	return p, nil
}
