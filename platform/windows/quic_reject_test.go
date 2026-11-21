package windowsplatform

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func TestNativeQUICRejectQuotesHeadersOnly(t *testing.T) {
	// A real IPv4 UDP/443 packet; encrypted application payload is never quoted.
	p := make([]byte, 128)
	p[0] = 0x45
	p[8] = 64
	p[9] = 17
	binary.BigEndian.PutUint16(p[2:4], uint16(len(p)))
	copy(p[12:16], []byte{192, 0, 2, 1})
	copy(p[16:20], []byte{203, 0, 113, 7})
	binary.BigEndian.PutUint16(p[20:22], 50000)
	binary.BigEndian.PutUint16(p[22:24], 443)
	binary.BigEndian.PutUint16(p[24:26], uint16(len(p)-20))
	copy(p[28:], []byte("QUIC payload must never appear in diagnostics or ICMP quote"))
	reply, err := RejectBrowserQUIC(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(reply) != 56 || reply[20] != 3 || reply[21] != 3 || !bytes.Equal(reply[28:], p[:28]) || !bytes.Equal(reply[12:16], p[16:20]) {
		t.Fatal("wrong ICMP reject", reply)
	}
	for _, block := range [][]byte{reply[:20], reply[20:]} {
		var sum uint32
		for i := 0; i < len(block); i += 2 {
			sum += uint32(binary.BigEndian.Uint16(block[i : i+2]))
		}
		for sum>>16 != 0 {
			sum = (sum & 65535) + (sum >> 16)
		}
		if sum != 65535 {
			t.Fatal("invalid independent checksum")
		}
	}
	binary.BigEndian.PutUint16(p[22:24], 53)
	if _, err = RejectBrowserQUIC(p); err == nil {
		t.Fatal("DNS rejected")
	}
	if _, err = RejectBrowserQUIC(p[:26]); err == nil {
		t.Fatal("truncated packet accepted")
	}
}
