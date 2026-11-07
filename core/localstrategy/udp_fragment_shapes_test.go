package localstrategy

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"testing"
)

func TestUDPFragmentShapesPreserveDatagram(t *testing.T) {
	for _, split := range []int{8, 16, 24} {
		t.Run(fmt.Sprint(split), func(t *testing.T) {
			p := continuousUDPProfile()
			p.Strategy = fmt.Sprintf("udp-fragment-%d", split)
			e, st, m := engine(t, p), &State{}, metadata()
			m.Protocol = "udp"
			for i := 0; i < 512; i++ {
				payload := make([]byte, 17+i%1200)
				for j := range payload {
					payload[j] = byte(i + j*37)
				}
				raw := packet(17, payload)
				// Exercise transport-checksum offload input, including its zero form.
				raw[26], raw[27] = 0, 0
				before := append([]byte(nil), raw...)
				r := e.Process(raw, st, m)
				if !r.Modified || len(r.Packets) != 2 || r.FakePackets != 0 {
					t.Fatalf("datagram%d: missing two-fragment plan", i)
				}
				var body []byte
				for j, q := range r.Packets {
					frag := binary.BigEndian.Uint16(q[6:])
					if finish(sum(q[:20])) != 0 || int(frag&8191)*8 != len(body) || frag&0x4000 != 0 || (frag&0x2000 != 0) != (j == 0) || !bytes.Equal(q[4:6], raw[4:6]) {
						t.Fatal("invalid IP checksum, identity, offset or flags")
					}
					body = append(body, q[20:]...)
				}
				if len(r.Packets[0]) != 20+split || !bytes.Equal(raw, before) || !bytes.Equal(body[8:], payload) || !bytes.Equal(body[:6], raw[20:26]) || finish(sum(raw[12:20])+17+uint32(len(body))+sum(body)) != 0 {
					t.Fatal("original/payload/UDP header or checksum changed")
				}
				e.Commit(r, len(raw))
			}
		})
	}
}

func TestUDPFragmentShapesBoundary(t *testing.T) {
	for _, split := range []int{8, 16, 24} {
		strategy := fmt.Sprintf("udp-fragment-%d", split)
		for _, size := range []int{28, 20 + split, 21 + split, 1500, 1501} {
			raw := packet(17, bytes.Repeat([]byte{0x5a}, size-28))
			want := size > 20+split && size <= 1500
			if got := len(transform(raw, strategy)) == 2; got != want {
				t.Fatalf("split%d size%d: modified%v want%v", split, size, got, want)
			}
		}
		for _, mutate := range []func([]byte){
			func(p []byte) { p[4], p[5] = 0, 0 },
			func(p []byte) { p[6], p[7] = 0x20, 0 },
			func(p []byte) { p[0] = 0x46 },
			func(p []byte) { p[24], p[25] = 0, 8 },
		} {
			raw := packet(17, bytes.Repeat([]byte{0x5a}, 40))
			mutate(raw)
			if got := transform(raw, strategy); got != nil {
				t.Fatalf("%s transformed unsupported packet", strategy)
			}
		}
	}
	for _, strategy := range []string{"udp-fragment-0", "udp-fragment-7", "udp-fragment-32", "udp-fragment-8-reverse"} {
		p := continuousUDPProfile()
		p.Strategy = strategy
		if _, err := compile(p); err == nil {
			t.Fatal("unknown fragment strategy accepted", strategy)
		}
	}
}
