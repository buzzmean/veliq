package protocol

import (
	"bytes"
	"fmt"
	"net/netip"
	"testing"
)

func TestRoundTrip(t *testing.T) {
	o := Open{UDP, 7, netip.MustParseAddrPort("127.0.0.1:9999")}
	var b bytes.Buffer
	if e := o.Write(&b); e != nil {
		t.Fatal(e)
	}
	got, e := ReadOpen(&b)
	if e != nil || got != o {
		t.Fatalf("%v %v", got, e)
	}
	f, e := Encode(7, []byte("hello"))
	if e != nil {
		t.Fatal(e)
	}
	id, p, e := Decode(f)
	if e != nil || id != 7 || string(p) != "hello" {
		t.Fatal(id, e)
	}
}
func TestReject(t *testing.T) {
	for _, b := range [][]byte{nil, {1}, {2, 0, 0, 0, 1}, {1, 0, 0, 0, 0}, make([]byte, MaxPayload+HeaderSize+1)} {
		if _, _, e := Decode(b); e == nil {
			t.Fatal("accepted malformed frame")
		}
	}
}
func FuzzDecode(f *testing.F) {
	f.Add([]byte{1, 0, 0, 0, 1, 42})
	f.Fuzz(func(t *testing.T, b []byte) {
		id, p, e := Decode(b)
		if e == nil {
			out, e := Encode(id, p)
			if e != nil || !bytes.Equal(out, b) {
				t.Fatal("roundtrip")
			}
		}
	})
}

func FuzzReadOpen(f *testing.F) {
	var b bytes.Buffer
	(Open{UDP, 1, netip.MustParseAddrPort("[::1]:1234")}).Write(&b)
	f.Add(b.Bytes())
	f.Fuzz(func(t *testing.T, b []byte) {
		o, e := ReadOpen(bytes.NewReader(b))
		if e == nil {
			var out bytes.Buffer
			if e = o.Write(&out); e != nil || !bytes.Equal(out.Bytes(), b[:OpenSize]) {
				t.Fatal("OPEN roundtrip")
			}
		}
	})
}
func BenchmarkFrame(b *testing.B) {
	for _, size := range []int{64, 512, 1100} {
		b.Run(fmt.Sprint(size), func(b *testing.B) {
			p := make([]byte, size)
			b.SetBytes(int64(size))
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				f, _ := Encode(1, p)
				Decode(f)
			}
		})
	}
}
