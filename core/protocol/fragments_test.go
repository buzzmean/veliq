package protocol

import (
	"bytes"
	"testing"
	"time"
)

func TestLargeUDPReordersWithoutChangingSmallWire(t *testing.T) {
	now := time.Now()
	for _, n := range []int{0, 64, 1100, 1200, 1350, 1472} {
		p := bytes.Repeat([]byte{byte(n)}, n)
		frames, e := EncodeDatagrams(5, 7, p)
		if e != nil {
			t.Fatal(e)
		}
		var r Reassembly
		var got []byte
		for i := len(frames) - 1; i >= 0; i-- {
			id, b, e := r.Decode(frames[i], now)
			if e != nil || id != 5 {
				t.Fatal(id, e)
			}
			if b != nil {
				got = b
			}
		}
		if !bytes.Equal(got, p) {
			t.Fatalf("size %d lost", n)
		}
		if n <= 1100 {
			old, _ := Encode(5, p)
			if len(frames) != 1 || !bytes.Equal(old, frames[0]) {
				t.Fatal("small wire changed")
			}
		}
	}
}
func TestFragmentLimitsExpiryAndNoPartialDelivery(t *testing.T) {
	now := time.Now()
	payload := bytes.Repeat([]byte{9}, 1200)
	frames, _ := EncodeDatagrams(1, 1, payload)
	var r Reassembly
	if _, b, e := r.Decode(frames[0], now); e != nil || b != nil {
		t.Fatal("partial delivered")
	}
	if _, b, e := r.Decode(frames[1], now.Add(3*time.Second)); e != nil || b != nil {
		t.Fatal("expired packet delivered")
	}
	var bounded Reassembly
	for i := uint32(1); i <= 64; i++ {
		f, _ := EncodeDatagrams(1, i, payload)
		if _, _, e := bounded.Decode(f[0], now); e != nil {
			t.Fatal(e)
		}
	}
	f, _ := EncodeDatagrams(1, 65, payload)
	if _, _, e := bounded.Decode(f[0], now); e == nil {
		t.Fatal("unbounded")
	}
	if _, _, e := bounded.Decode(f[0], now.Add(3*time.Second)); e != nil {
		t.Fatal("expired state retained")
	}
	if _, e := EncodeDatagrams(1, 1, make([]byte, 1473)); e == nil {
		t.Fatal("oversize accepted")
	}
	bad := append([]byte(nil), frames[0]...)
	bad[12] = 1
	if _, _, e := r.Decode(bad, now); e == nil {
		t.Fatal("noncanonical fragment")
	}
}
