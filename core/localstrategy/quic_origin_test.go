package localstrategy

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/tls"
	"encoding/binary"
	"testing"
	"time"
)

var originDCID = []byte("origin-d")
var originSCID = []byte("origin-s")

func originHello(t testing.TB) []byte {
	t.Helper()
	q := tls.QUICClient(&tls.QUICConfig{TLSConfig: &tls.Config{ServerName: "www.youtube.com", NextProtos: []string{"h3"}, MinVersion: tls.VersionTLS13, CurvePreferences: []tls.CurveID{tls.X25519}}})
	defer q.Close()
	q.SetTransportParameters(append([]byte{15, 8}, originSCID...))
	if err := q.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	var hello []byte
	for e := q.NextEvent(); e.Kind != tls.QUICNoEvent; e = q.NextEvent() {
		if e.Kind == tls.QUICWriteData && e.Level == tls.QUICEncryptionLevelInitial {
			hello = append(hello, e.Data...)
		}
	}
	if len(hello) == 0 {
		t.Fatal("missing own ClientHello")
	}
	return hello
}
func originCrypto(offset int, data []byte) []byte {
	p := binary.BigEndian.AppendUint16([]byte{6}, 0x4000|uint16(offset))
	p = binary.BigEndian.AppendUint16(p, 0x4000|uint16(len(data)))
	return append(p, data...)
}
func originSeal(t testing.TB, dcid, scid, frames []byte, pn uint32, size int) []byte {
	t.Helper()
	h := append([]byte{0xc3, 0, 0, 0, 1, byte(len(dcid))}, dcid...)
	h = append(h, byte(len(scid)))
	h = append(h, scid...)
	h = append(h, 0)
	h = binary.BigEndian.AppendUint16(h, 0x4000|uint16(size-len(h)-2))
	at := len(h)
	h = binary.BigEndian.AppendUint32(h, pn)
	plain := make([]byte, size-len(h)-16)
	if len(frames) > len(plain) {
		t.Fatal("fixture size")
	}
	copy(plain, frames)
	key, iv, hp, err := quicInitialKeys(dcid)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 4; i++ {
		iv[len(iv)-1-i] ^= byte(pn >> uint(8*i))
	}
	b, _ := aes.NewCipher(key)
	a, _ := cipher.NewGCM(b)
	p := a.Seal(h, iv, plain, h)
	b, _ = aes.NewCipher(hp)
	var mask [16]byte
	b.Encrypt(mask[:], p[at+4:at+20])
	p[0] ^= mask[0] & 15
	for i := 0; i < 4; i++ {
		p[at+i] ^= mask[i+1]
	}
	return p
}
func originAddExtension(hello []byte, kind uint16, value []byte) []byte {
	p := bytes.Clone(hello)
	at := 39 + int(p[38])
	at += 2 + int(binary.BigEndian.Uint16(p[at:]))
	at += 1 + int(p[at])
	n := int(binary.BigEndian.Uint16(p[at:]))
	binary.BigEndian.PutUint16(p[at:], uint16(n+4+len(value)))
	p = binary.BigEndian.AppendUint16(p, kind)
	p = binary.BigEndian.AppendUint16(p, uint16(len(value)))
	p = append(p, value...)
	n = len(p) - 4
	p[1], p[2], p[3] = byte(n>>16), byte(n>>8), byte(n)
	return p
}
func TestQUICOriginReassemblyAndImmutableInput(t *testing.T) {
	hello := originHello(t)
	now := time.Now()
	cut := len(hello) / 2
	for _, ordered := range []bool{true, false} {
		var o QUICOriginObserver
		parts := [][]byte{originCrypto(0, hello[:cut]), originCrypto(cut, hello[cut:])}
		if !ordered {
			parts[0], parts[1] = parts[1], parts[0]
		}
		for i, frame := range parts {
			p := originSeal(t, originDCID, originSCID, frame, uint32(i), 1200)
			saved := bytes.Clone(p)
			r := o.Observe(p, now)
			if !bytes.Equal(p, saved) {
				t.Fatal("mutated input")
			}
			if i == 0 && (r.Complete || r.Domain != "") {
				t.Fatal("partial hello published", r)
			}
			if i == 1 && (!r.Complete || r.Domain != "www.youtube.com" || r.Reason != "QUIC_ORIGIN_VISIBLE_SNI" || r.Datagrams != 2) {
				t.Fatal(r)
			}
		}
		if o.data != nil || o.present != nil || o.dcid != nil {
			t.Fatal("completed hello retained")
		}
	}
}
func TestQUICOriginRefusesAmbiguousOrUnprotectedMetadata(t *testing.T) {
	hello := originHello(t)
	valid := originSeal(t, originDCID, originSCID, originCrypto(0, hello), 0, 1200)
	cases := []struct {
		name, reason string
		packet       []byte
	}{
		{"bad-tag", "QUIC_ORIGIN_PROTECTION_FAILED", append(bytes.Clone(valid[:1199]), valid[1199]^1)},
		{"short-header", "QUIC_ORIGIN_HEADER_UNSUPPORTED", append([]byte{0x40}, valid[1:]...)},
		{"v2", "QUIC_ORIGIN_VERSION_UNSUPPORTED", func() []byte { p := bytes.Clone(valid); binary.BigEndian.PutUint32(p[1:5], 0x6b3343cf); return p }()},
		{"retry", "QUIC_ORIGIN_PACKET_TYPE_UNSUPPORTED", append([]byte{0xf0}, valid[1:]...)},
		{"token", "QUIC_ORIGIN_TOKEN_UNSUPPORTED", func() []byte { p := bytes.Clone(valid); p[23] = 1; return p }()},
		{"late-pn", "QUIC_ORIGIN_PACKET_NUMBER_UNSUPPORTED", originSeal(t, originDCID, originSCID, originCrypto(0, hello), 1, 1200)},
		{"ech", "QUIC_ORIGIN_ECH", originSeal(t, originDCID, originSCID, originCrypto(0, originAddExtension(hello, 0xfe0d, []byte{0, 0, 0})), 0, 1200)},
		{"early-data", "QUIC_ORIGIN_RESUMPTION_UNSUPPORTED", originSeal(t, originDCID, originSCID, originCrypto(0, originAddExtension(hello, 42, nil)), 0, 1200)},
		{"psk", "QUIC_ORIGIN_RESUMPTION_UNSUPPORTED", originSeal(t, originDCID, originSCID, originCrypto(0, originAddExtension(hello, 41, []byte{0})), 0, 1200)},
		{"duplicate-alpn", "QUIC_ORIGIN_HELLO_INVALID", originSeal(t, originDCID, originSCID, originCrypto(0, originAddExtension(hello, 16, []byte{0, 3, 2, 'h', '3'})), 0, 1200)},
		{"unknown-frame", "QUIC_ORIGIN_FRAME_UNSUPPORTED", originSeal(t, originDCID, originSCID, []byte{0x08}, 0, 1200)},
		{"transport-cid", "QUIC_ORIGIN_CID_CHANGED", originSeal(t, originDCID, []byte("other-id"), originCrypto(0, hello), 0, 1200)},
		{"crypto-bound", "QUIC_ORIGIN_CRYPTO_LIMIT", originSeal(t, originDCID, originSCID, originCrypto(QUICOriginMaxHello, []byte{1}), 0, 1200)},
		{"extra-handshake", "QUIC_ORIGIN_EXTRA_CRYPTO", originSeal(t, originDCID, originSCID, originCrypto(0, append(bytes.Clone(hello), 0)), 0, 1200)},
	}
	// A complete first Initial must not hide a coalesced 0-RTT packet.
	first := originSeal(t, originDCID, originSCID, originCrypto(0, hello), 0, 600)
	cases = append(cases, struct {
		name, reason string
		packet       []byte
	}{"coalesced-0rtt", "QUIC_ORIGIN_PACKET_TYPE_UNSUPPORTED", append(first, append([]byte{0xd0, 0, 0, 0, 1}, make([]byte, 595)...)...)})
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var o QUICOriginObserver
			r := o.Observe(tc.packet, time.Now())
			if r.Domain != "" || !r.Complete || r.Reason != tc.reason {
				t.Fatal(r)
			}
			if o.data != nil || o.present != nil {
				t.Fatal("rejected hello retained")
			}
			if got := o.Observe(valid, time.Now()); got != r {
				t.Fatal("terminal failure resurrected")
			}
		})
	}
}
func TestQUICOriginBoundsConflictsAndFlightIdentity(t *testing.T) {
	hello := originHello(t)
	now := time.Now()
	first := originSeal(t, originDCID, originSCID, originCrypto(0, hello[:20]), 0, 1200)
	for _, mode := range []string{"timeout", "capacity", "overlap", "dcid", "scid"} {
		t.Run(mode, func(t *testing.T) {
			var o QUICOriginObserver
			o.Observe(first, now)
			var r QUICOriginObservation
			switch mode {
			case "timeout":
				r = o.Observe(first, now.Add(QUICOriginDeadline))
			case "capacity":
				for i := 0; i < QUICOriginMaxDatagrams; i++ {
					r = o.Observe(first, now)
				}
			case "overlap":
				r = o.Observe(originSeal(t, originDCID, originSCID, originCrypto(0, []byte{2}), 1, 1200), now)
			case "dcid":
				r = o.Observe(originSeal(t, []byte("other-id"), originSCID, originCrypto(20, hello[20:]), 1, 1200), now)
			case "scid":
				r = o.Observe(originSeal(t, originDCID, []byte("other-id"), originCrypto(20, hello[20:]), 1, 1200), now)
			}
			if !r.Complete || r.Domain != "" || o.data != nil {
				t.Fatal("invalid flight published/retained", r)
			}
		})
	}
}
func FuzzQUICOriginInitial(f *testing.F) {
	hello := originHello(f)
	f.Add(originSeal(f, originDCID, originSCID, originCrypto(0, hello), 0, 1200))
	f.Add([]byte{0xc0})
	f.Fuzz(func(t *testing.T, p []byte) {
		if len(p) > 1600 {
			return
		}
		saved := bytes.Clone(p)
		var o QUICOriginObserver
		r := o.Observe(p, time.Unix(1, 0))
		if !bytes.Equal(p, saved) {
			t.Fatal("input mutation")
		}
		if r.Domain != "" && (!r.Complete || r.Reason != "QUIC_ORIGIN_VISIBLE_SNI") {
			t.Fatal(r)
		}
		o.Finish("end")
		if o.data != nil {
			t.Fatal("retained")
		}
	})
}
func FuzzQUICOriginHello(f *testing.F) {
	f.Add(originHello(f))
	f.Add([]byte{1})
	f.Fuzz(func(t *testing.T, p []byte) {
		if len(p) > QUICOriginMaxHello {
			return
		}
		_, _ = quicOriginHello(p, originSCID)
	})
}
