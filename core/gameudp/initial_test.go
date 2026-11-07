package gameudp

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"testing"
)

func testHex(s string) []byte { v, _ := hex.DecodeString(s); return v }

// Independent HMAC expansion for the wire verifier, instead of the generator's
// crypto/hkdf helper. RFC 9001 A.1 fixes all three expected outputs.
func verifyInitialKeys(cid []byte) ([]byte, []byte, []byte) {
	m := hmac.New(sha256.New, testHex("38762cf7f55934b34d179ae6a4c80cadccbb7f0a"))
	m.Write(cid)
	initial := m.Sum(nil)
	expand := func(s []byte, label string, n int) []byte {
		l := []byte("tls13 " + label)
		info := []byte{0, byte(n), byte(len(l))}
		info = append(info, l...)
		info = append(info, 0, 1)
		h := hmac.New(sha256.New, s)
		h.Write(info)
		return h.Sum(nil)[:n]
	}
	c := expand(initial, "client in", 32)
	return expand(c, "quic key", 16), expand(c, "quic iv", 12), expand(c, "quic hp", 16)
}
func decodeInitial(p []byte) ([]byte, error) {
	if len(p) != 1250 || p[0]&0xf0 != 0xc0 || binary.BigEndian.Uint32(p[1:]) != 1 || p[5] != 8 || p[14] != 8 || p[23] != 0 || int(binary.BigEndian.Uint16(p[24:])&0x3fff) != len(p)-26 {
		return nil, errors.New("header")
	}
	k, iv, hp := verifyInitialKeys(p[6:14])
	h, _ := aes.NewCipher(hp)
	mask := make([]byte, 16)
	h.Encrypt(mask, p[30:46])
	first := p[0] ^ (mask[0] & 15)
	n := int(first&3) + 1
	header := append([]byte(nil), p[:26+n]...)
	header[0] = first
	var pn uint64
	for i := 0; i < n; i++ {
		header[26+i] ^= mask[i+1]
		pn = pn<<8 | uint64(header[26+i])
	}
	for i := 0; i < 8; i++ {
		iv[11-i] ^= byte(pn >> (8 * i))
	}
	b, _ := aes.NewCipher(k)
	a, _ := cipher.NewGCM(b)
	plain, err := a.Open(nil, iv, p[26+n:], header)
	if err != nil {
		return nil, err
	}
	if first&12 != 0 {
		return nil, errors.New("reserved")
	}
	return plain, nil
}
func TestInitialRFC9001Vector(t *testing.T) {
	cid := testHex("8394c8f03e515708")
	k, iv, hp, err := initialKeys(cid)
	a, b, c := verifyInitialKeys(cid)
	if err != nil || hex.EncodeToString(k) != "1f369613dd76d5467730efcbe3b1a22d" || hex.EncodeToString(iv) != "fa044b2f42a3fd3b46fb255c" || hex.EncodeToString(hp) != "9f50449e04a0e810283a1e9933adedd2" || !bytes.Equal(k, a) || !bytes.Equal(iv, b) || !bytes.Equal(hp, c) {
		t.Fatal("RFC vector mismatch", err)
	}
}
func TestInitialAuthenticatedClientHello(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 64; i++ {
		p, err := InitialPayload()
		if err != nil {
			t.Fatal(err)
		}
		plain, err := decodeInitial(p)
		if err != nil {
			t.Fatal(err)
		}
		n := int(binary.BigEndian.Uint16(plain[2:]) & 0x3fff)
		if plain[0] != 6 || plain[1] != 0 || n > 1000 || !bytes.Equal(plain[4+n:], make([]byte, len(plain)-4-n)) {
			t.Fatal("CRYPTO/PADDING")
		}
		hello := plain[4 : 4+n]
		called := false
		stop := errors.New("fixture stops before server flight")
		server := tls.QUICServer(&tls.QUICConfig{TLSConfig: &tls.Config{MinVersion: tls.VersionTLS13, NextProtos: []string{"h3"}, GetConfigForClient: func(h *tls.ClientHelloInfo) (*tls.Config, error) {
			called = h.ServerName == "www.google.com" && len(h.SupportedProtos) == 1 && h.SupportedProtos[0] == "h3"
			return nil, stop
		}}})
		server.SetTransportParameters(nil)
		if err = server.Start(context.Background()); err != nil {
			t.Fatal(err)
		}
		err = server.HandleData(tls.QUICEncryptionLevelInitial, hello)
		server.Close()
		if !called || err == nil {
			t.Fatal("independent TLS parser did not accept ClientHello", err)
		}
		cid := string(p[6:14])
		if seen[cid] {
			t.Fatal("reused CID")
		}
		seen[cid] = true
		p[len(p)-1] ^= 1
		if _, err = decodeInitial(p); err == nil {
			t.Fatal("corruption accepted")
		}
	}
}
