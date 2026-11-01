package localstrategy

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"testing"
)

func TestQUICProbeRFC9001InitialKeys(t *testing.T) {
	dcid, _ := hex.DecodeString("8394c8f03e515708")
	key, iv, hp, err := quicInitialKeys(dcid)
	if err != nil || hex.EncodeToString(key) != "1f369613dd76d5467730efcbe3b1a22d" || hex.EncodeToString(iv) != "fa044b2f42a3fd3b46fb255c" || hex.EncodeToString(hp) != "9f50449e04a0e810283a1e9933adedd2" {
		t.Fatal("RFC9001 A.1 known-answer mismatch")
	}
}

func quicProbeInput() []byte {
	p := make([]byte, 1200)
	p[0] = 0xc0
	p[4] = 1
	p[5] = 8
	copy(p[6:14], []byte("real-dci"))
	p[14] = 8
	copy(p[15:23], []byte("real-sci"))
	binary.BigEndian.PutUint16(p[24:26], 0x4000|uint16(len(p)-26))
	copy(p[30:], []byte("opaque-client-data-must-not-enter-decoy"))
	return packet(17, p)
}

func TestQUICProbeOwnInitialAndOriginalByteIdentity(t *testing.T) {
	original := quicProbeInput()
	saved := bytes.Clone(original)
	for _, repeats := range []uint8{1, 6, 11, 16} {
		plan, err := QUICInitialPlan(original, repeats)
		if err != nil || len(plan) != int(repeats)+1 {
			t.Fatal(err, len(plan))
		}
		if !bytes.Equal(plan[len(plan)-1], saved) || !bytes.Equal(original, saved) {
			t.Fatal("original mutated")
		}
		for i, p := range plan[:len(plan)-1] {
			if finish(sum(p[:20])) != 0 || finish(sum(p[12:20])+17+uint32(len(p)-20)+sum(p[20:])) != 0 {
				t.Fatal("invalid IPv4/UDP checksum")
			}
			if len(p) != 1228 || !bytes.Equal(p[12:24], original[12:24]) || bytes.Contains(p, []byte("opaque-client-data")) || !bytes.Equal(p, plan[0]) {
				t.Fatal("decoy bounds/tuple/model", i)
			}
		}
		p := bytes.Clone(plan[0][28:])
		dcid, scid := p[6:14], p[15:23]
		if bytes.Equal(dcid, original[34:42]) || bytes.Equal(scid, original[43:51]) || bytes.Equal(dcid, scid) {
			t.Fatal("CID reuse")
		}
		// Check both QUIC protection and a real TLS parser on the generated model.
		key, iv, hp, err := quicInitialKeys(dcid)
		if err != nil {
			t.Fatal(err)
		}
		hpb, _ := aes.NewCipher(hp)
		var mask [16]byte
		hpb.Encrypt(mask[:], p[30:46])
		p[0] ^= mask[0] & 15
		for j := 0; j < 4; j++ {
			p[26+j] ^= mask[j+1]
		}
		if p[0] != 0xc3 || binary.BigEndian.Uint32(p[26:30]) != 0 {
			t.Fatal("header/PN")
		}
		block, _ := aes.NewCipher(key)
		aead, _ := cipher.NewGCM(block)
		plain, err := aead.Open(nil, iv, p[30:], p[:30])
		if err != nil {
			t.Fatal("Initial AEAD", err)
		}
		n := int(binary.BigEndian.Uint16(plain[2:4]) & 0x3fff)
		if plain[0] != 6 || plain[1] != 0 || n > len(plain)-4 {
			t.Fatal("CRYPTO frame")
		}
		for _, v := range plain[4+n:] {
			if v != 0 {
				t.Fatal("nonpadding trailing frame")
			}
		}
		var observed bool
		server := tls.QUICServer(&tls.QUICConfig{TLSConfig: &tls.Config{MinVersion: tls.VersionTLS13, NextProtos: []string{"h3"}, GetConfigForClient: func(info *tls.ClientHelloInfo) (*tls.Config, error) {
			observed = info.ServerName == "www.google.com" && len(info.SupportedProtos) == 1 && info.SupportedProtos[0] == "h3"
			return nil, errors.New("fixture stops before any server handshake")
		}}})
		server.SetTransportParameters(nil)
		if err = server.Start(context.Background()); err != nil {
			t.Fatal(err)
		}
		_ = server.HandleData(tls.QUICEncryptionLevelInitial, plain[4:4+n])
		server.Close()
		if !observed {
			t.Fatal("own TLS ClientHello not parsed")
		}
		plan[0][28] = 0
		if plan[1][28] == 0 && repeats > 1 || !bytes.Equal(original, saved) {
			t.Fatal("aliased packet storage")
		}
	}
}

func TestQUICProbeRejectsUnsupportedAndEntropyFailure(t *testing.T) {
	for _, mutate := range []func([]byte) []byte{
		func(p []byte) []byte { return p[:20] },
		func(p []byte) []byte { p[0] = 0x46; return p },
		func(p []byte) []byte { p[6] |= 0x20; return p },
		func(p []byte) []byte { p[23] = 53; return p },
		func(p []byte) []byte { p[32] = 2; return p },
		func(p []byte) []byte { p[28] = 0x40; return p },
		func(p []byte) []byte { p[33] = 255; return p },
		func(p []byte) []byte { p[52] = 0xff; return p },
	} {
		if out, err := QUICInitialPlan(mutate(quicProbeInput()), 6); err == nil || out != nil {
			t.Fatal("unsupported input produced plan")
		}
	}
	for _, n := range []uint8{0, 17, 255} {
		if _, err := QUICInitialPlan(quicProbeInput(), n); err == nil {
			t.Fatal("unbounded repeats")
		}
	}
	for _, entropy := range [][]byte{nil, make([]byte, 10000), append([]byte("real-dci"), []byte("othercid")...)} {
		if out, err := quicInitialPlan(quicProbeInput(), 6, bytes.NewReader(entropy)); err == nil || out != nil {
			t.Fatal("entropy/collision failure ignored")
		}
	}
}

func FuzzQUICProbeInitialPlan(f *testing.F) {
	f.Add(quicProbeInput())
	f.Add([]byte{0x45})
	f.Fuzz(func(t *testing.T, p []byte) {
		if len(p) > 1600 {
			return
		}
		plan, err := QUICInitialPlan(p, 1)
		if err == nil && (len(plan) != 2 || len(plan[0]) != 1228 || !bytes.Equal(plan[1], p)) {
			t.Fatal("plan escaped byte/packet bounds")
		}
	})
}
