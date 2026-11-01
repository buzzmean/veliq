package localstrategy

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"io"
)

const QUICProbeMaxRepeats = 16
const QUICProbeInitialBytes = 1200

// QUICInitialPlan is an offline packet plan for an explicitly scoped probe.
// It is NOT a strategy registered with LocalStrategyEngine or browser AUTO.
// Only the original's public long-header CIDs are inspected, never decrypted.
// A sender must enforce process/tuple/policy scope and a one-flight budget.
func QUICInitialPlan(original []byte, repeats uint8) ([][]byte, error) {
	return quicInitialPlan(original, repeats, rand.Reader)
}

func quicInitialPlan(original []byte, repeats uint8, random io.Reader) ([][]byte, error) {
	payload, ok := packetPayload(original, "udp")
	if !ok || len(original) > 1500 || binary.BigEndian.Uint16(original[22:24]) != 443 || repeats < 1 || repeats > QUICProbeMaxRepeats || !validQUICInitial(payload) {
		return nil, errors.New("QUIC_PROBE_INITIAL_UNSUPPORTED")
	}
	n := int(payload[5])
	dcid, scid := payload[6:6+n], payload[7+n:7+n+int(payload[6+n])]
	ids := make([]byte, 16)
	if _, err := io.ReadFull(random, ids); err != nil {
		return nil, errors.New("QUIC_PROBE_RANDOM_UNAVAILABLE")
	}
	// Never mix a decoy handshake into either direction of the real connection.
	if bytes.Equal(ids[:8], ids[8:]) || bytes.Equal(ids[:8], dcid) || bytes.Equal(ids[:8], scid) || bytes.Equal(ids[8:], dcid) || bytes.Equal(ids[8:], scid) {
		return nil, errors.New("QUIC_PROBE_CID_COLLISION")
	}
	fake, err := ownQUICInitial(ids[:8], ids[8:], random)
	if err != nil {
		return nil, err
	}
	out := make([][]byte, 0, int(repeats)+1)
	for i := uint8(0); i < repeats; i++ {
		p := make([]byte, 28+len(fake))
		copy(p, original[:28])
		copy(p[28:], fake)
		binary.BigEndian.PutUint16(p[2:4], uint16(len(p)))
		binary.BigEndian.PutUint16(p[24:26], uint16(len(fake)+8))
		checksumTransport(p)
		out = append(out, p)
	}
	return append(out, bytes.Clone(original)), nil
}

// Generate our own TLS ClientHello and protect ONLY that decoy with the public
// QUIC v1 Initial derivation (RFC 9001). No user TLS data or upstream blob enters
// the model. The incomplete, independent handshake sends no application data.
func ownQUICInitial(dcid, scid []byte, random io.Reader) ([]byte, error) {
	q := tls.QUICClient(&tls.QUICConfig{TLSConfig: &tls.Config{
		MinVersion: tls.VersionTLS13, ServerName: "www.google.com", NextProtos: []string{"h3"},
		CurvePreferences: []tls.CurveID{tls.X25519}, Rand: random,
	}})
	defer q.Close()
	q.SetTransportParameters(append([]byte{0x0f, byte(len(scid))}, scid...))
	if err := q.Start(context.Background()); err != nil {
		return nil, errors.New("QUIC_PROBE_MODEL_FAILED")
	}
	var hello []byte
	for event := q.NextEvent(); event.Kind != tls.QUICNoEvent; event = q.NextEvent() {
		if event.Kind == tls.QUICWriteData && event.Level == tls.QUICEncryptionLevelInitial {
			hello = append(hello, event.Data...)
		}
	}
	if len(hello) == 0 || len(hello) > 1000 {
		return nil, errors.New("QUIC_PROBE_MODEL_LIMIT")
	}
	// PN length=4, token length=0; Length includes PN and GCM tag.
	header := append([]byte{0xc3, 0, 0, 0, 1, byte(len(dcid))}, dcid...)
	header = append(header, byte(len(scid)))
	header = append(header, scid...)
	header = append(header, 0)
	length := QUICProbeInitialBytes - len(header) - 2
	header = binary.BigEndian.AppendUint16(header, 0x4000|uint16(length))
	pnOffset := len(header)
	header = append(header, 0, 0, 0, 0)
	plain := make([]byte, QUICProbeInitialBytes-len(header)-16)
	plain[0], plain[1] = 6, 0 // CRYPTO frame, offset 0.
	binary.BigEndian.PutUint16(plain[2:4], 0x4000|uint16(len(hello)))
	copy(plain[4:], hello) // Remaining bytes are PADDING frames.
	key, iv, hp, err := quicInitialKeys(dcid)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	sealed := aead.Seal(header, iv, plain, header) // Packet number zero.
	hpBlock, err := aes.NewCipher(hp)
	if err != nil {
		return nil, err
	}
	var mask [16]byte
	hpBlock.Encrypt(mask[:], sealed[pnOffset+4:pnOffset+20])
	sealed[0] ^= mask[0] & 15
	for i := 0; i < 4; i++ {
		sealed[pnOffset+i] ^= mask[i+1]
	}
	return sealed, nil
}

func quicInitialKeys(dcid []byte) (key, iv, hp []byte, err error) {
	salt := []byte{0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a}
	initial, err := hkdf.Extract(sha256.New, dcid, salt)
	if err != nil {
		return nil, nil, nil, err
	}
	expand := func(secret []byte, label string, n uint16) ([]byte, error) {
		label = "tls13 " + label
		info := []byte{byte(n >> 8), byte(n), byte(len(label))}
		info = append(info, label...)
		info = append(info, 0)
		return hkdf.Expand(sha256.New, secret, string(info), int(n))
	}
	client, err := expand(initial, "client in", 32)
	if err != nil {
		return nil, nil, nil, err
	}
	key, err = expand(client, "quic key", 16)
	if err != nil {
		return nil, nil, nil, err
	}
	iv, err = expand(client, "quic iv", 12)
	if err != nil {
		return nil, nil, nil, err
	}
	hp, err = expand(client, "quic hp", 16)
	return
}
