package gameudp

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"errors"
)

// InitialPayload creates an independent QUIC v1 client Initial in memory.
// It opens no connection, reads no application traffic and imports no templates.
// Initial protection follows RFC 9001 sections 5.2-5.4. These public derivation
// keys are unrelated to VELIQ credentials or the game's encrypted session.
func InitialPayload() ([]byte, error) {
	ids := make([]byte, 16)
	if _, err := rand.Read(ids); err != nil {
		return nil, errors.New("GAME_INITIAL_RANDOM_UNAVAILABLE")
	}
	q := tls.QUICClient(&tls.QUICConfig{TLSConfig: &tls.Config{
		MinVersion: tls.VersionTLS13, ServerName: "www.google.com",
		NextProtos: []string{"h3"}, CurvePreferences: []tls.CurveID{tls.X25519},
	}})
	defer q.Close()
	params := append([]byte{15, 8}, ids[8:]...)
	params = append(params, 3, 2, 0x44, 0xe2, 14, 1, 2)
	q.SetTransportParameters(params)
	if err := q.Start(context.Background()); err != nil {
		return nil, errors.New("GAME_INITIAL_TLS_UNAVAILABLE")
	}
	var hello []byte
	for {
		ev := q.NextEvent()
		if ev.Kind == tls.QUICNoEvent {
			break
		}
		if ev.Kind == tls.QUICWriteData && ev.Level == tls.QUICEncryptionLevelInitial {
			hello = append(hello, ev.Data...)
		}
	}
	if len(hello) == 0 || len(hello) > 1000 {
		return nil, errors.New("GAME_INITIAL_HELLO_BOUND")
	}
	header := []byte{0xc3, 0, 0, 0, 1, 8}
	header = append(header, ids[:8]...)
	header = append(header, 8)
	header = append(header, ids[8:]...)
	header = append(header, 0, 0x44, 0xc8, 0, 0, 0, 0)
	plain := make([]byte, 1250-len(header)-16)
	plain[0] = 6 // CRYPTO, offset zero, then PADDING to 1250 bytes.
	binary.BigEndian.PutUint16(plain[2:4], uint16(len(hello))|0x4000)
	copy(plain[4:], hello)
	key, iv, hp, err := initialKeys(ids[:8])
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
	packet := aead.Seal(header, iv, plain, header) // Packet number zero.
	h, err := aes.NewCipher(hp)
	if err != nil {
		return nil, err
	}
	mask := make([]byte, 16)
	h.Encrypt(mask, packet[30:46])
	packet[0] ^= mask[0] & 15
	for i := 0; i < 4; i++ {
		packet[26+i] ^= mask[i+1]
	}
	return packet, nil
}

func initialLabel(secret []byte, name string, n int) ([]byte, error) {
	label := []byte("tls13 " + name)
	info := []byte{byte(n >> 8), byte(n), byte(len(label))}
	info = append(info, label...)
	info = append(info, 0)
	return hkdf.Expand(sha256.New, secret, string(info), n)
}
func initialKeys(cid []byte) (key, iv, hp []byte, err error) {
	salt := []byte{0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a}
	secret, err := hkdf.Extract(sha256.New, cid, salt)
	if err != nil {
		return nil, nil, nil, err
	}
	client, err := initialLabel(secret, "client in", 32)
	if err != nil {
		return nil, nil, nil, err
	}
	key, err = initialLabel(client, "quic key", 16)
	if err == nil {
		iv, err = initialLabel(client, "quic iv", 12)
	}
	if err == nil {
		hp, err = initialLabel(client, "quic hp", 16)
	}
	return
}
