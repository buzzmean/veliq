package enrollment

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"strings"
	"testing"
)

func TestCodeEntropyShapeHashAndSafeErrors(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 1000; i++ {
		code, e := NewCode()
		if e != nil || len(code) != 32 || seen[code] {
			t.Fatal("random code format/collision")
		}
		seen[code] = true
		h, e := CodeHash(code)
		if e != nil || len(h) != 32 {
			t.Fatal("hash")
		}
		h2, _ := CodeHash(strings.ToLower(code))
		if hex.EncodeToString(h) != hex.EncodeToString(h2) {
			t.Fatal("canonicalization")
		}
	}
	secret := "VQ-secret"
	_, e := CodeHash(secret)
	if e == nil || strings.Contains(e.Error(), secret) {
		t.Fatal("code leaked")
	}
}
func TestHardwareV2StableSaltedAndNoMachineGuid(t *testing.T) {
	h := Hardware{"00112233-4455-6677-8899-aabbccddeeff", "BOARD123", "02-11-22-33-44-55"}
	salt := make([]byte, 32)
	a, e := HardwareHash(h, salt)
	if e != nil || len(a) != 64 {
		t.Fatal(a, e)
	}
	h.UUID = strings.ToUpper(h.UUID)
	h.MAC = "02:11:22:33:44:55"
	b, _ := HardwareHash(h, salt)
	if a != b {
		t.Fatal("normalization")
	}
	salt[0] = 1
	b, _ = HardwareHash(h, salt)
	if a == b {
		t.Fatal("salt ignored")
	}
	h.UUID = strings.Repeat("0", 32)
	h.BoardSerial = "Default string"
	if _, e = HardwareHash(h, salt); e == nil {
		t.Fatal("empty hardware accepted")
	}
}
func TestCSRReusesFreshValidationAndKeyNeverInWire(t *testing.T) {
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	id := strings.Repeat("a", 32)
	q, e := NewRequest(id, strings.Repeat("b", 64), key)
	if e != nil || !strings.Contains(q.CSR, "BEGIN CERTIFICATE REQUEST") {
		t.Fatal(e)
	}
	if strings.Contains(q.CSR, "PRIVATE KEY") {
		t.Fatal("private key escaped")
	}
}
