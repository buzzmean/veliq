// Package security uses Ed25519 signatures with domain separation and bounded parsing.
package security

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

const MaxDocument = 65536

// Configs carry the complete revocation set. This bound is domain-specific:
// tickets, proofs, IPC and other documents retain their original 64 KiB limit.
const MaxConfigDocument = 1024 * 1024

func documentLimit(domain string) int {
	if domain == "config" {
		return MaxConfigDocument
	}
	return MaxDocument
}

var ErrSignature = errors.New("invalid signature or untrusted key")

type Envelope struct {
	KeyID     string          `json:"key_id"`
	Payload   json.RawMessage `json:"payload"`
	Signature string          `json:"signature"`
}

func Parse(b []byte, v any) error { return parseLimit(b, v, MaxDocument) }
func parseLimit(b []byte, v any, limit int) error {
	if len(b) > limit {
		return errors.New("document too large")
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if e := d.Decode(v); e != nil {
		return e
	}
	var extra any
	if e := d.Decode(&extra); e != io.EOF {
		return errors.New("trailing document")
	}
	return nil
}
func Fingerprint(pub ed25519.PublicKey) string {
	h := sha256.Sum256(pub)
	return hex.EncodeToString(h[:])
}
func Sign(domain, kid string, key ed25519.PrivateKey, value any) ([]byte, error) {
	if len(key) != ed25519.PrivateKeySize {
		return nil, errors.New("invalid signing key")
	}
	p, e := json.Marshal(value)
	if e != nil {
		return nil, e
	}
	sig := ed25519.Sign(key, append([]byte("neexitlag:"+domain+":v1\x00"), p...))
	b, e := json.Marshal(Envelope{kid, p, base64.RawURLEncoding.EncodeToString(sig)})
	if len(b) > documentLimit(domain) {
		return nil, errors.New("document too large")
	}
	return b, e
}
func Verify(domain string, keys map[string]ed25519.PublicKey, b []byte, value any) error {
	var env Envelope
	if e := parseLimit(b, &env, documentLimit(domain)); e != nil {
		return e
	}
	key := keys[env.KeyID]
	sig, e := base64.RawURLEncoding.DecodeString(env.Signature)
	if e != nil || len(key) != ed25519.PublicKeySize || !ed25519.Verify(key, append([]byte("neexitlag:"+domain+":v1\x00"), env.Payload...), sig) {
		return ErrSignature
	}
	return parseLimit(env.Payload, value, documentLimit(domain))
}

type Identity struct {
	ID   string `json:"id"`
	Seed string `json:"seed"`
}

func NewID() (string, error) {
	var b [16]byte
	if _, e := rand.Read(b[:]); e != nil {
		return "", e
	}
	return hex.EncodeToString(b[:]), nil
}
func LoadOrCreateIdentity(path string) (Identity, ed25519.PrivateKey, error) {
	b, e := os.ReadFile(path)
	if e == nil {
		var i Identity
		if e = Parse(b, &i); e != nil {
			return i, nil, e
		}
		seed, e := base64.RawURLEncoding.DecodeString(i.Seed)
		if e != nil || len(seed) != ed25519.SeedSize {
			return i, nil, errors.New("invalid device seed")
		}
		return i, ed25519.NewKeyFromSeed(seed), nil
	}
	if !os.IsNotExist(e) {
		return Identity{}, nil, e
	}
	_, key, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		return Identity{}, nil, e
	}
	id, e := NewID()
	if e != nil {
		return Identity{}, nil, e
	}
	i := Identity{id, base64.RawURLEncoding.EncodeToString(key.Seed())}
	b, _ = json.Marshal(i)
	if e = os.MkdirAll(filepath.Dir(path), 0700); e != nil {
		return Identity{}, nil, e
	}
	f, e := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if e != nil {
		return Identity{}, nil, e
	}
	_, e = f.Write(b)
	closeErr := f.Close()
	if e != nil {
		return Identity{}, nil, e
	}
	if closeErr != nil {
		return Identity{}, nil, closeErr
	}
	return i, key, nil
}
func DecodePublicKey(s string) (ed25519.PublicKey, error) {
	b, e := base64.RawURLEncoding.DecodeString(s)
	if e != nil || len(b) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("invalid Ed25519 public key")
	}
	return ed25519.PublicKey(b), nil
}
