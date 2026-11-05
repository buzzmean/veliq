package security

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type Ticket struct {
	ID        string    `json:"id"`
	DeviceID  string    `json:"device_id"`
	DeviceKey string    `json:"device_key"`
	RelayID   string    `json:"relay_id"`
	IssuedAt  time.Time `json:"issued_at"`
	ExpiresAt time.Time `json:"expires_at"`
}

// TicketVerifier locks are split by purpose: mu guards keys and the revocation set
// (read on every relay flow, never held across I/O); useMu guards the one-shot
// replay cache and its durable copy, whose fsync must not stall revocation checks.
type TicketVerifier struct {
	mu       sync.RWMutex
	Keys     map[string]ed25519.PublicKey
	Audience string
	revoked  map[string]bool
	useMu    sync.Mutex
	used     map[string]time.Time
	owner    map[string]string
	Limit    int
	// DeviceLimit bounds live one-shot tickets per device so one noisy or broken
	// client cannot exhaust the shared cache. Zero disables the per-device bound.
	DeviceLimit int
	path        string
}

func NewTicketVerifier(keys map[string]ed25519.PublicKey, audience string) *TicketVerifier {
	return &TicketVerifier{Keys: copyKeys(keys), Audience: audience, used: make(map[string]time.Time), owner: make(map[string]string), revoked: make(map[string]bool), Limit: 10000}
}
func copyKeys(keys map[string]ed25519.PublicKey) map[string]ed25519.PublicKey {
	out := make(map[string]ed25519.PublicKey, len(keys))
	for id, k := range keys {
		out[id] = append(ed25519.PublicKey(nil), k...)
	}
	return out
}
func (v *TicketVerifier) Update(keys map[string]ed25519.PublicKey, revoked []string) {
	next := make(map[string]bool, len(revoked))
	for _, id := range revoked {
		next[id] = true
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	v.Keys = copyKeys(keys)
	v.revoked = next
}
func (v *TicketVerifier) Revoked(id string) bool {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return v.revoked[id]
}
func (v *TicketVerifier) Accept(raw []byte, peer ed25519.PublicKey, now time.Time) (Ticket, error) {
	return v.AcceptForDevice(raw, peer, "", now)
}

// AcceptForDevice validates the session binding before consuming the one-shot ticket.
func (v *TicketVerifier) AcceptForDevice(raw []byte, peer ed25519.PublicKey, device string, now time.Time) (Ticket, error) {
	v.mu.RLock()
	keys := v.Keys // replaced wholesale by Update, never mutated in place
	v.mu.RUnlock()
	var t Ticket
	if e := Verify("ticket", keys, raw, &t); e != nil {
		return t, e
	}
	if (device != "" && t.DeviceID != device) || t.ID == "" || len(t.ID) > 128 || t.DeviceID == "" || t.RelayID != v.Audience || t.DeviceKey != Fingerprint(peer) || !t.ExpiresAt.After(now) || t.IssuedAt.After(now.Add(30*time.Second)) || t.ExpiresAt.Sub(t.IssuedAt) > 5*time.Minute || !t.ExpiresAt.After(t.IssuedAt) || v.Revoked(t.DeviceID) {
		return t, errors.New("invalid, revoked or expired relay ticket")
	}
	v.useMu.Lock()
	defer v.useMu.Unlock()
	perDevice := 0
	for id, exp := range v.used {
		if !exp.After(now) {
			delete(v.used, id)
			delete(v.owner, id)
		} else if v.owner[id] == t.DeviceID {
			perDevice++
		}
	}
	if _, ok := v.used[t.ID]; ok {
		return t, errors.New("relay ticket replay")
	}
	if len(v.used) >= v.Limit {
		return t, errors.New("replay cache capacity")
	}
	if v.DeviceLimit > 0 && perDevice >= v.DeviceLimit {
		return t, errors.New("replay cache device quota")
	}
	v.used[t.ID] = t.ExpiresAt
	v.owner[t.ID] = t.DeviceID
	if e := v.persist(); e != nil {
		delete(v.used, t.ID)
		delete(v.owner, t.ID)
		return t, e
	}
	return t, nil
}

// RenewalAudience is the Proof.RelayID value reserved for client certificate renewal.
const RenewalAudience = "certificate-renewal"

// SubscriptionAudience is the Proof.RelayID value reserved for subscription status checks.
const SubscriptionAudience = "subscription-status"

type Proof struct {
	DeviceID  string    `json:"device_id"`
	RelayID   string    `json:"relay_id"`
	Nonce     string    `json:"nonce"`
	IssuedAt  time.Time `json:"issued_at"`
	Signature string    `json:"signature"`
}

func (p Proof) message() []byte {
	return []byte("neexitlag:device-proof:v1\x00" + p.DeviceID + "\n" + p.RelayID + "\n" + p.Nonce + "\n" + p.IssuedAt.UTC().Format(time.RFC3339Nano))
}
func NewProof(id, relay string, key ed25519.PrivateKey, now time.Time) (Proof, error) {
	nonce, e := NewID()
	if e != nil {
		return Proof{}, e
	}
	p := Proof{DeviceID: id, RelayID: relay, Nonce: nonce, IssuedAt: now.UTC()}
	p.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(key, p.message()))
	return p, nil
}
func (p Proof) Verify(key ed25519.PublicKey, now time.Time) error {
	sig, e := base64.RawURLEncoding.DecodeString(p.Signature)
	if e != nil || len(p.DeviceID) > 128 || len(p.RelayID) > 128 || len(p.Nonce) != 32 || now.Sub(p.IssuedAt) > time.Minute || p.IssuedAt.After(now.Add(10*time.Second)) || !ed25519.Verify(key, p.message(), sig) {
		return errors.New("invalid device proof")
	}
	return nil
}

func NewPersistentTicketVerifier(keys map[string]ed25519.PublicKey, audience, path string) (*TicketVerifier, error) {
	v := NewTicketVerifier(keys, audience)
	v.path = path
	v.Limit = 2048
	v.DeviceLimit = 64
	raw, e := os.ReadFile(path)
	if os.IsNotExist(e) {
		return v, nil
	}
	if e != nil {
		return nil, e
	}
	if e = Parse(raw, &v.used); e != nil {
		return nil, e
	}
	if v.used == nil || len(v.used) > v.Limit {
		return nil, errors.New("replay store capacity")
	}
	return v, nil
}
func (v *TicketVerifier) persist() error {
	if v.path == "" {
		return nil
	}
	if e := os.MkdirAll(filepath.Dir(v.path), 0700); e != nil {
		return e
	}
	raw, e := json.Marshal(v.used)
	if e != nil {
		return e
	}
	f, e := os.CreateTemp(filepath.Dir(v.path), ".replay-*")
	if e != nil {
		return e
	}
	name := f.Name()
	defer os.Remove(name)
	f.Chmod(0600)
	_, e = f.Write(raw)
	if e == nil {
		e = f.Sync()
	}
	f.Close()
	if e != nil {
		return e
	}
	return os.Rename(name, v.path)
}
