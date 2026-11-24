package security

import (
	"crypto/ed25519"
	"crypto/rand"
	"github.com/buzzmean/veliq/core/optimizer"
	"github.com/buzzmean/veliq/core/profiles"
	"path/filepath"
	"testing"
	"time"
)

func TestTicketDeviceBindingReplayExpiryAndRevoke(t *testing.T) {
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	device, _, _ := ed25519.GenerateKey(rand.Reader)
	now := time.Now()
	ticket := Ticket{"nonce", "device", Fingerprint(device), "FRA", now, now.Add(time.Minute)}
	raw, _ := Sign("ticket", "key", key, ticket)
	v := NewTicketVerifier(map[string]ed25519.PublicKey{"key": pub}, "FRA")
	if _, e := v.Accept(raw, device, now); e != nil {
		t.Fatal(e)
	}
	if _, e := v.Accept(raw, device, now); e == nil {
		t.Fatal("replay accepted")
	}
	v = NewTicketVerifier(map[string]ed25519.PublicKey{"key": pub}, "WAW")
	if _, e := v.Accept(raw, device, now); e == nil {
		t.Fatal("audience")
	}
	v.Audience = "FRA"
	if _, e := v.Accept(raw, pub, now); e == nil {
		t.Fatal("key binding")
	}
	if _, e := v.Accept(raw, device, now.Add(2*time.Minute)); e == nil {
		t.Fatal("expiry")
	}
	v.Update(map[string]ed25519.PublicKey{"key": pub}, []string{"device"})
	if _, e := v.Accept(raw, device, now); e == nil {
		t.Fatal("revoke")
	}
}
func TestConfigLKG(t *testing.T) {
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	keys := map[string]ed25519.PublicKey{"key": pub}
	now := time.Now()
	cfg := Config{Version: 2, GeneratedAt: now, ExpiresAt: now.Add(time.Hour), ApplicationProfiles: profiles.Defaults(), RoutingParameters: optimizer.DefaultParameters()}
	raw, _ := Sign("config", "key", key, cfg)
	cache := NewConfigCache(keys, filepath.Join(t.TempDir(), "config.json"))
	if e := cache.Apply(raw, now); e != nil {
		t.Fatal(e)
	}
	bad := append([]byte(nil), raw...)
	bad[len(bad)-2] = 'x'
	if cache.Apply(bad, now) == nil {
		t.Fatal("signature")
	}
	cfg.Version = 1
	older, _ := Sign("config", "key", key, cfg)
	if cache.Apply(older, now) == nil {
		t.Fatal("rollback")
	}
	if _, e := cache.Current(now); e != nil {
		t.Fatal("outage must retain LKG")
	}
	if _, e := cache.Current(now.Add(2 * time.Hour)); e == nil {
		t.Fatal("expired config")
	}
	loaded := NewConfigCache(keys, cache.Path)
	if e := loaded.Load(now); e != nil {
		t.Fatal(e)
	}
	if cache.Apply(raw, now.Add(2*time.Hour)) == nil {
		t.Fatal("expired signed config")
	}
}
func TestIdentityProofAndRotation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "device.json")
	id, key, e := LoadOrCreateIdentity(path)
	if e != nil {
		t.Fatal(e)
	}
	loaded, k, e := LoadOrCreateIdentity(path)
	if e != nil || loaded.ID != id.ID || !key.Equal(k) {
		t.Fatal("identity persistence")
	}
	now := time.Now()
	proof, _ := NewProof(id.ID, "FRA", key, now)
	if e = proof.Verify(key.Public().(ed25519.PublicKey), now); e != nil {
		t.Fatal(e)
	}
	proof.RelayID = "evil"
	if proof.Verify(key.Public().(ed25519.PublicKey), now) == nil {
		t.Fatal("tampered proof")
	}
}
func FuzzTicket(f *testing.F) {
	key := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	pub := key.Public().(ed25519.PublicKey)
	now := time.Unix(1800000000, 0)
	raw, _ := Sign("ticket", "key", key, Ticket{"id", "device", Fingerprint(pub), "FRA", now, now.Add(time.Minute)})
	f.Add(raw)
	var env Envelope
	if e := Parse(raw, &env); e != nil {
		f.Fatal(e)
	}
	f.Add([]byte(env.Payload))
	f.Fuzz(func(t *testing.T, b []byte) {
		var payload Ticket
		_ = Parse(b, &payload)
		v := NewTicketVerifier(map[string]ed25519.PublicKey{"key": pub}, "FRA")
		v.Accept(b, pub, now)
	})
}
func FuzzConfig(f *testing.F) {
	key := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	pub := key.Public().(ed25519.PublicKey)
	now := time.Unix(1800000000, 0)
	raw, _ := Sign("config", "key", key, Config{Version: 1, GeneratedAt: now, ExpiresAt: now.Add(time.Hour), RoutingParameters: optimizer.DefaultParameters()})
	f.Add(raw)
	var env Envelope
	if e := Parse(raw, &env); e != nil {
		f.Fatal(e)
	}
	f.Add([]byte(env.Payload))
	f.Fuzz(func(t *testing.T, b []byte) {
		var payload Config
		_ = Parse(b, &payload)
		ValidateConfig(map[string]ed25519.PublicKey{"key": pub}, b, now)
	})
}

func TestPersistentReplayAndKeyRotation(t *testing.T) {
	pub1, key1, _ := ed25519.GenerateKey(rand.Reader)
	pub2, key2, _ := ed25519.GenerateKey(rand.Reader)
	device, _, _ := ed25519.GenerateKey(rand.Reader)
	now := time.Now()
	ticket := Ticket{ID: "persisted", DeviceID: "device", DeviceKey: Fingerprint(device), RelayID: "FRA", IssuedAt: now, ExpiresAt: now.Add(time.Minute)}
	raw, _ := Sign("ticket", "old", key1, ticket)
	path := filepath.Join(t.TempDir(), "replay.json")
	v, e := NewPersistentTicketVerifier(map[string]ed25519.PublicKey{"old": pub1, "new": pub2}, "FRA", path)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = v.Accept(raw, device, now); e != nil {
		t.Fatal(e)
	}
	restarted, e := NewPersistentTicketVerifier(map[string]ed25519.PublicKey{"old": pub1, "new": pub2}, "FRA", path)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = restarted.Accept(raw, device, now); e == nil {
		t.Fatal("replay survived restart")
	}
	ticket.ID = "new-ticket"
	raw, _ = Sign("ticket", "new", key2, ticket)
	if _, e = restarted.Accept(raw, device, now); e != nil {
		t.Fatal("rotation overlap", e)
	}
	restarted.Update(map[string]ed25519.PublicKey{"new": pub2}, nil)
	ticket.ID = "retired-ticket"
	raw, _ = Sign("ticket", "old", key1, ticket)
	if _, e = restarted.Accept(raw, device, now); e == nil {
		t.Fatal("retired key accepted")
	}
}
