package security

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func signedTicket(t *testing.T, key ed25519.PrivateKey, peer ed25519.PublicKey, id, device string, now time.Time) []byte {
	t.Helper()
	raw, err := Sign("ticket", "key", key, Ticket{ID: id, DeviceID: device, DeviceKey: Fingerprint(peer), RelayID: "FRA", IssuedAt: now, ExpiresAt: now.Add(time.Minute)})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// Revocation is read on every relay flow; it must not wait behind a ticket being
// persisted (fsync) by another connection.
func TestRevokedDoesNotWaitForReplayPersistence(t *testing.T) {
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	v := NewTicketVerifier(map[string]ed25519.PublicKey{"key": pub}, "FRA")
	v.useMu.Lock() // stands in for a slow persist inside AcceptForDevice
	defer v.useMu.Unlock()
	done := make(chan bool, 1)
	go func() { v.Update(map[string]ed25519.PublicKey{"key": pub}, []string{"d"}); done <- v.Revoked("d") }()
	select {
	case revoked := <-done:
		if !revoked {
			t.Fatal("revocation not applied")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Revoked/Update blocked behind replay persistence")
	}
	_ = key
}

func TestDeviceQuotaProtectsSharedReplayCache(t *testing.T) {
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	peer, _, _ := ed25519.GenerateKey(rand.Reader)
	v, err := NewPersistentTicketVerifier(map[string]ed25519.PublicKey{"key": pub}, "FRA", filepath.Join(t.TempDir(), "replay.json"))
	if err != nil {
		t.Fatal(err)
	}
	v.DeviceLimit = 3
	now := time.Now()
	for i := 0; i < 3; i++ {
		if _, err := v.Accept(signedTicket(t, key, peer, fmt.Sprintf("a%d", i), "noisy", now), peer, now); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := v.Accept(signedTicket(t, key, peer, "a3", "noisy", now), peer, now); err == nil {
		t.Fatal("device quota not enforced")
	}
	if _, err := v.Accept(signedTicket(t, key, peer, "b0", "quiet", now), peer, now); err != nil {
		t.Fatalf("other device starved: %v", err)
	}
}

func TestConcurrentAcceptRevokeAndReplay(t *testing.T) {
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	peer, _, _ := ed25519.GenerateKey(rand.Reader)
	v, _ := NewPersistentTicketVerifier(map[string]ed25519.PublicKey{"key": pub}, "FRA", filepath.Join(t.TempDir(), "replay.json"))
	now := time.Now()
	shared := signedTicket(t, key, peer, "shared", "d0", now)
	var wg sync.WaitGroup
	accepted := make(chan struct{}, 32)
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_ = v.Revoked("x")
			if _, err := v.Accept(shared, peer, now); err == nil {
				accepted <- struct{}{}
			}
			v.Accept(signedTicket(t, key, peer, fmt.Sprintf("t%d", i), fmt.Sprintf("d%d", i%4), now), peer, now)
		}(i)
	}
	wg.Wait()
	if len(accepted) != 1 {
		t.Fatalf("one-shot ticket accepted %d times", len(accepted))
	}
}
