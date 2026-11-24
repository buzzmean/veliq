package security

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/buzzmean/veliq/core/optimizer"
)

func TestConfigRevocationSizeDomainBoundAndAtomicCache(t *testing.T) {
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	keys := map[string]ed25519.PublicKey{"root": pub}
	now := time.Now()
	cfg := Config{Version: 1, GeneratedAt: now, ExpiresAt: now.Add(time.Hour), RoutingParameters: optimizer.DefaultParameters()}
	for i := 0; i < 5000; i++ {
		cfg.RevokedDevices = append(cfg.RevokedDevices, fmt.Sprintf("%032d", i))
	}
	raw, err := Sign("config", "root", key, cfg)
	if err != nil || len(raw) <= MaxDocument {
		t.Fatal("complete large config", len(raw), err)
	}
	cache := NewConfigCache(keys, "")
	if err = cache.Apply(raw, now); err != nil {
		t.Fatal(err)
	}
	if _, err = Sign("ticket", "root", key, cfg); err == nil {
		t.Fatal("ticket limit widened")
	}
	var env Envelope
	if err = Parse(raw, &env); err == nil {
		t.Fatal("generic parser limit widened")
	}
	cfg.Version = 2
	cfg.RevokedDevices = append(cfg.RevokedDevices, strings.Repeat("z", MaxConfigDocument))
	if raw, err = Sign("config", "root", key, cfg); err == nil || raw != nil {
		t.Fatal("oversize config signed")
	}
	if err = cache.Apply([]byte(strings.Repeat("z", MaxConfigDocument+1)), now); err == nil {
		t.Fatal("oversize config applied")
	}
	current, err := cache.Current(now)
	if err != nil || current.Version != 1 || len(current.RevokedDevices) != 5000 {
		t.Fatal("partial cache mutation", err)
	}
}
