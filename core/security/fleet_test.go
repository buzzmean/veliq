package security

import (
	"crypto/ed25519"
	"path/filepath"
	"testing"
	"time"

	"github.com/buzzmean/veliq/core/optimizer"
)

func TestFleetPolicyBoundToTrustedDeviceVersionAndMode(t *testing.T) {
	pub, key, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1730000000, 0).UTC()
	keys := map[string]ed25519.PublicKey{"fixture": pub}
	path := filepath.Join(t.TempDir(), "fleet-state.json")
	cache := NewFleetCache(keys, "device-A", path)
	prepare := func(p FleetPolicy) []byte {
		t.Helper()
		raw, e := Sign(FleetConfigDomain, "fixture", key, p)
		if e != nil {
			t.Fatal(e)
		}
		return raw
	}
	p := FleetPolicy{Schema: FleetSchema, Version: 7, IssuedAt: now, ExpiresAt: now.Add(FleetFreshness), Device: "device-A", Enabled: true}
	if _, e := cache.Apply(prepare(p), now); e != nil {
		t.Fatal(e)
	}
	for _, bad := range []FleetPolicy{
		{Schema: 1, Version: 8, IssuedAt: now, ExpiresAt: now.Add(FleetFreshness), Device: "device-B"},
		{Schema: 1, Version: 6, IssuedAt: now, ExpiresAt: now.Add(FleetFreshness), Device: "device-A"},
		{Schema: 1, Version: 7, IssuedAt: now.Add(time.Second), ExpiresAt: now.Add(FleetFreshness), Device: "device-A"},
	} {
		if _, e := cache.Apply(prepare(bad), now); e == nil {
			t.Fatalf("unverified state accepted: %+v", bad)
		}
	}
	reopened := NewFleetCache(keys, "device-A", path)
	if cached, e := reopened.Load(now.Add(time.Minute)); e != nil || !cached.Enabled || cached.ValidAt(now.Add(time.Minute)) {
		t.Fatalf("expired floor = %+v, %v", cached, e)
	}
	rollback := p
	rollback.Enabled = false
	rollback.Version++
	rollback.IssuedAt = now.Add(time.Minute)
	rollback.ExpiresAt = rollback.IssuedAt.Add(FleetFreshness)
	if actual, e := reopened.Apply(prepare(rollback), rollback.IssuedAt); e != nil || actual.Enabled {
		t.Fatalf("trusted higher rollback rejected: %v", e)
	}
}

func TestFleetSignatureDoesNotChangeLegacyStrictConfig(t *testing.T) {
	pub, key, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1730000000, 0).UTC()
	keys := map[string]ed25519.PublicKey{"fixture": pub}
	legacy := Config{Version: 3, GeneratedAt: now, ExpiresAt: now.Add(time.Hour), RoutingParameters: optimizer.DefaultParameters()}
	raw, e := Sign("config", "fixture", key, legacy)
	if e != nil {
		t.Fatal(e)
	}
	if _, e := ValidateConfig(keys, raw, now); e != nil {
		t.Fatal(e)
	}
	sidecar, e := Sign(FleetConfigDomain, "fixture", key, FleetPolicy{Schema: 1, Version: 3, IssuedAt: now, ExpiresAt: now.Add(FleetFreshness), Device: "D", Enabled: true})
	if e != nil {
		t.Fatal(e)
	}
	if _, e := ValidateConfig(keys, sidecar, now); e == nil {
		t.Fatal("sidecar accepted by legacy parser")
	}
	cache := NewFleetCache(keys, "D", "")
	if _, e := cache.Apply(raw, now); e == nil {
		t.Fatal("legacy envelope enabled fleet")
	}
	if _, e := cache.Apply(sidecar, now); e != nil {
		t.Fatal(e)
	}
}

func TestFleetRefreshMarksMissingLoadWithoutMovingSampleBackward(t *testing.T) {
	now := time.Now().UTC()
	base := FleetResources{Sessions: 20, Flows: 200, Packets: 100, Bits: 100000, Opens: 10}
	initial := FleetPolicy{Schema: FleetSchema, Version: 2, Enabled: true,
		Device: "fixture", IssuedAt: now, ExpiresAt: now.Add(FleetFreshness),
		Candidates: []FleetCandidate{
			{ID: "node", Address: "127.0.0.1:4433", Phase: FleetActive,
				Limits: base, Used: FleetResources{Sessions: 2}, ObservedAt: now, LoadAvailable: true},
		}}
	missing := initial
	missing.Candidates = append([]FleetCandidate(nil), initial.Candidates...)
	missing.Candidates[0].LoadAvailable = false
	if !sameFleetPolicy(initial, missing) || sameFleetPolicy(missing, initial) {
		t.Fatal("missing load could resurrect an older sample")
	}
	missing.Candidates[0].Used.Sessions++
	if sameFleetPolicy(initial, missing) {
		t.Fatal("equivocal load at the same observed timestamp was accepted")
	}
}
