package clientservice

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/buzzmean/veliq/core/controlclient"
	"github.com/buzzmean/veliq/core/security"
)

func TestRemoteFleetOffLegacyCPAndSignedRollback(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	public, signer, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	devicePublic, deviceKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	trust := map[string]ed25519.PublicKey{"fixture": public}
	dir := t.TempDir()
	device := "pilot-fixture"
	var mode, calls atomic.Int32
	cp := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/fleet/config" || r.Method != http.MethodPost {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		calls.Add(1)
		var proof security.Proof
		now := time.Now().UTC()
		if err := json.NewDecoder(r.Body).Decode(&proof); err != nil || proof.DeviceID != device ||
			proof.RelayID != security.FleetProofAudience || proof.Verify(devicePublic, now) != nil {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		switch mode.Load() {
		case 0:
			w.WriteHeader(http.StatusNotFound)
			return
		case 2:
			w.Write([]byte("{bad signature envelope}"))
			return
		}
		policy := security.FleetPolicy{Schema: security.FleetSchema, Version: 2, Device: device,
			Enabled: true, IssuedAt: now, ExpiresAt: now.Add(security.FleetFreshness), Candidates: []security.FleetCandidate{}}
		if mode.Load() == 3 {
			policy.Version, policy.Enabled = 3, false
		}
		raw, err := security.Sign(security.FleetConfigDomain, "fixture", signer, policy)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		_, _ = w.Write(raw)
	}))
	defer cp.Close()
	c := New(ctx)
	defer c.Close()
	s := &remoteState{controller: c, cp: &controlclient.Client{BaseURL: cp.URL, HTTP: cp.Client(), DeviceID: device, DeviceKey: deviceKey}}
	s.initFleet(trust, device, dir)
	if c.fleet.Enabled() || s.fleet != nil || calls.Load() != 0 {
		t.Fatal("feature-off client unexpectedly attempted fleet")
	}
	if err := os.WriteFile(filepath.Join(dir, fleetOptInFile), []byte(`{"scope":"all"}`), 0600); err != nil {
		t.Fatal(err)
	}
	s.initFleet(trust, device, dir)
	s.refreshFleet(ctx)
	if !c.fleet.Enabled() || calls.Load() != 1 || !c.fleet.expires.IsZero() {
		t.Fatal("opt-in silently fell back when the old CP returned 404")
	}
	mode.Store(1)
	s.refreshFleet(ctx)
	if !c.fleet.Enabled() || c.fleet.epoch != 2 || c.fleet.expires.IsZero() {
		t.Fatal("valid signed policy was not applied")
	}
	mode.Store(2)
	s.refreshFleet(ctx)
	if !c.fleet.Enabled() || !c.fleet.expires.IsZero() {
		t.Fatal("malformed policy enabled new legacy implicit opens")
	}
	mode.Store(3)
	s.refreshFleet(ctx)
	if c.fleet.Enabled() || c.fleet.epoch != 3 {
		t.Fatal("newer signed rollback did not restore legacy mode")
	}
	mode.Store(1)
	s.refreshFleet(ctx)
	if c.fleet.Enabled() || c.fleet.epoch != 3 {
		t.Fatal("old policy changed the signed rollback")
	}
	if got := c.fleet.snapshot(time.Now()); strings.Contains(got["reason"].(string), device) {
		t.Fatalf("status disclosed device scope: %+v", got)
	}
}
