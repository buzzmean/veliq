package controlplane

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/buzzmean/veliq/core/optimizer"
	"github.com/buzzmean/veliq/core/security"
)

func TestFleetCohortAndDrainAdmissions(t *testing.T) {
	cohort := FleetCohort{Enabled: true, Devices: []string{"A", "B"}}
	meta := fleetRegistryMeta{Managed: true, Phase: security.FleetCanary, CanaryDevice: "A"}
	if !cohort.valid() || !meta.admitsDevice("A", cohort) || meta.admitsDevice("B", cohort) {
		t.Fatal("canary not scoped")
	}
	moveFleetToDrain(&meta, cohort)
	if !meta.admitsDevice("A", FleetCohort{}) || meta.admitsDevice("B", cohort) || meta.Phase != security.FleetDrain {
		t.Fatal("drain did not keep only the previous credential cohort")
	}
	if (FleetCohort{Enabled: true, Devices: []string{"A", "A"}}).valid() {
		t.Fatal("duplicate device")
	}
}

func TestFleetReferenceStoreRegistersAndRollsBackWithoutChangingLegacyConfig(t *testing.T) {
	s := codeStore(t)
	ctx := context.Background()
	pub, key, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	if err = s.PutRelay(ctx, optimizer.RelayCandidate{ID: "legacy", Address: "127.0.0.1:4422"}); err != nil {
		t.Fatal(err)
	}
	if _, err = s.Publish(ctx, "test", key, nil); err != nil {
		t.Fatal(err)
	}
	before, err := readFleetVersion(ctx, s.DB)
	if err != nil {
		t.Fatal(err)
	}
	change := func(req FleetRegistryChange) uint64 {
		t.Helper()
		v, e := s.changeFleetRegistry(ctx, req)
		if e != nil {
			t.Fatal(e)
		}
		return v
	}
	cohort := FleetCohort{Enabled: true, Devices: []string{"pilot"}}
	ver := change(FleetRegistryChange{Operation: "scope", ExpectedVersion: before, Cohort: &cohort})
	sum := sha256.Sum256([]byte("synthetic heartbeat"))
	node := FleetRegistryNode{ID: "fleet-node", Address: "127.0.0.1:4433", Phase: security.FleetStaged,
		Limits:      security.FleetResources{Sessions: 20, Flows: 250, Packets: 10000, Bits: 10000000, Opens: 40},
		ProbeDevice: "probe", ProbeTarget: "127.0.0.1:9900", HeartbeatSHA256: hex.EncodeToString(sum[:]),
		FleetArtifact: FleetArtifact{SourceCommit: strings.Repeat("a", 40), SHA256: strings.Repeat("b", 64), Bytes: 30}}
	request := FleetRegistryChange{Operation: "stage", ExpectedVersion: ver, Node: &node}
	ver = change(request)
	if retry := change(request); retry != ver {
		t.Fatal("idempotent retry republished")
	}
	substitute := node
	substitute.FleetArtifact.SHA256 = strings.Repeat("c", 64)
	if _, err := s.changeFleetRegistry(ctx, FleetRegistryChange{Operation: request.Operation,
		ExpectedVersion: request.ExpectedVersion, Node: &substitute}); err != ErrFleetRegistryConflict {
		t.Fatalf("changed artifact reused an operation receipt: %v", err)
	}
	if _, err = s.Publish(ctx, "test", key, nil); err != nil {
		t.Fatal(err)
	}
	if after, err := readFleetVersion(ctx, s.DB); err != nil || after != ver {
		t.Fatalf("legacy republish changed fleet CAS: %d, %v", after, err)
	}
	if relays, err := s.Relays(ctx); err != nil || len(relays) != 1 || relays[0].ID != "legacy" {
		t.Fatalf("fleet-only row leaked through legacy discovery: %+v, %v", relays, err)
	}
	if allow, e := s.fleetTicket(ctx, node.ID, "pilot"); e != nil || allow {
		t.Fatalf("staged opened for pilot: %t %v", allow, e)
	}
	if allow, e := s.fleetTicket(ctx, node.ID, "probe"); e != nil || !allow {
		t.Fatalf("staged proof refused: %t %v", allow, e)
	}
	now := time.Now().UTC()
	hb := security.FleetHeartbeat{ID: node.ID, Sequence: uint64(now.UnixNano()), Sampled: true}
	incorrect := hb
	incorrect.ObserveOnly = true
	if _, err = s.recordFleetHeartbeat(ctx, incorrect, sum[:], now); err == nil {
		t.Fatal("managed relay accepted observation-only heartbeat")
	}
	if policy, e := s.recordFleetHeartbeat(ctx, hb, sum[:], now); e != nil || policy.Phase != security.FleetStaged {
		t.Fatalf("stage heartbeat: %v", e)
	}
	if _, e := s.recordFleetHeartbeat(ctx, hb, sum[:], now); e == nil {
		t.Fatal("replayed heartbeat accepted")
	}
	node.Phase, node.CanaryDevice, node.ProbeDevice, node.ProbeTarget, node.HeartbeatSHA256 = security.FleetCanary, "pilot", "", "", ""
	node.ProofSHA256 = hex.EncodeToString(sum[:])
	ver = change(FleetRegistryChange{Operation: "canary", ExpectedVersion: ver, Node: &node})
	policy, e := s.fleetPolicy(ctx, "pilot", now)
	if e != nil || len(policy.Candidates) != 1 || policy.Candidates[0].ID != node.ID {
		t.Fatalf("canary not selected: %+v %v", policy, e)
	}
	disabled := FleetCohort{}
	next := change(FleetRegistryChange{Operation: "rollback", ExpectedVersion: ver, Cohort: &disabled})
	if next <= ver {
		t.Fatal("rollback did not publish a new version")
	}
	if allow, e := s.fleetTicket(ctx, node.ID, "pilot"); e != nil || !allow {
		t.Fatalf("draining lease lost its ticket route: %v %v", allow, e)
	}
	policy, e = s.fleetPolicy(ctx, "pilot", time.Now().UTC())
	if e != nil || policy.Enabled || len(policy.Candidates) != 0 {
		t.Fatalf("rollback sidecar: %+v %v", policy, e)
	}
	raw, e := s.LatestConfig(ctx)
	if e != nil {
		t.Fatal(e)
	}
	legacy, e := security.ValidateConfig(map[string]ed25519.PublicKey{"test": pub}, raw, time.Now())
	if e != nil || len(legacy.Relays) != 1 || legacy.Relays[0].ID != "legacy" {
		t.Fatalf("legacy registry changed: %+v %v", legacy.Relays, e)
	}
}

func TestFleetRegistryRequiresItsOwnBearer(t *testing.T) {
	old := strings.Repeat("a", 32)
	fleet := strings.Repeat("b", 32)
	api := &API{Settings: Settings{AdminToken: old, FleetRegistryToken: fleet}}
	for _, token := range []string{"", old, fleet + "x"} {
		r := httptest.NewRequest(http.MethodGet, "/api/v1/fleet/registry", nil)
		r.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		api.fleetRegistry(w, r)
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("unexpected registry status %d", w.Code)
		}
	}
}
