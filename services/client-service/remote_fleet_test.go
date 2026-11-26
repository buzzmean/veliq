package clientservice

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/buzzmean/veliq/core/routing"
)

func TestRuntimeFleetOptInIsSeparateAndFailsClosed(t *testing.T) {
	controller := New(context.Background())
	defer controller.Close()
	root := t.TempDir()
	r := &remoteState{controller: controller}
	r.initFleet(nil, "fixture", root)
	if r.fleet != nil || controller.fleet.Enabled() {
		t.Fatal("default attempted fleet discovery")
	}
	if err := os.WriteFile(filepath.Join(root, fleetOptInFile), []byte(`{"scope":"application","application_id":"canary"}`), 0600); err != nil {
		t.Fatal(err)
	}
	r.initFleet(nil, "fixture", root)
	if r.fleet == nil || !controller.fleet.Enabled() {
		t.Fatal("configured opt-in was ignored")
	}
	if !controller.fleet.ManagesFlow(routing.Flow{ApplicationID: "canary"}) || controller.fleet.ManagesFlow(routing.Flow{ApplicationID: "chatgpt-desktop"}) {
		t.Fatal("canary scope admitted another application")
	}
	if got := controller.fleet.snapshot(controller.fleet.now())["reason"]; got != "fleet_policy_unavailable" {
		t.Fatalf("missing sidecar admitted opens: %v", got)
	}
}

func TestFleetOptInRequiresExplicitScope(t *testing.T) {
	for _, raw := range []string{"", "{}", `{"scope":"application"}`, `{"scope":"all","application_id":"canary"}`, `{"scope":"application","application_id":"canary","unknown":1}`} {
		if _, err := parseFleetOptIn([]byte(raw)); err == nil {
			t.Fatalf("invalid marker admitted: %q", raw)
		}
	}
	if application, err := parseFleetOptIn([]byte(`{"scope":"all"}`)); err != nil || application != "" {
		t.Fatalf("explicit all scope rejected: %q %v", application, err)
	}
	if application, err := parseFleetOptIn([]byte(`{"scope":"application","application_id":"!v2-fi-canary"}`)); err != nil || application != "!v2-fi-canary" {
		t.Fatalf("application scope rejected: %q %v", application, err)
	}
}

func TestInvalidFleetMarkerCannotActivatePolicy(t *testing.T) {
	controller := New(context.Background())
	defer controller.Close()
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, fleetOptInFile), []byte("{}"), 0600); err != nil {
		t.Fatal(err)
	}
	r := &remoteState{controller: controller}
	r.initFleet(nil, "fixture", root)
	if r.fleet == nil || !r.fleet.floorUnknown || !controller.fleet.Enabled() || !controller.fleet.expires.IsZero() {
		t.Fatal("malformed marker did not stay fail-closed")
	}
}

func TestRuntimeFleetCannotLoseAnUnverifiedVersionFloor(t *testing.T) {
	c := New(context.Background())
	defer c.Close()
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, fleetCacheFile), []byte("{invalid floor"), 0600); err != nil {
		t.Fatal(err)
	}
	s := &remoteState{controller: c}
	s.initFleet(nil, "fixture", root)
	if s.fleet == nil || !s.fleet.floorUnknown {
		t.Fatal("bad persisted floor was silently treated as a new device")
	}
	s.refreshFleet(context.Background())
	if !c.fleet.Enabled() || !c.fleet.expires.IsZero() {
		t.Fatal("bad floor admitted implicit legacy opens")
	}
}
