package clientservice

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestRuntimeFleetOptInIsSeparateAndFailsClosed(t *testing.T) {
	controller:=New(context.Background())
	defer controller.Close()
	root:=t.TempDir()
	r:=&remoteState{controller:controller}
	r.initFleet(nil,"fixture",root)
	if r.fleet!=nil||controller.fleet.Enabled(){t.Fatal("default attempted fleet discovery")}
	if err:=os.WriteFile(filepath.Join(root,fleetOptInFile),[]byte("{}"),0600);err!=nil{t.Fatal(err)}
	r.initFleet(nil,"fixture",root)
	if r.fleet==nil||!controller.fleet.Enabled(){t.Fatal("configured opt-in was ignored")}
	if got:=controller.fleet.snapshot(controller.fleet.now())["reason"];got!="fleet_policy_unavailable"{
		t.Fatalf("missing sidecar admitted opens: %v",got)
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
