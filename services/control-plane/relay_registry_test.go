package controlplane

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"testing"

	"github.com/buzzmean/neexitlag/core/optimizer"
)

func TestFleetAtomicPublishCASAndRollbackPreservesSecurity(t *testing.T) {
	s := codeStore(t)
	ctx := context.Background()
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	trust := map[string]string{"fleet": base64.RawURLEncoding.EncodeToString(pub)}
	old := FleetRelayState{Exists: true, Node: optimizer.RelayCandidate{ID: "VPS-01", Address: "2.56.177.4:4433"}, HeartbeatHash: []byte("old-hash")}
	if e := s.ChangeFleetRelay(ctx, "VPS-01", "", old, "fleet", key, trust, nil); e != nil {
		t.Fatal(e)
	}
	var before int64
	s.DB.QueryRow(ctx, "SELECT max(version) FROM config_versions").Scan(&before)
	next := old
	next.Node.Address = "146.0.77.98:4433"
	next.HeartbeatHash = []byte("new-hash")
	if e := s.ChangeFleetRelay(ctx, "VPS-01", old.Node.Address, next, "fleet", key, trust, []byte("wrong")); e == nil {
		t.Fatal("accepted stale hash")
	}
	if e := s.ChangeFleetRelay(ctx, "VPS-01", old.Node.Address, next, "fleet", key, trust, old.HeartbeatHash); e != nil {
		t.Fatal(e)
	}
	// Security state written after publication must survive relay rollback.
	if _, e := s.DB.Exec(ctx, "INSERT INTO users(id,name) VALUES('fleet-user','fixture'); INSERT INTO devices(id,user_id,name,public_key) VALUES('fleet-fixture','fleet-user','fixture','public-fixture'); INSERT INTO auth_nonces(device_id,nonce,expires_at) VALUES('fleet-fixture','nonce',now()+interval '1 hour')"); e != nil {
		t.Fatal(e)
	}
	if e := s.ChangeFleetRelay(ctx, "VPS-01", next.Node.Address, old, "fleet", key, trust, next.HeartbeatHash); e != nil {
		t.Fatal(e)
	}
	var after int64
	var n int
	s.DB.QueryRow(ctx, "SELECT max(version) FROM config_versions").Scan(&after)
	s.DB.QueryRow(ctx, "SELECT count(*) FROM auth_nonces WHERE device_id='fleet-fixture'").Scan(&n)
	got, e := s.FleetRelay(ctx, "VPS-01")
	if e != nil || got.Node.Address != old.Node.Address || n != 1 || after <= before {
		t.Fatalf("rollback: %+v nonce=%d version=%d/%d err=%v", got, n, before, after, e)
	}
	// Publication failure rolls back the row as well as the signed config.
	if _, e = s.DB.Exec(ctx, "ALTER TABLE config_versions RENAME TO config_versions_unavailable"); e != nil {
		t.Fatal(e)
	}
	if e = s.ChangeFleetRelay(ctx, "VPS-01", old.Node.Address, next, "fleet", key, trust, old.HeartbeatHash); e == nil {
		t.Fatal("publication succeeded without table")
	}
	got, e = s.FleetRelay(ctx, "VPS-01")
	if e != nil || got.Node.Address != old.Node.Address {
		t.Fatal("partial publication", got, e)
	}
}
