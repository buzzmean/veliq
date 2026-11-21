package controlplane

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"github.com/buzzmean/neexitlag/core/security"
	"github.com/jackc/pgx/v5/pgxpool"
	"os"
	"strings"
	"testing"
	"time"
)

func TestFreshEnrollmentAtomicReplacementRetryRevocationAndDBFailure(t *testing.T) {
	database := os.Getenv("NEEXITLAG_TEST_DATABASE_URL")
	if database == "" {
		t.Skip("isolated PostgreSQL required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	root, e := pgxpool.New(ctx, database)
	if e != nil {
		t.Fatal(e)
	}
	defer root.Close()
	id, _ := security.NewID()
	schema := "test_fresh_" + id
	if _, e = root.Exec(ctx, "CREATE SCHEMA "+schema); e != nil {
		t.Fatal(e)
	}
	defer root.Exec(context.Background(), "DROP SCHEMA "+schema+" CASCADE")
	cfg, e := pgxpool.ParseConfig(database)
	if e != nil {
		t.Fatal(e)
	}
	cfg.ConnConfig.RuntimeParams["search_path"] = schema
	pool, e := pgxpool.NewWithConfig(ctx, cfg)
	if e != nil {
		t.Fatal(e)
	}
	defer pool.Close()
	s := &Store{pool}
	if e = s.Migrate(ctx); e != nil {
		t.Fatal(e)
	}
	pub, signer, _ := ed25519.GenerateKey(rand.Reader)
	trust := map[string]string{"vps-1": base64.RawURLEncoding.EncodeToString(pub)}
	makeDevice := func() Device {
		key, _, _ := ed25519.GenerateKey(rand.Reader)
		id, _ := security.NewID()
		return Device{ID: id, Name: "PC", PublicKey: base64.RawURLEncoding.EncodeToString(key)}
	}
	machine := strings.Repeat("a", 64)
	a, b, c := makeDevice(), makeDevice(), makeDevice()
	enroll := func(d Device) error { return s.EnrollFreshDevice(ctx, machine, d, "vps-1", signer, trust) }
	if e = enroll(a); e != nil {
		t.Fatal(e)
	}
	if e = enroll(a); e != nil {
		t.Fatal("lost response retry", e)
	}
	var count int
	if e = pool.QueryRow(ctx, "SELECT count(*) FROM devices").Scan(&count); e != nil || count != 1 {
		t.Fatal("retry creates identities", count, e)
	}
	if e = enroll(b); e != nil {
		t.Fatal(e)
	}
	old, e := s.Device(ctx, a.ID)
	if e != nil || !old.Revoked {
		t.Fatal("old identity active", old, e)
	}
	raw, e := s.LatestConfig(ctx)
	if e != nil {
		t.Fatal(e)
	}
	signed, e := security.ValidateConfig(map[string]ed25519.PublicKey{"vps-1": pub}, raw, time.Now())
	if e != nil || len(signed.RevokedDevices) != 1 || signed.RevokedDevices[0] != a.ID {
		t.Fatal("revocation not published atomically", signed, e)
	}
	if e = enroll(a); e == nil {
		t.Fatal("old request resurrected revoked identity")
	}
	// Fail at the LAST publication write, after registration/revocation/slot updates.
	if _, e = pool.Exec(ctx, `CREATE FUNCTION deny_fresh_publish() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RAISE EXCEPTION 'isolated injected publication failure'; END;$$; CREATE TRIGGER deny_publish BEFORE INSERT ON config_versions FOR EACH ROW EXECUTE FUNCTION deny_fresh_publish()`); e != nil {
		t.Fatal(e)
	}
	if e = enroll(c); e == nil {
		t.Fatal("DB publication failure ignored")
	}
	current, e := s.Device(ctx, b.ID)
	if e != nil || current.Revoked {
		t.Fatal("failed transaction revoked working identity", current, e)
	}
	if _, e = s.Device(ctx, c.ID); e == nil {
		t.Fatal("failed transaction registered partial identity")
	}
	var slot string
	if e = pool.QueryRow(ctx, "SELECT device_id FROM fresh_machine_slots WHERE machine_hash=$1", machine).Scan(&slot); e != nil || slot != b.ID {
		t.Fatal("slot partially changed", slot, e)
	}
	latest, e := s.LatestConfig(ctx)
	if e != nil || string(latest) != string(raw) {
		t.Fatal("failed publication replaced config", e)
	}
}
