package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/buzzmean/neexitlag/core/security"
	"github.com/buzzmean/neexitlag/internal/releaseinfo"
	cp "github.com/buzzmean/neexitlag/services/control-plane"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestUpgradeCapabilityAndJournalContracts(t *testing.T) {
	raw, e := json.Marshal(releaseinfo.Current("relay", []string{"neexitlag/2", "neexitlag/3"}, security.MaxConfigDocument, 1800))
	if e != nil {
		t.Fatal(e)
	}
	var info map[string]any
	if json.Unmarshal(raw, &info) != nil || info["default_lease_seconds"] != float64(1800) || info["lease_seconds"] != nil {
		t.Fatal("lease capability wire contract changed")
	}
	good := "/etc/neexitlag.bak-20261020T100000Z-aabbccddeeff/probe.id"
	leafJournal := "/var/backups/neexitlag-certificates/20261021T074452Z-7cf97ecb/probe.id"
	if !validProbeJournal(good) || !validProbeJournal(leafJournal) {
		t.Fatal("valid journal rejected")
	}
	for _, bad := range []string{"/tmp/probe.id", good + "/../identity.json", "/etc/neexitlag/probe.id", leafJournal + "/../probe.id", "/var/backups/neexitlag-certificates/probe.id", "/var/backups/neexitlag-certificates/20261021T074452Z-7cf97ecb00/probe.id"} {
		if validProbeJournal(bad) {
			t.Fatal("unbounded journal path accepted")
		}
	}
	if !localInterfaceIP("127.0.0.1") || localInterfaceIP("not-an-ip") {
		t.Fatal("local-only address check failed")
	}
}

func TestUpgradeProbeRevokePublicationRetryPostgres(t *testing.T) {
	database := os.Getenv("NEEXITLAG_TEST_DATABASE_URL")
	if database == "" {
		t.Skip("isolated PostgreSQL required")
	}
	ctx, stop := context.WithTimeout(context.Background(), 30*time.Second)
	defer stop()
	root, e := pgxpool.New(ctx, database)
	if e != nil {
		t.Fatal(e)
	}
	defer root.Close()
	id, _ := security.NewID()
	schema := "test_upgrade_" + id
	if _, e = root.Exec(ctx, "CREATE SCHEMA "+schema); e != nil {
		t.Fatal(e)
	}
	defer root.Exec(context.Background(), "DROP SCHEMA "+schema+" CASCADE")
	cfg, e := pgxpool.ParseConfig(database)
	if e != nil {
		t.Fatal(e)
	}
	cfg.ConnConfig.RuntimeParams["search_path"] = schema
	db, e := pgxpool.NewWithConfig(ctx, cfg)
	if e != nil {
		t.Fatal(e)
	}
	defer db.Close()
	store := &cp.Store{DB: db}
	if store.Migrate(ctx) != nil || store.Migrate(ctx) != nil {
		t.Fatal("additive migration not repeatable")
	}
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	trust := map[string]string{"vps-1": base64.RawURLEncoding.EncodeToString(pub)}
	deviceKey, _, _ := ed25519.GenerateKey(rand.Reader)
	if e = store.Register(ctx, cp.Device{ID: id, Name: "isolated local probe", PublicKey: base64.RawURLEncoding.EncodeToString(deviceKey)}); e != nil {
		t.Fatal(e)
	}
	if _, e = db.Exec(ctx, `CREATE FUNCTION reject_probe_publish() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RAISE EXCEPTION 'isolated publish failure'; END;$$; CREATE TRIGGER reject_publish BEFORE INSERT ON config_versions FOR EACH ROW EXECUTE FUNCTION reject_probe_publish()`); e != nil {
		t.Fatal(e)
	}
	if revokePublishedProbe(ctx, store, id, key, trust) == nil {
		t.Fatal("publication error ignored")
	}
	device, e := store.Device(ctx, id)
	if e != nil || !device.Revoked {
		t.Fatal("failed publication resurrected probe")
	}
	if _, e = db.Exec(ctx, "DROP TRIGGER reject_publish ON config_versions"); e != nil {
		t.Fatal(e)
	}
	if e = revokePublishedProbe(ctx, store, id, key, trust); e != nil {
		t.Fatal(e)
	}
	raw, e := store.LatestConfig(ctx)
	if e != nil {
		t.Fatal(e)
	}
	config, e := security.ValidateConfig(map[string]ed25519.PublicKey{"vps-1": pub}, raw, time.Now())
	if e != nil || len(config.RevokedDevices) != 1 || config.RevokedDevices[0] != id {
		t.Fatal("probe revocation not fully published")
	}
	if e = revokePublishedProbe(ctx, store, "missing-device", key, trust); e != nil {
		t.Fatal("pre-register interruption cleanup failed", e)
	}
}

// The old binary executes only migration 001. Reapplying that exact additive
// SQL must not remove activation tables, salt, device revocations or config rows.
func TestSchema2RemainsCompatibleWithBaselineMigrationPostgres(t *testing.T) {
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
	schema := "test_compat_" + id
	if _, e = root.Exec(ctx, "CREATE SCHEMA "+schema); e != nil {
		t.Fatal(e)
	}
	defer root.Exec(context.Background(), "DROP SCHEMA "+schema+" CASCADE")
	config, e := pgxpool.ParseConfig(database)
	if e != nil {
		t.Fatal(e)
	}
	config.ConnConfig.RuntimeParams["search_path"] = schema
	db, e := pgxpool.NewWithConfig(ctx, config)
	if e != nil {
		t.Fatal(e)
	}
	defer db.Close()
	store := &cp.Store{DB: db}
	if e = store.Migrate(ctx); e != nil {
		t.Fatal(e)
	}
	var salt []byte
	if e = db.QueryRow(ctx, "SELECT hardware_salt FROM activation_policy").Scan(&salt); e != nil {
		t.Fatal(e)
	}
	if e = store.Register(ctx, cp.Device{ID: id, Name: "fixture", PublicKey: "fixture-" + id}); e != nil {
		t.Fatal(e)
	}
	if e = store.Revoke(ctx, id); e != nil {
		t.Fatal(e)
	}
	legacy, e := os.ReadFile("../../services/control-plane/migrations/001_initial.sql")
	if e != nil {
		t.Fatal(e)
	}
	if _, e = db.Exec(ctx, string(legacy)); e != nil {
		t.Fatal(e)
	}
	// The deployed activation release also replays migration 002 on startup.
	// It must leave schema3 test metadata, slots, salt and revocations intact.
	activationLegacy, e := os.ReadFile("../../services/control-plane/migrations/002_activation_codes.sql")
	if e != nil {
		t.Fatal(e)
	}
	if _, e = db.Exec(ctx, string(activationLegacy)); e != nil {
		t.Fatal(e)
	}
	if e = store.Migrate(ctx); e != nil {
		t.Fatal(e)
	}
	var version, count int
	var revoked bool
	var after []byte
	if e = db.QueryRow(ctx, "SELECT max(version) FROM schema_migrations").Scan(&version); e != nil {
		t.Fatal(e)
	}
	if e = db.QueryRow(ctx, "SELECT count(*) FROM information_schema.tables WHERE table_schema=$1 AND table_name IN ('activation_codes','activation_slots','activation_policy')", schema).Scan(&count); e != nil {
		t.Fatal(e)
	}
	if e = db.QueryRow(ctx, "SELECT revoked FROM devices WHERE id=$1", id).Scan(&revoked); e != nil {
		t.Fatal(e)
	}
	if e = db.QueryRow(ctx, "SELECT hardware_salt FROM activation_policy").Scan(&after); e != nil {
		t.Fatal(e)
	}
	if version != 4 || count != 3 || !revoked || string(salt) != string(after) {
		t.Fatal("schema3 additive downgrade/retry lost security state")
	}
}
