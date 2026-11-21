package controlplane

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"github.com/buzzmean/neexitlag/core/enrollment"
	"github.com/buzzmean/neexitlag/core/security"
	"github.com/jackc/pgx/v5/pgxpool"
	"os"
	"strings"
	"testing"
	"time"
)

func codeStore(t *testing.T) *Store {
	t.Helper()
	dsn := os.Getenv("NEEXITLAG_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("isolated PostgreSQL required")
	}
	ctx := context.Background()
	root, e := pgxpool.New(ctx, dsn)
	if e != nil {
		t.Fatal(e)
	}
	id, _ := security.NewID()
	schema := "test_codes_" + id
	if _, e = root.Exec(ctx, "CREATE SCHEMA "+schema); e != nil {
		t.Fatal(e)
	}
	cfg, e := pgxpool.ParseConfig(dsn)
	if e != nil {
		t.Fatal(e)
	}
	cfg.ConnConfig.RuntimeParams["search_path"] = schema
	pool, e := pgxpool.NewWithConfig(ctx, cfg)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { pool.Close(); root.Exec(context.Background(), "DROP SCHEMA "+schema+" CASCADE"); root.Close() })
	s := &Store{pool}
	if e = s.Migrate(ctx); e != nil {
		t.Fatal(e)
	}
	if e = s.Migrate(ctx); e != nil {
		t.Fatal("additive migration", e)
	}
	return s
}
func TestCodeFiftyFreezeReplacementsOneSeatAtomicRevokeAndLimit(t *testing.T) {
	s := codeStore(t)
	ctx := context.Background()
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	trust := map[string]string{"test": base64.RawURLEncoding.EncodeToString(pub)}
	c, raw, e := s.CreateCode(ctx, ActivationCode{Kind: "club", Name: "Fixture", Limit: 1, Expires: time.Now().Add(time.Hour)})
	if e != nil {
		t.Fatal(e)
	}
	hash, _ := enrollment.CodeHash(raw)
	machine := strings.Repeat("a", 64)
	makeDevice := func() Device {
		pk, _, _ := ed25519.GenerateKey(rand.Reader)
		id, _ := security.NewID()
		return Device{ID: id, Name: "test", PublicKey: base64.RawURLEncoding.EncodeToString(pk)}
	}
	enroll := func(m string, d Device) error { return s.EnrollCode(ctx, hash, m, d, "test", key, trust) }
	start := time.Now()
	var current Device
	for i := 0; i < 50; i++ {
		next := makeDevice()
		if e = enroll(machine, next); e != nil {
			t.Fatal(i, e)
		}
		if i > 0 {
			old, e := s.Device(ctx, current.ID)
			if e != nil || !old.Revoked {
				t.Fatal("old identity active", e)
			}
		}
		current = next
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatal("50 replacements exceeded bounded fixture budget", elapsed)
	}
	slots, e := s.CodeMachines(ctx, c.ID)
	if e != nil || len(slots) != 1 {
		t.Fatal("not one seat", e)
	}
	if e = enroll(machine, current); e != nil {
		t.Fatal("lost reply retry", e)
	}
	if e = enroll(strings.Repeat("b", 64), makeDevice()); e == nil || e.Error() != "ACTIVATION_LIMIT" {
		t.Fatal("limit not enforced", e)
	}
	// Publication error must roll back the replacement and old revocation.
	if _, e = s.DB.Exec(ctx, `CREATE FUNCTION deny_code_publish() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RAISE EXCEPTION 'isolated injection'; END;$$; CREATE TRIGGER deny_code BEFORE INSERT ON config_versions FOR EACH ROW EXECUTE FUNCTION deny_code_publish()`); e != nil {
		t.Fatal(e)
	}
	failed := makeDevice()
	if e = enroll(machine, failed); e == nil {
		t.Fatal("publication failure ignored")
	}
	active, e := s.Device(ctx, current.ID)
	if e != nil || active.Revoked {
		t.Fatal("rollback revoked working identity")
	}
	if _, e = s.Device(ctx, failed.ID); e == nil {
		t.Fatal("partial insert")
	}
	s.DB.Exec(ctx, "DROP TRIGGER deny_code ON config_versions")
	if e = s.RevokeCode(ctx, c.ID, machine, "test", key, trust); e != nil {
		t.Fatal(e)
	}
	if e = enroll(machine, makeDevice()); e == nil || e.Error() != "MACHINE_DISABLED" {
		t.Fatal("disabled resurrected", e)
	}
	// Disabled slots retain their denial, but free a seat for replacement hardware.
	if e = enroll(strings.Repeat("c", 64), makeDevice()); e != nil {
		t.Fatal("disabled slot not released", e)
	}
	if e = s.RevokeCode(ctx, c.ID, "", "test", key, trust); e != nil {
		t.Fatal(e)
	}
	if e = enroll(machine, makeDevice()); e == nil || e.Error() != "ACTIVATION_REVOKED" {
		t.Fatal("code revoke ignored", e)
	}
	cfgRaw, e := s.LatestConfig(ctx)
	if e != nil {
		t.Fatal(e)
	}
	signed, e := security.ValidateConfig(map[string]ed25519.PublicKey{"test": pub}, cfgRaw, time.Now())
	if e != nil || len(signed.RevokedDevices) != 51 {
		t.Fatal("complete revocations missing", len(signed.RevokedDevices), e)
	}
	var stored []byte
	if e = s.DB.QueryRow(ctx, "SELECT code_hash FROM activation_codes WHERE id=$1", c.ID).Scan(&stored); e != nil || string(stored) == raw {
		t.Fatal("plaintext credential in DB", e)
	}
	t.Logf("50 freeze replacements: %s; one hardware seat", time.Since(start))
}
func TestActivationIPCodeRateBounds(t *testing.T) {
	now := time.Now()
	l := newEnrollmentLimiter(now)
	for i := 0; i < 60; i++ {
		if !l.allow(now, "nat") {
			t.Fatal("club boot burst rejected", i)
		}
	}
	if l.allow(now, "nat") {
		t.Fatal("rate limit missing")
	}
	if !l.allow(now.Add(time.Second), "nat") {
		t.Fatal("no refill")
	}
}

func TestActivationAdminInventoryPaginationNeverSilentlyTruncates(t *testing.T) {
	s := codeStore(t)
	ctx := context.Background()
	_, e := s.DB.Exec(ctx, `INSERT INTO activation_codes(id,code_hash,kind,seat_limit,name,expires_at) SELECT lpad(to_hex(n),32,'0'),decode(lpad(to_hex(n),64,'0'),'hex'),'personal',2,'fixture',now()+interval '1 hour' FROM generate_series(1,257) n`)
	if e != nil {
		t.Fatal(e)
	}
	count := 0
	cursor := ""
	seen := map[string]bool{}
	for {
		rows, next, e := s.CodesPage(ctx, cursor)
		if e != nil {
			t.Fatal(e)
		}
		if len(rows) > 128 {
			t.Fatal("unbounded page")
		}
		for _, row := range rows {
			if seen[row.ID] {
				t.Fatal("duplicate page row")
			}
			seen[row.ID] = true
			count++
		}
		if next == "" {
			break
		}
		if next <= cursor {
			t.Fatal("nonadvancing cursor")
		}
		cursor = next
	}
	if count != 257 {
		t.Fatal("incomplete code inventory", count)
	}
}
