package controlplane

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"strings"
	"testing"
	"time"

	"github.com/buzzmean/veliq/core/enrollment"
	"github.com/buzzmean/veliq/core/security"
)

func TestTemporaryCodeHashBoundsFreezeAndAtomicBulkRevoke(t *testing.T) {
	s := codeStore(t)
	ctx := context.Background()
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	trust := map[string]string{"fixture": base64.RawURLEncoding.EncodeToString(pub)}
	before := time.Now().UTC()
	code, err := s.CreateTestCode(ctx, "test", "temporary fixture")
	if err != nil {
		t.Fatal(err)
	}
	if code.Kind != "test" || code.Limit != 2 || !strings.HasPrefix(code.Name, "[TEST]") || code.Expires.Before(before.Add(14*24*time.Hour)) || code.Expires.After(time.Now().Add(14*24*time.Hour)) {
		t.Fatal("test bounds")
	}
	hash, _ := enrollment.CodeHash("test")
	var stored []byte
	if err = s.DB.QueryRow(ctx, "SELECT code_hash FROM activation_codes WHERE id=$1", code.ID).Scan(&stored); err != nil || !bytes.Equal(stored, hash) || bytes.Contains(stored, []byte("test")) {
		t.Fatal("hash-only DB", err)
	}
	if _, err = s.CreateTestCode(ctx, "test", "duplicate"); err == nil || err.Error() != "TEST_CODE_ALREADY_EXISTS" {
		t.Fatal("duplicate resurrected")
	}
	if _, err = s.CreateTestCode(ctx, "another", "bad"); err == nil {
		t.Fatal("arbitrary short code accepted")
	}
	if _, _, err = s.CreateCode(ctx, ActivationCode{Kind: "test", Limit: 2, Name: "bad", Expires: time.Now().Add(time.Hour)}); err == nil {
		t.Fatal("ordinary create bypass")
	}
	inventory, err := s.Codes(ctx)
	if err != nil || len(inventory) != 1 || inventory[0].Kind != "test" {
		t.Fatal("test not labeled", err)
	}
	makeDevice := func() Device {
		p, _, _ := ed25519.GenerateKey(rand.Reader)
		id, _ := security.NewID()
		return Device{ID: id, Name: "fixture", PublicKey: base64.RawURLEncoding.EncodeToString(p)}
	}
	enroll := func(machine string, d Device) error {
		return s.EnrollCode(ctx, hash, machine, d, "fixture", key, trust)
	}
	a, b := makeDevice(), makeDevice()
	if err = enroll(strings.Repeat("a", 64), a); err != nil {
		t.Fatal(err)
	}
	replacement := makeDevice()
	if err = enroll(strings.Repeat("a", 64), replacement); err != nil {
		t.Fatal("freeze replacement", err)
	}
	if err = enroll(strings.Repeat("b", 64), b); err != nil {
		t.Fatal(err)
	}
	if err = enroll(strings.Repeat("c", 64), makeDevice()); err == nil || err.Error() != "ACTIVATION_LIMIT" {
		t.Fatal("seat limit", err)
	}
	slots, _ := s.CodeMachines(ctx, code.ID)
	if len(slots) != 2 {
		t.Fatal("freeze consumed seat")
	}
	normal, raw, err := s.CreateCode(ctx, ActivationCode{Kind: "club", Limit: 40, Name: "normal", Expires: time.Now().Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	normalHash, _ := enrollment.CodeHash(raw)
	normalDevice := makeDevice()
	if err = s.EnrollCode(ctx, normalHash, strings.Repeat("a", 64), normalDevice, "fixture", key, trust); err != nil {
		t.Fatal(err)
	}
	if _, err = s.DB.Exec(ctx, `CREATE FUNCTION deny_test_publish() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RAISE EXCEPTION 'isolated injection'; END;$$; CREATE TRIGGER deny_test BEFORE INSERT ON config_versions FOR EACH ROW EXECUTE FUNCTION deny_test_publish()`); err != nil {
		t.Fatal(err)
	}
	if _, err = s.RevokeTestCodes(ctx, "fixture", key, trust); err == nil {
		t.Fatal("publish failure ignored")
	}
	current, _ := s.Device(ctx, replacement.ID)
	if current.Revoked {
		t.Fatal("non-atomic device revoke")
	}
	var revoked bool
	if err = s.DB.QueryRow(ctx, "SELECT revoked FROM activation_codes WHERE id=$1", code.ID).Scan(&revoked); err != nil || revoked {
		t.Fatal("non-atomic code revoke", err)
	}
	s.DB.Exec(ctx, "DROP TRIGGER deny_test ON config_versions")
	// A second pre-existing test row must also be revoked by the single command.
	secondRaw, _ := enrollment.NewCode()
	secondHash, _ := enrollment.CodeHash(secondRaw)
	secondID, _ := security.NewID()
	if _, err = s.DB.Exec(ctx, "INSERT INTO activation_codes(id,code_hash,kind,seat_limit,name,expires_at) VALUES($1,$2,'test',2,'[TEST] second fixture',now()+interval '1 day')", secondID, secondHash); err != nil {
		t.Fatal(err)
	}
	secondDevice := makeDevice()
	if err = s.EnrollCode(ctx, secondHash, strings.Repeat("d", 64), secondDevice, "fixture", key, trust); err != nil {
		t.Fatal(err)
	}
	if n, err := s.RevokeTestCodes(ctx, "fixture", key, trust); err != nil || n != 2 {
		t.Fatal("bulk revoke", n, err)
	}
	for _, d := range []Device{a, b, replacement, secondDevice} {
		v, err := s.Device(ctx, d.ID)
		if err != nil || !v.Revoked {
			t.Fatal("test identity remains valid", err)
		}
	}
	kept, err := s.Device(ctx, normalDevice.ID)
	if err != nil || kept.Revoked {
		t.Fatal("normal identity revoked", err)
	}
	if err = s.DB.QueryRow(ctx, "SELECT revoked FROM activation_codes WHERE id=$1", normal.ID).Scan(&revoked); err != nil || revoked {
		t.Fatal("normal code revoked", err)
	}
	if err = enroll(strings.Repeat("a", 64), makeDevice()); err == nil || err.Error() != "ACTIVATION_REVOKED" {
		t.Fatal("revoked test reactivated")
	}
	if n, err := s.RevokeTestCodes(ctx, "fixture", key, trust); err != nil || n != 0 {
		t.Fatal("repeat revoke", n, err)
	}
	if _, err = s.CreateTestCode(ctx, "test", "resurrect"); err == nil {
		t.Fatal("revoked known credential resurrected")
	}
	cfg, err := s.LatestConfig(ctx)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := security.ValidateConfig(map[string]ed25519.PublicKey{"fixture": pub}, cfg, time.Now())
	if err != nil || len(signed.RevokedDevices) != 4 {
		t.Fatal("complete signed revocations", err)
	}
}

func TestTemporaryCodeMigrationFromSchema2AndExpiry(t *testing.T) {
	s := codeStore(t)
	ctx := context.Background()
	// Recreate the exact schema2 constraint, retaining normal data and security rows.
	_, raw, err := s.CreateCode(ctx, ActivationCode{Kind: "personal", Limit: 2, Name: "before migration", Expires: time.Now().Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.DB.Exec(ctx, `ALTER TABLE activation_codes DROP CONSTRAINT activation_test_bounds; ALTER TABLE activation_codes DROP CONSTRAINT activation_codes_kind_check; ALTER TABLE activation_codes ADD CONSTRAINT activation_codes_kind_check CHECK(kind IN ('club','personal')); DELETE FROM schema_migrations WHERE version=3`); err != nil {
		t.Fatal(err)
	}
	if err = s.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	if err = s.Migrate(ctx); err != nil {
		t.Fatal("idempotent migration", err)
	}
	var n int
	if err = s.DB.QueryRow(ctx, "SELECT count(*) FROM activation_codes").Scan(&n); err != nil || n != 1 {
		t.Fatal("migration lost data", err)
	}
	hash, _ := enrollment.CodeHash(raw)
	var stored []byte
	s.DB.QueryRow(ctx, "SELECT code_hash FROM activation_codes").Scan(&stored)
	if !bytes.Equal(hash, stored) {
		t.Fatal("migration changed normal credential")
	}
	code, err := s.CreateTestCode(ctx, "test", "expiry")
	if err != nil {
		t.Fatal(err)
	}
	for _, query := range []string{"UPDATE activation_codes SET seat_limit=3 WHERE kind='test'", "UPDATE activation_codes SET expires_at=created_at+interval '15 days' WHERE kind='test'"} {
		if _, err = s.DB.Exec(ctx, query); err == nil {
			t.Fatal("DB allowed invalid test bounds")
		}
	}
	if _, err = s.DB.Exec(ctx, "UPDATE activation_codes SET expires_at=now()-interval '1 second' WHERE id=$1", code.ID); err != nil {
		t.Fatal(err)
	}
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	hash, _ = enrollment.CodeHash("test")
	err = s.EnrollCode(ctx, hash, strings.Repeat("a", 64), Device{}, "fixture", key, map[string]string{"fixture": base64.RawURLEncoding.EncodeToString(pub)})
	if err == nil || err.Error() != "ACTIVATION_EXPIRED" {
		t.Fatal("expired test accepted", err)
	}
}
