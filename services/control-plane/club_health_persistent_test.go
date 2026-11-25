package controlplane

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/buzzmean/veliq/core/clubhealth"
	"github.com/buzzmean/veliq/core/security"
	"github.com/jackc/pgx/v5/pgxpool"
)

func persistentDeviceFixture(t *testing.T, s *Store, pc string) (string, string, ed25519.PrivateKey) {
	t.Helper()
	ctx := context.Background()
	owner, _ := security.NewID()
	if _, err := s.DB.Exec(ctx, "INSERT INTO accounts(id,email) VALUES($1,$2)", owner, owner+"@example.test"); err != nil {
		t.Fatal(err)
	}
	sub, err := s.CreateSubscription(ctx, Account{ID: owner}, Plan{ID: "player", Kind: "player", MaxSeats: 1}, 1)
	if err != nil {
		t.Fatal(err)
	}
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	id, _ := security.NewID()
	if err = s.Register(ctx, Device{ID: id, Name: pc, PublicKey: base64.RawURLEncoding.EncodeToString(pub)}); err != nil {
		t.Fatal(err)
	}
	if _, err = s.DB.Exec(ctx, "INSERT INTO account_device_bindings(device_id,subscription_id) VALUES($1,$2)", id, sub); err != nil {
		t.Fatal(err)
	}
	if _, err = s.DB.Exec(ctx, `INSERT INTO activation_slots(code_id,machine_hash,device_id)
		SELECT id,$2,$3 FROM activation_codes WHERE subscription_id=$1`, sub, strings.Repeat("a", 64), id); err != nil {
		t.Fatal(err)
	}
	return owner, id, key
}
func persistentFixtureBatch(pc string) clubhealth.Batch {
	id, _ := security.NewID()
	session, _ := security.NewID()
	return clubhealth.Batch{Protocol: 1, Events: []clubhealth.Diagnostic{{ID: id, At: time.Now().UTC(), PC: pc, Version: "0.3.736", Source: "fixture", Session: session,
		Observer: "WINDOWS_EVENT_LOG", Component: "TLS", State: "observed", Code: "SCHANNEL_EVENT", NativeCode: 0x80092013, EventID: 36876}}}
}
func TestPersistentIngestionProofDedupOwnershipAndRetention(t *testing.T) {
	a, s, _ := accountAPI(t, true)
	ctx := context.Background()
	owner, device, key := persistentDeviceFixture(t, s, "PC13")
	other, _, _ := persistentDeviceFixture(t, s, "PC14")
	b := persistentFixtureBatch("PC13")
	proof, _ := security.NewProof(device, b.Audience(), key, time.Now())
	q := clubhealth.PersistentRequest{Batch: b, Proof: proof}
	call := func(q clubhealth.PersistentRequest) (int, clubhealth.Receipt) {
		raw, _ := json.Marshal(q)
		r := httptest.NewRequest("POST", clubhealth.PersistentEndpoint, bytes.NewReader(raw))
		w := httptest.NewRecorder()
		a.Handler().ServeHTTP(w, r)
		var receipt clubhealth.Receipt
		_ = json.Unmarshal(w.Body.Bytes(), &receipt)
		return w.Code, receipt
	}
	if status, ack := call(q); status != 200 || !ack.Accepts(b) {
		t.Fatalf("durable ACK: %d %+v", status, ack)
	}
	if status, _ := call(q); status != 401 {
		t.Fatalf("replay accepted: %d", status)
	}
	q.Proof, _ = security.NewProof(device, b.Audience(), key, time.Now())
	if status, ack := call(q); status != 200 || !ack.Accepts(b) {
		t.Fatalf("retry: %d", status)
	}
	var count int
	if err := s.DB.QueryRow(ctx, "SELECT count(*) FROM club_health_persistent_events WHERE device_id=$1", device).Scan(&count); err != nil || count != 1 {
		t.Fatal("duplicate", count, err)
	}
	view, err := s.PersistentDiagnosticsView(ctx, owner, "PC13")
	if err != nil || !bytes.Contains(view, []byte("PC13")) || !bytes.Contains(view, []byte("0.3.736")) {
		t.Fatal("owner view", string(view), err)
	}
	view, err = s.PersistentDiagnosticsView(ctx, other, "PC13")
	if err != nil || bytes.Contains(view, []byte("SCHANNEL_EVENT")) {
		t.Fatal("cross-owner disclosure", string(view), err)
	}
	changed := q
	changed.Batch = persistentFixtureBatch("PC14")
	if status, _ := call(changed); status != 400 {
		t.Fatal("payload not bound", status)
	}
	// A gap is recorded by the independent receipt clock, without a cause claim.
	if _, err = s.DB.Exec(ctx, "UPDATE club_health_persistent_devices SET last_seen=now()-interval '5 minutes' WHERE device_id=$1", device); err != nil {
		t.Fatal(err)
	}
	if err = s.PrunePersistentDiagnostics(ctx); err != nil {
		t.Fatal(err)
	}
	q.Proof, _ = security.NewProof(device, b.Audience(), key, time.Now())
	if status, _ := call(q); status != 200 {
		t.Fatal("recovery", status)
	}
	if err = s.DB.QueryRow(ctx, "SELECT count(*) FROM club_health_persistent_events WHERE device_id=$1 AND summary->>'component'='HEARTBEAT'", device).Scan(&count); err != nil || count != 2 {
		t.Fatal("gap/recovery pair", count, err)
	}
	if _, err = s.DB.Exec(ctx, "UPDATE club_health_persistent_events SET observed_at=now()-interval '15 days' WHERE device_id=$1", device); err != nil {
		t.Fatal(err)
	}
	if err = s.PrunePersistentDiagnostics(ctx); err != nil {
		t.Fatal(err)
	}
	if err = s.DB.QueryRow(ctx, "SELECT count(*) FROM club_health_persistent_events WHERE device_id=$1", device).Scan(&count); err != nil || count != 0 {
		t.Fatal("retention", count, err)
	}
	if err = s.Revoke(ctx, device); err != nil {
		t.Fatal(err)
	}
	q.Proof, _ = security.NewProof(device, b.Audience(), key, time.Now())
	if status, _ := call(q); status != 401 {
		t.Fatal("revoked device", status)
	}
}
func TestPersistentMigration8To13PreservesIdentity(t *testing.T) {
	base := codeStore(t)
	ctx := context.Background()
	id, _ := security.NewID()
	schema := "diagnostics_schema8_" + id
	if _, err := base.DB.Exec(ctx, "CREATE SCHEMA "+schema); err != nil {
		t.Fatal(err)
	}
	cfg := base.DB.Config()
	cfg.ConnConfig.RuntimeParams["search_path"] = schema
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pool.Close(); base.DB.Exec(context.Background(), "DROP SCHEMA "+schema+" CASCADE") })
	entries, err := migrations.ReadDir("migrations")
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if entry.Name() > "008_promotions.sql" {
			continue
		}
		raw, err := migrations.ReadFile("migrations/" + entry.Name())
		if err != nil {
			t.Fatal(err)
		}
		if _, err = pool.Exec(ctx, string(raw)); err != nil {
			t.Fatal(entry.Name(), err)
		}
	}
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	store := &Store{pool}
	key := base64.RawURLEncoding.EncodeToString(pub)
	if err = store.Register(ctx, Device{ID: id, Name: "PC13", PublicKey: key}); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err = store.Migrate(ctx); err != nil {
			t.Fatal("8 to 13", err)
		}
	}
	var version int
	if err = pool.QueryRow(ctx, "SELECT max(version) FROM schema_migrations").Scan(&version); err != nil || version != 13 {
		t.Fatal(version, err)
	}
	d, err := store.Device(ctx, id)
	if err != nil || d.PublicKey != key || d.Revoked {
		t.Fatal("identity changed", err)
	}
	var cabinet bool
	if err = pool.QueryRow(ctx, "SELECT to_regclass('device_details') IS NOT NULL").Scan(&cabinet); err != nil || !cabinet {
		t.Fatal("cabinet migration missing", err)
	}
}
func TestPersistentQuotaAndNoAckOnRolledBackStorage(t *testing.T) {
	a, s, _ := accountAPI(t, true)
	ctx := context.Background()
	_, id, key := persistentDeviceFixture(t, s, "PC13")
	b := persistentFixtureBatch("PC13")
	proof, _ := security.NewProof(id, b.Audience(), key, time.Now())
	q := clubhealth.PersistentRequest{Batch: b, Proof: proof}
	if err := s.RecordPersistentDiagnostics(ctx, q); err != nil {
		t.Fatal(err)
	}
	var owner string
	if err := s.DB.QueryRow(ctx, "SELECT account_id FROM club_health_persistent_devices WHERE device_id=$1", id).Scan(&owner); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.Exec(ctx, `INSERT INTO club_health_persistent_events(device_id,event_id,account_id,observed_at,summary)
		SELECT $1,md5(n::text),$2,now()-interval '1 hour','{}' FROM generate_series(1,8200) n ON CONFLICT DO NOTHING`, id, owner); err != nil {
		t.Fatal(err)
	}
	q.Proof, _ = security.NewProof(id, b.Audience(), key, time.Now())
	if err := s.RecordPersistentDiagnostics(ctx, q); err != nil {
		t.Fatal(err)
	}
	var count int
	if err := s.DB.QueryRow(ctx, "SELECT count(*) FROM club_health_persistent_events WHERE device_id=$1", id).Scan(&count); err != nil || count > clubhealth.ServerDeviceEvents {
		t.Fatal("quota", count, err)
	}
	if _, err := s.DB.Exec(ctx, "UPDATE club_health_persistent_devices SET last_seen=now()-interval '5 minutes' WHERE device_id=$1", id); err != nil {
		t.Fatal(err)
	}
	if err := s.PrunePersistentDiagnostics(ctx); err != nil {
		t.Fatal(err)
	}
	if err := s.DB.QueryRow(ctx, "SELECT count(*) FROM club_health_persistent_events WHERE device_id=$1", id).Scan(&count); err != nil || count != clubhealth.ServerDeviceEvents {
		t.Fatal("background gap exceeds quota", count, err)
	}
	// Trigger aborts INSERT after proof consumption; transaction must roll back.
	if _, err := s.DB.Exec(ctx, `CREATE FUNCTION diagnostic_fixture_reject() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'fixture storage failure'; END $$;
		CREATE TRIGGER diagnostic_fixture_reject BEFORE INSERT ON club_health_persistent_events FOR EACH ROW EXECUTE FUNCTION diagnostic_fixture_reject()`); err != nil {
		t.Fatal(err)
	}
	b = persistentFixtureBatch("PC13")
	q.Batch = b
	q.Proof, _ = security.NewProof(id, b.Audience(), key, time.Now())
	raw, _ := json.Marshal(q)
	r := httptest.NewRequest("POST", clubhealth.PersistentEndpoint, bytes.NewReader(raw))
	w := httptest.NewRecorder()
	a.Handler().ServeHTTP(w, r)
	if w.Code != 503 || strings.Contains(w.Body.String(), `"committed":true`) {
		t.Fatal("failed transaction ACKed", w.Code, w.Body.String())
	}
	if _, err := s.DB.Exec(ctx, "DROP TRIGGER diagnostic_fixture_reject ON club_health_persistent_events"); err != nil {
		t.Fatal(err)
	}
	// The exact proof still works: the failed transaction did not consume it.
	if err := s.RecordPersistentDiagnostics(ctx, q); err != nil {
		t.Fatal(fmt.Errorf("rollback retained proof: %w", err))
	}
}

func TestPersistentLegacySlotOwnerAndAmbiguousOwners(t *testing.T) {
	_, s, _ := accountAPI(t, true)
	ctx := context.Background()
	owner, device, key := persistentDeviceFixture(t, s, "PC13")
	other, otherDevice, _ := persistentDeviceFixture(t, s, "PC_OTHER")
	if _, err := s.DB.Exec(ctx, "DELETE FROM account_device_bindings WHERE device_id=$1", device); err != nil {
		t.Fatal(err)
	}
	b := persistentFixtureBatch("PC13")
	proof, _ := security.NewProof(device, b.Audience(), key, time.Now())
	q := clubhealth.PersistentRequest{Batch: b, Proof: proof}
	if err := s.RecordPersistentDiagnostics(ctx, q); err != nil {
		t.Fatal("legacy activation excluded", err)
	}
	view, err := s.PersistentDiagnosticsView(ctx, owner, "PC13")
	if err != nil || !bytes.Contains(view, []byte("SCHANNEL_EVENT")) {
		t.Fatal("legacy view", err)
	}
	view, err = s.PersistentDiagnosticsView(ctx, other, "PC13")
	if err != nil || bytes.Contains(view, []byte("SCHANNEL_EVENT")) {
		t.Fatal("legacy disclosure", err)
	}
	if _, err := s.DB.Exec(ctx, `INSERT INTO activation_slots(code_id,machine_hash,device_id)
	 SELECT code_id,$2,$1 FROM activation_slots WHERE device_id=$3`, device, strings.Repeat("b", 64), otherDevice); err != nil {
		t.Fatal(err)
	}
	q.Proof, _ = security.NewProof(device, b.Audience(), key, time.Now())
	if err := s.RecordPersistentDiagnostics(ctx, q); !errors.Is(err, errDiagnosticOwner) {
		t.Fatal("ambiguous owner accepted", err)
	}
	for _, account := range []string{owner, other} {
		view, err = s.PersistentDiagnosticsView(ctx, account, "PC13")
		if err != nil || bytes.Contains(view, []byte("SCHANNEL_EVENT")) {
			t.Fatal("ambiguous history disclosed", err)
		}
	}
}
