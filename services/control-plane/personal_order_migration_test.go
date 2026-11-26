package controlplane

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/buzzmean/veliq/core/security"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestPersonalOrderMigration13To14PreservesFinancialRightsAndDiagnostics(t *testing.T) {
	base := codeStore(t)
	ctx := context.Background()
	id, _ := security.NewID()
	schema := "personal_schema13_" + id
	if _, err := base.DB.Exec(ctx, "CREATE SCHEMA "+schema); err != nil {
		t.Fatal(err)
	}
	config := base.DB.Config()
	config.ConnConfig.RuntimeParams["search_path"] = schema
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pool.Close(); base.DB.Exec(context.Background(), "DROP SCHEMA "+schema+" CASCADE") })
	entries, err := migrations.ReadDir("migrations")
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if entry.Name() > "013_persistent_club_health.sql" {
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
	const seed = `
INSERT INTO activation_policy(singleton,hardware_salt) VALUES(true,decode(repeat('33',32),'hex'));
INSERT INTO accounts(id,email,account_type) VALUES(repeat('a',32),'legacy-finance@example.test','player');
INSERT INTO subscriptions(id,account_id,plan_id,kind,seats,paid_until,lifetime)
 VALUES(repeat('b',32),repeat('a',32),'old-personal-plan','player',1,now()+interval '30 days',false),
       (repeat('c',32),repeat('a',32),'old-perpetual-plan','player',1,NULL,true);
INSERT INTO devices(id,user_id,name,public_key)
 VALUES(repeat('d',32),'owner','Fixture-paid','fixture-public-paid'),(repeat('e',32),'owner','Fixture-perpetual','fixture-public-perpetual');
INSERT INTO activation_codes(id,code_hash,kind,seat_limit,name,expires_at,subscription_id)
 VALUES('fixture-code-paid',decode(repeat('11',32),'hex'),'personal',1,'Fixture paid',now()+interval '20 years',repeat('b',32)),
       ('fixture-code-perpetual',decode(repeat('22',32),'hex'),'personal',1,'Fixture perpetual',now()+interval '20 years',repeat('c',32));
INSERT INTO activation_slots(code_id,machine_hash,device_id)
 VALUES('fixture-code-paid',repeat('1',64),repeat('d',32)),('fixture-code-perpetual',repeat('2',64),repeat('e',32));
INSERT INTO account_device_bindings(device_id,subscription_id) VALUES(repeat('d',32),repeat('b',32)),(repeat('e',32),repeat('c',32));
INSERT INTO payments(id,subscription_id,provider,provider_payment_id,amount_kopecks,period_days,status,reference)
 VALUES(repeat('f',32),repeat('b',32),'platega','fixture-historical-provider-id',399,30,'succeeded','historical-terms-preserved');
INSERT INTO payment_review_events(payment_id,provider_status,refund_id,refund_status,refunded_kopecks)
 VALUES(repeat('f',32),'PARTIALLY_REFUNDED','fixture-refund','Succeeded',395);
INSERT INTO club_health_persistent_devices(device_id,account_id,pc,software_version,source)
 VALUES(repeat('d',32),repeat('a',32),'PC13','0.3.792','fixture');`
	if _, err = pool.Exec(ctx, seed); err != nil {
		t.Fatal(err)
	}
	event := persistentFixtureBatch("PC13").Events[0]
	raw, _ := json.Marshal(event)
	if _, err = pool.Exec(ctx, `INSERT INTO club_health_persistent_events(device_id,event_id,account_id,observed_at,summary)
 VALUES(repeat('d',32),$1,repeat('a',32),$2,$3)`, event.ID, event.At, raw); err != nil {
		t.Fatal(err)
	}
	store := &Store{pool}
	snapshot := func() string {
		t.Helper()
		var out string
		if err := pool.QueryRow(ctx, `SELECT jsonb_build_object(
 'subscriptions',(SELECT jsonb_agg(to_jsonb(t) ORDER BY id) FROM subscriptions t),
 'payments',(SELECT jsonb_agg(to_jsonb(t) ORDER BY id) FROM payments t),
 'reviews',(SELECT jsonb_agg(to_jsonb(t) ORDER BY id) FROM payment_review_events t),
 'devices',(SELECT jsonb_agg(to_jsonb(t) ORDER BY id) FROM devices t),
 'codes',(SELECT jsonb_agg(to_jsonb(t) ORDER BY id) FROM activation_codes t),
 'slots',(SELECT jsonb_agg(to_jsonb(t) ORDER BY code_id,machine_hash) FROM activation_slots t),
 'bindings',(SELECT jsonb_agg(to_jsonb(t) ORDER BY device_id) FROM account_device_bindings t),
 'policy',(SELECT jsonb_agg(to_jsonb(t)) FROM activation_policy t),
 'health_devices',(SELECT jsonb_agg(to_jsonb(t) ORDER BY device_id) FROM club_health_persistent_devices t),
 'health_events',(SELECT jsonb_agg(to_jsonb(t) ORDER BY event_id) FROM club_health_persistent_events t))::text`).Scan(&out); err != nil {
			t.Fatal(err)
		}
		return out
	}
	before := snapshot()
	paid, err := store.DeviceEntitlement(ctx, strings.Repeat("d", 32))
	if err != nil || paid.Until.IsZero() {
		t.Fatal("schema13 paid fixture unavailable", err)
	}
	for range 2 {
		if err = store.Migrate(ctx); err != nil || snapshot() != before {
			t.Fatal("additive migration rewrote financial, access or C03 data", err)
		}
	}
	after, err := store.DeviceEntitlement(ctx, strings.Repeat("d", 32))
	perpetual, perpetualErr := store.DeviceEntitlement(ctx, strings.Repeat("e", 32))
	if err != nil || perpetualErr != nil || after != paid || !perpetual.Lifetime {
		t.Fatal("migration changed active/lifetime entitlement", err, perpetualErr)
	}
	var version, orders int
	var diagnosticsSupported bool
	if err = pool.QueryRow(ctx, `SELECT (SELECT max(version) FROM schema_migrations),
 EXISTS(SELECT 1 FROM schema_migrations WHERE version=13),(SELECT count(*) FROM personal_payment_orders)`).Scan(&version, &diagnosticsSupported, &orders); err != nil || version != 14 || !diagnosticsSupported || orders != 0 {
		t.Fatal("schema13 contract or clean additive order table missing", version, orders, err)
	}
}
