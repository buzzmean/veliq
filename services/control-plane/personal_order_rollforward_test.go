package controlplane

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type personalRollforwardFixture struct {
	api      *API
	store    *Store
	caller   *call
	provider *personalProviderEmulator
	id, sub  string
	until    time.Time
}

// Represents the persisted result of a pre-014 callback: credit and payment
// status committed, while the newer durable order is still open. Execution of
// the actual older binary is a separate compatibility check.
func newPersonalRollforwardFixture(t *testing.T) personalRollforwardFixture {
	t.Helper()
	api, store, caller, _, sub, _ := personalOrderFixture(t)
	provider := newPersonalProviderEmulator(t, "", nil)
	api.Settings.Payments = provider.provider()
	status, result := caller.do(t, "POST", "/api/v1/account/subscriptions/"+sub+"/pay", personalPayFixture("rollforward-original-key-0001", 3, 113715))
	if status != 200 {
		t.Fatal("initial provider order", status, result)
	}
	id := result["id"].(string)
	until := time.Now().UTC().Add(93 * 24 * time.Hour).Truncate(time.Microsecond)
	ctx := context.Background()
	tx, err := store.DB.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	if _, err = tx.Exec(ctx, "UPDATE payments SET status='succeeded' WHERE id=$1", id); err != nil {
		t.Fatal(err)
	}
	if _, err = tx.Exec(ctx, "UPDATE subscriptions SET paid_until=$2 WHERE id=$1", sub, until); err != nil {
		t.Fatal(err)
	}
	if _, err = tx.Exec(ctx, "INSERT INTO audit_log(actor,action,entity_id) VALUES('payment:platega','payment.succeeded',$1)", sub); err != nil {
		t.Fatal(err)
	}
	if err = tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	return personalRollforwardFixture{api, store, caller, provider, id, sub, until}
}

func (f personalRollforwardFixture) frozen(t *testing.T) string {
	t.Helper()
	var raw string
	if err := f.store.DB.QueryRow(context.Background(), `SELECT jsonb_build_object(
 'payment',to_jsonb(p),'order',to_jsonb(o)-'state','subscription',to_jsonb(s),
 'reviews',(SELECT jsonb_agg(to_jsonb(e) ORDER BY e.id) FROM payment_review_events e WHERE e.payment_id=p.id),
 'credits',(SELECT count(*) FROM audit_log WHERE action='payment.succeeded' AND entity_id=s.id))::text
 FROM payments p JOIN personal_payment_orders o ON o.payment_id=p.id
 JOIN subscriptions s ON s.id=p.subscription_id WHERE p.id=$1`, f.id).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	return raw
}

func (f personalRollforwardFixture) state(t *testing.T) string {
	t.Helper()
	var state string
	if err := f.store.DB.QueryRow(context.Background(), "SELECT state FROM personal_payment_orders WHERE payment_id=$1", f.id).Scan(&state); err != nil {
		t.Fatal(err)
	}
	return state
}

func (f personalRollforwardFixture) callback(t *testing.T, status, secret, sub string, amount json.Number) int {
	t.Helper()
	body, err := json.Marshal(map[string]any{"id": "personal-fixture-tx-1", "status": status, "amount": amount, "currency": "RUB", "paymentMethod": 2, "payload": plategaPayloadPrefix + sub})
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest("POST", "/api/v1/payments/webhook", strings.NewReader(string(body)))
	r.Header.Set("X-MerchantId", "merchant-1")
	r.Header.Set("X-Secret", secret)
	w := httptest.NewRecorder()
	f.api.paymentWebhook(w, r)
	return w.Code
}

func TestPersonalOrderOldCallbackReplayCompletesTrackingWithoutCredit(t *testing.T) {
	f := newPersonalRollforwardFixture(t)
	before := f.frozen(t)
	for _, invalid := range []struct {
		secret, sub string
		amount      json.Number
	}{{"wrong-secret", f.sub, "1137.15"}, {"test-secret", f.sub, "1137"}, {"test-secret", strings.Repeat("f", 32), "1137.15"}} {
		if code := f.callback(t, "CONFIRMED", invalid.secret, invalid.sub, invalid.amount); code != 400 || f.state(t) != "open" || f.frozen(t) != before {
			t.Fatal("unverified callback changed a known order", code)
		}
	}
	ctx := context.Background()
	if code := f.callback(t, "CONFIRMED", "test-secret", f.sub, "1137.15"); code != 200 || f.state(t) != "consumed" || f.frozen(t) != before {
		t.Fatal("authenticated replay changed credit or did not complete tracking", code)
	}
	for _, status := range []string{"succeeded", "succeeded", "canceled", "pending"} {
		until, extended, err := f.store.RecordProviderPayment(ctx, "platega", "personal-fixture-tx-1", f.sub, 113715, status, "payment:platega", time.Now())
		if err != nil || extended || !until.Equal(f.until) || f.state(t) != "consumed" || f.frozen(t) != before {
			t.Fatal("replay changed credit or frozen terms", status, until, extended, err)
		}
	}
	if status, result := f.caller.do(t, "POST", "/api/v1/account/subscriptions/"+f.sub+"/pay", personalPayFixture("rollforward-original-key-0001", 3, 113715)); status != 200 || result["id"] != f.id || result["status"] != "succeeded" || result["redirect"] != nil || f.provider.creates.Load() != 1 {
		t.Fatal("original key created a new payment", status, result)
	}
	for _, query := range []string{
		"UPDATE payments SET amount_kopecks=1 WHERE id=$1",
		"UPDATE payments SET period_days=1 WHERE id=$1",
		"UPDATE payments SET provider='other' WHERE id=$1",
		"UPDATE payments SET reference='changed' WHERE id=$1",
		"UPDATE personal_payment_orders SET snapshot='{}' WHERE payment_id=$1",
		"UPDATE personal_payment_orders SET state='open' WHERE payment_id=$1",
	} {
		if _, err := f.store.DB.Exec(ctx, query, f.id); err == nil {
			t.Fatal("rollforward removed immutable protection", query)
		}
	}
	if err := f.store.AttachPersonalPayment(ctx, f.id, "platega", "different-provider-id", ""); err == nil || f.frozen(t) != before {
		t.Fatal("rollforward allowed rebinding or changed frozen state", err)
	}
}

func TestPersonalOrderOldCallbackNextReservationWithAndWithoutReplay(t *testing.T) {
	for _, replay := range []bool{false, true} {
		t.Run(fmt.Sprintf("concurrent_replay_%t", replay), func(t *testing.T) {
			f := newPersonalRollforwardFixture(t)
			before := f.frozen(t)
			var wg sync.WaitGroup
			var accepted atomic.Int64
			start := make(chan struct{})
			for i := range 12 {
				wg.Add(1)
				go func(i int) {
					defer wg.Done()
					<-start
					caller := &call{api: f.api, cookie: f.caller.cookie}
					status, result := caller.do(t, "POST", "/api/v1/account/subscriptions/"+f.sub+"/pay", personalPayFixture(fmt.Sprintf("rollforward-next-key-%016d", i), 1, 39900))
					if status == 200 {
						accepted.Add(1)
					} else if status != 409 || result["error"] != "PAYMENT_IN_PROGRESS" {
						t.Error("next reservation", status, result)
					}
				}(i)
			}
			if replay {
				wg.Add(1)
				go func() {
					defer wg.Done()
					<-start
					for range 4 {
						until, extended, err := f.store.RecordProviderPayment(context.Background(), "platega", "personal-fixture-tx-1", f.sub, 113715, "succeeded", "payment:platega", time.Now())
						if err != nil || extended || !until.Equal(f.until) {
							t.Error("concurrent replay", until, extended, err)
						}
					}
				}()
			}
			close(start)
			wg.Wait()
			var open, consumed int
			if err := f.store.DB.QueryRow(context.Background(), "SELECT count(*) FILTER(WHERE state='open'),count(*) FILTER(WHERE state='consumed') FROM personal_payment_orders").Scan(&open, &consumed); err != nil || open != 1 || consumed != 1 || accepted.Load() != 1 || f.provider.creates.Load() != 2 || f.frozen(t) != before {
				t.Fatal("old credit or next creation duplicated", open, consumed, accepted.Load(), f.provider.creates.Load(), err)
			}
		})
	}
}

func TestPersonalOrderRollforwardDoesNotReleaseUnresolvedOrReviewedOrders(t *testing.T) {
	for _, kind := range []string{"pending", "canceled", "DISPUTED", "CHARGEBACKED", "PARTIALLY_REFUNDED", "unknown-provider-id", "foreign-owner"} {
		t.Run(kind, func(t *testing.T) {
			f := newPersonalRollforwardFixture(t)
			ctx := context.Background()
			switch kind {
			case "pending", "canceled":
				if _, err := f.store.DB.Exec(ctx, "UPDATE payments SET status=$2 WHERE id=$1", f.id, kind); err != nil {
					t.Fatal(err)
				}
			case "unknown-provider-id":
				if _, err := f.store.DB.Exec(ctx, "UPDATE payments SET provider_payment_id='reservation:'||id WHERE id=$1", f.id); err != nil {
					t.Fatal(err)
				}
			case "foreign-owner":
				// Simulate an inconsistent historical owner binding without
				// weakening the production immutable trigger.
				if _, err := f.store.DB.Exec(ctx, "INSERT INTO accounts(id,email) VALUES('foreign-owner','foreign@example.test')"); err != nil {
					t.Fatal(err)
				}
				if _, err := f.store.DB.Exec(ctx, "UPDATE subscriptions SET account_id='foreign-owner' WHERE id=$1", f.sub); err != nil {
					t.Fatal(err)
				}
			default:
				if _, err := f.store.DB.Exec(ctx, "INSERT INTO payment_review_events(payment_id,provider_status,refunded_kopecks) VALUES($1,$2,395)", f.id, kind); err != nil {
					t.Fatal(err)
				}
			}
			before := f.frozen(t)
			if kind == "foreign-owner" {
				var account string
				if err := f.store.DB.QueryRow(ctx, "SELECT account_id FROM personal_payment_orders WHERE payment_id=$1", f.id).Scan(&account); err != nil {
					t.Fatal(err)
				}
				tx, err := f.store.DB.Begin(ctx)
				if err != nil {
					t.Fatal(err)
				}
				defer tx.Rollback(ctx)
				if _, err = tx.Exec(ctx, "SELECT id FROM accounts WHERE id=$1 FOR NO KEY UPDATE", account); err != nil {
					t.Fatal(err)
				}
				blocked, err := unresolvedPersonalPayment(ctx, tx, account)
				if err != nil || !blocked {
					t.Fatal("foreign order normalized", blocked, err)
				}
				if err = tx.Commit(ctx); err != nil {
					t.Fatal(err)
				}
			} else if status, result := f.caller.do(t, "POST", "/api/v1/account/subscriptions/"+f.sub+"/pay", personalPayFixture("rollforward-must-stay-blocked", 1, 39900)); status != 409 || result["error"] != "PAYMENT_IN_PROGRESS" {
				t.Fatal("unresolved order released", status, result)
			}
			if kind != "pending" && kind != "canceled" && kind != "unknown-provider-id" {
				if _, extended, err := f.store.RecordProviderPayment(ctx, "platega", "personal-fixture-tx-1", f.sub, 113715, "succeeded", "payment:platega", time.Now()); err != nil || extended {
					t.Fatal("guarded replay", extended, err)
				}
			}
			if f.state(t) != "open" || f.frozen(t) != before || f.provider.creates.Load() != 1 {
				t.Fatal("unresolved/reviewed order changed or another charge created")
			}
		})
	}
}

func TestPersonalOrderRollforwardReservationCommitFailureKeepsTrackingAtomic(t *testing.T) {
	f := newPersonalRollforwardFixture(t)
	before := f.frozen(t)
	ctx := context.Background()
	if _, err := f.store.DB.Exec(ctx, `CREATE FUNCTION reject_rollforward_reservation() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'fixture commit failure'; END $$;
 CREATE CONSTRAINT TRIGGER reject_rollforward_reservation AFTER INSERT ON personal_payment_orders DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION reject_rollforward_reservation()`); err != nil {
		t.Fatal(err)
	}
	path := "/api/v1/account/subscriptions/" + f.sub + "/pay"
	request := personalPayFixture("rollforward-atomic-next-key", 1, 39900)
	if status, result := f.caller.do(t, "POST", path, request); status != 503 || result["error"] != "ACCOUNT_UNAVAILABLE" || f.state(t) != "open" || f.provider.creates.Load() != 1 || f.frozen(t) != before {
		t.Fatal("failed reservation partially committed", status, result)
	}
	if _, err := f.store.DB.Exec(ctx, "DROP TRIGGER reject_rollforward_reservation ON personal_payment_orders"); err != nil {
		t.Fatal(err)
	}
	if status, result := f.caller.do(t, "POST", path, request); status != 200 || f.state(t) != "consumed" || f.provider.creates.Load() != 2 || f.frozen(t) != before {
		t.Fatal("safe retry failed after rolled-back reservation", status, result)
	}
}
