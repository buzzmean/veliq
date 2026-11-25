package controlplane

import (
	"context"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

func TestPersonalSubscriptionConcurrentCreateReusesOne(t *testing.T) {
	for _, isolation := range []string{"read committed", "repeatable read"} {
		t.Run(isolation, func(t *testing.T) {
			api, store, mailer := accountAPI(t, false)
			config := store.DB.Config()
			config.ConnConfig.RuntimeParams["default_transaction_isolation"] = isolation
			ctx := context.Background()
			pool, err := pgxpool.NewWithConfig(ctx, config)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(pool.Close)
			store = &Store{pool}
			api.Store = store
			client := &call{api: api}
			login(t, client, mailer, "one-subscription@example.com")
			account, err := store.SessionAccount(ctx, client.cookie, time.Now())
			if err != nil {
				t.Fatal(err)
			}
			plan := api.Settings.Plans[0]
			observer := accountLockObserver(t, store)
			barrier, err := observer.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer barrier.Rollback(ctx)
			if _, err = barrier.Exec(ctx, "SELECT id FROM accounts WHERE id=$1 FOR UPDATE", account.ID); err != nil {
				t.Fatal(err)
			}
			type attempt struct {
				id  string
				err error
			}
			const parallel = 4
			results := make(chan attempt, parallel)
			for range parallel {
				go func() {
					id, err := store.CreateSubscription(ctx, account, plan, 1)
					results <- attempt{id, err}
				}()
			}
			waitAccountLocks(t, observer, []string{"SELECT id,account_type FROM accounts%FOR NO KEY UPDATE"}, parallel, nil)
			if err = barrier.Commit(ctx); err != nil {
				t.Fatal(err)
			}
			var id string
			for range parallel {
				result := <-results
				if result.err != nil || result.id == "" {
					t.Fatal("create personal", result.err, result.id)
				}
				if id == "" {
					id = result.id
				}
				if result.id != id {
					t.Fatal("concurrent personal requests created different subscriptions")
				}
			}
			status, result := client.do(t, "POST", "/api/v1/account/subscriptions", map[string]any{"plan_id": plan.ID, "seats": 1})
			if status != http.StatusCreated || result["id"] != id {
				t.Fatal("authenticated retry did not reuse personal subscription", status, result)
			}
			var subscriptions, codes int
			if err = pool.QueryRow(ctx, `
SELECT (SELECT count(*) FROM subscriptions WHERE account_id=$1),
       (SELECT count(*) FROM activation_codes WHERE subscription_id=$2)`, account.ID, id).Scan(&subscriptions, &codes); err != nil || subscriptions != 1 || codes != 1 {
				t.Fatal("expected one subscription and one activation code", err, subscriptions, codes)
			}
		})
	}
}

func TestPersonalSubscriptionLegacyRightsSurviveCreateConflict(t *testing.T) {
	api, store, mailer := accountAPI(t, true)
	provider := &failingPromoProvider{failure: context.Canceled}
	api.Settings.Payments = provider
	client := &call{api: api}
	login(t, client, mailer, "legacy-rights@example.com")
	ctx := context.Background()
	account, err := store.SessionAccount(ctx, client.cookie, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	plan := api.Settings.Plans[0]
	const subscriptionsPath = "/api/v1/account/subscriptions"
	request := map[string]any{"plan_id": plan.ID, "seats": 1}
	status, result := client.do(t, "POST", subscriptionsPath, request)
	if status != http.StatusCreated {
		t.Fatal("create legacy fixture", status, result)
	}
	permanentID := result["id"].(string)
	if _, err = store.DB.Exec(ctx, "UPDATE subscriptions SET lifetime=true WHERE id=$1", permanentID); err != nil {
		t.Fatal(err)
	}
	status, result = client.do(t, "POST", subscriptionsPath+"/"+permanentID+"/code", map[string]any{})
	if status != http.StatusOK {
		t.Fatal("issue code for existing permanent right", status, result)
	}
	enrollWith(t, api, store, result["code"].(string), strings.Repeat("a", 64))
	const paidID = "legacy-paid-right"
	if _, err = store.DB.Exec(ctx, "INSERT INTO subscriptions(id,account_id,plan_id,kind,seats) VALUES($1,$2,$3,'player',1)", paidID, account.ID, plan.ID); err != nil {
		t.Fatal(err)
	}
	if _, extended, err := store.RecordPayment(ctx, paidID, "manual", "fixture-paid", 30000, 30, "succeeded", "test", "test", time.Now()); err != nil || !extended {
		t.Fatal("seed legacy paid access", err, extended)
	}
	beforeStatus, before := client.do(t, "GET", "/api/v1/account", nil)
	if beforeStatus != http.StatusOK || len(before["subscriptions"].([]any)) != 2 || len(before["payments"].([]any)) != 1 {
		t.Fatal("legacy fixture", beforeStatus)
	}
	status, result = client.do(t, "POST", subscriptionsPath, request)
	if status != http.StatusConflict || result["error"] != "PERSONAL_SUBSCRIPTION_CONFLICT" {
		t.Fatal("creation should flag existing distinct rights", status, result["error"])
	}
	for _, action := range []string{"quote", "pay"} {
		status, result = client.do(t, "POST", subscriptionsPath+"/"+permanentID+"/"+action, map[string]int{"months": 1})
		if status != http.StatusConflict || result["error"] != "PAYMENT_NOT_REQUIRED" {
			t.Fatal("lifetime payment protection", action, status, result["error"])
		}
	}
	afterStatus, after := client.do(t, "GET", "/api/v1/account", nil)
	if afterStatus != http.StatusOK || !reflect.DeepEqual(before["subscriptions"], after["subscriptions"]) ||
		!reflect.DeepEqual(before["payments"], after["payments"]) || provider.calls.Load() != 0 {
		t.Fatal("legacy rights, devices, or payments changed after rejected creation")
	}
}
