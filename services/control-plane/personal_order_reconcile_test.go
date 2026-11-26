package controlplane

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestPersonalOrderReconciliationChecksProviderOwnershipAndNeverRecreates(t *testing.T) {
	api, store, caller, _, sub, _ := personalOrderFixture(t)
	provider := newPersonalProviderEmulator(t, "error", nil)
	api.Settings.Payments = provider.provider()
	path := "/api/v1/account/subscriptions/" + sub + "/pay"
	request := personalPayFixture("personal-reconcile-key-0001", 1, 39900)
	if status, result := caller.do(t, "POST", path, request); status != 409 || result["error"] != "PAYMENT_RECONCILIATION_REQUIRED" {
		t.Fatal(status, result)
	}
	ctx := context.Background()
	var id string
	if err := store.DB.QueryRow(ctx, "SELECT payment_id FROM personal_payment_orders").Scan(&id); err != nil {
		t.Fatal(err)
	}
	const txID = "personal-fixture-tx-1"
	reconcile := map[string]any{"payment_id": id, "provider_payment_id": txID}
	admin := func(r *http.Request) { r.Header.Set("Authorization", "Bearer "+strings.Repeat("a", 32)) }
	if status, _ := caller.do(t, "POST", "/api/v1/admin/promotions/reconcile", reconcile); status != 401 {
		t.Fatal("untrusted browser bound a provider transaction", status)
	}
	for _, mismatch := range []string{"merchant", "subscription", "amount"} {
		provider.update(txID, func(record *personalProviderRecord) {
			record.Merchant, record.Payload, record.Amount = "merchant-1", plategaPayloadPrefix+sub, "399.00"
			switch mismatch {
			case "merchant":
				record.Merchant = "not-this-merchant"
			case "subscription":
				record.Payload = plategaPayloadPrefix + strings.Repeat("f", 32)
			case "amount":
				record.Amount = "1.00"
			}
		})
		if status, _ := caller.do(t, "POST", "/api/v1/admin/promotions/reconcile", reconcile, admin); status < 400 {
			t.Fatal("unverified/mismatched provider transaction accepted", mismatch, status)
		}
		var saved string
		var paid *time.Time
		if err := store.DB.QueryRow(ctx, "SELECT p.provider_payment_id,s.paid_until FROM payments p JOIN subscriptions s ON s.id=p.subscription_id WHERE p.id=$1", id).Scan(&saved, &paid); err != nil || saved != "reservation:"+id || paid != nil {
			t.Fatal("failed reconciliation mutated money or rights", err)
		}
	}
	provider.update(txID, func(record *personalProviderRecord) {
		record.Merchant, record.Payload, record.Amount, record.Status = "merchant-1", plategaPayloadPrefix+sub, "399.00", "PENDING"
	})
	if status, result := caller.do(t, "POST", "/api/v1/admin/promotions/reconcile", reconcile, admin); status != 200 || result["status"] != "pending" {
		t.Fatal("verified pending ID not recovered", status, result)
	}
	if status, result := caller.do(t, "POST", path, request); status != 409 || result["error"] != "PAYMENT_RECONCILIATION_REQUIRED" {
		t.Fatal("status-only reconciliation invented a new payment link", status, result)
	}
	provider.update(txID, func(record *personalProviderRecord) { record.Status = "CONFIRMED" })
	for range 2 {
		if status, result := caller.do(t, "POST", "/api/v1/admin/promotions/reconcile", reconcile, admin); status != 200 || result["status"] != "succeeded" {
			t.Fatal("verified payment not credited", status, result)
		}
	}
	var credits int
	if err := store.DB.QueryRow(ctx, "SELECT count(*) FROM audit_log WHERE action='payment.succeeded'").Scan(&credits); err != nil || credits != 1 || provider.creates.Load() != 1 {
		t.Fatal("reconciliation reposted or credited twice", credits, provider.creates.Load(), err)
	}
	if status, result := caller.do(t, "POST", path, request); status != 200 || result["status"] != "succeeded" || result["redirect"] != nil {
		t.Fatal("paid order replay did not report authoritative state", status, result)
	}
}

func TestPersonalOrderLegacyUnresolvedRecordsArePreserved(t *testing.T) {
	for _, oldStatus := range []string{"pending", "canceled", "review"} {
		t.Run(oldStatus, func(t *testing.T) {
			api, store, caller, _, sub, _ := personalOrderFixture(t)
			provider := newPersonalProviderEmulator(t, "", nil)
			api.Settings.Payments = provider.provider()
			ctx := context.Background()
			status := oldStatus
			if status == "review" {
				status = "succeeded"
			}
			if _, _, err := store.RecordPayment(ctx, sub, "platega", "legacy-provider-id", 399, 30, status, "existing-real-or-unknown", "fixture", time.Now()); err != nil {
				t.Fatal(err)
			}
			if oldStatus == "review" {
				if _, err := store.DB.Exec(ctx, `INSERT INTO payment_review_events(payment_id,provider_status,refunded_kopecks)
 SELECT id,'PARTIALLY_REFUNDED',395 FROM payments WHERE provider_payment_id='legacy-provider-id'`); err != nil {
					t.Fatal(err)
				}
			}
			snapshot := func() string {
				t.Helper()
				var raw string
				if err := store.DB.QueryRow(ctx, `SELECT jsonb_build_object(
 'subscriptions',(SELECT jsonb_agg(to_jsonb(s) ORDER BY id) FROM subscriptions s),
 'payments',(SELECT jsonb_agg(to_jsonb(p) ORDER BY id) FROM payments p),
 'reviews',(SELECT jsonb_agg(to_jsonb(r) ORDER BY id) FROM payment_review_events r))::text`).Scan(&raw); err != nil {
					t.Fatal(err)
				}
				return raw
			}
			before := snapshot()
			if status, result := caller.do(t, "POST", "/api/v1/account/subscriptions/"+sub+"/pay", personalPayFixture("new-order-with-legacy-0001", 1, 39900)); status != 409 || result["error"] != "PAYMENT_IN_PROGRESS" {
				t.Fatal("old unresolved order bypassed", status, result)
			}
			if after := snapshot(); after != before || provider.creates.Load() != 0 {
				t.Fatal("existing payments/refunds/rights were cleaned up or another charge created")
			}
		})
	}
}
