package controlplane

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type reviewFixture struct {
	api                  *API
	store                *Store
	client               *call
	before               paymentReviewSnapshot
	fresh                PaymentEvent
	q                    paymentReviewResolutionRequest
	mu                   sync.Mutex
	status, refundStatus string
	amount, refund       float64
	httpStatus           int
	omitRefund           bool
	calls                atomic.Int32
}

func newReviewFixture(t *testing.T) *reviewFixture {
	return newReviewFixtureHistory(t, "")
}

func newReviewFixtureHistory(t *testing.T, prior string) *reviewFixture {
	t.Helper()
	a, s, m := accountAPI(t, true)
	c := &call{api: a}
	login(t, c, m, "review@example.com")
	code, out := c.do(t, "POST", "/api/v1/account/subscriptions", map[string]any{"plan_id": "player-month", "seats": 1})
	if code != 201 {
		t.Fatal(code, out)
	}
	sub := out["id"].(string)
	ctx := context.Background()
	if _, _, err := s.RecordPayment(ctx, sub, "platega", "review-tx", 399, 30, "succeeded", "", "fixture", time.Now()); err != nil {
		t.Fatal(err)
	}
	ev := PaymentEvent{ProviderID: "review-tx", Subscription: sub, AmountKopecks: 399, Status: "review", ProviderStatus: "PARTIALLY_REFUNDED", RefundID: "refund-1", RefundStatus: "Succeeded", RefundedKopecks: 395}
	if prior != "" {
		old := ev
		switch prior {
		case "DISPUTED", "CHARGEBACKED":
			old.ProviderStatus = prior
		case "other_refund":
			old.RefundID = "earlier-refund"
		case "other_amount":
			old.RefundedKopecks = 394
		case "same_pending":
			old.RefundStatus = "Pending"
		default:
			t.Fatal("unsupported fixture history")
		}
		if _, _, err := s.RecordProviderPayment(ctx, "platega", ev.ProviderID, sub, 399, "review", "fixture", time.Now(), old); err != nil {
			t.Fatal(err)
		}
	}
	if _, _, err := s.RecordProviderPayment(ctx, "platega", ev.ProviderID, sub, 399, "review", "fixture", time.Now(), ev); err != nil {
		t.Fatal(err)
	}
	var id string
	if err := s.DB.QueryRow(ctx, "SELECT id FROM payments WHERE subscription_id=$1", sub).Scan(&id); err != nil {
		t.Fatal(err)
	}
	before, err := s.paymentReview(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	f := &reviewFixture{api: a, store: s, client: c, before: before, fresh: ev, status: ev.ProviderStatus, refundStatus: ev.RefundStatus, amount: 3.99, refund: 3.95, httpStatus: 200}
	f.q = paymentReviewResolutionRequest{LastEventID: before.LastEventID, EvidenceSHA256: strings.Repeat("a", 64), Outcome: "review_completed_no_access_change"}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.calls.Add(1)
		f.mu.Lock()
		defer f.mu.Unlock()
		if r.Method != "GET" || r.URL.Path != "/transaction/review-tx" || r.Header.Get("X-MerchantId") != "fixture-merchant" || r.Header.Get("X-Secret") != "fixture-secret" {
			t.Error("actual status request contract")
			w.WriteHeader(401)
			return
		}
		w.WriteHeader(f.httpStatus)
		body := map[string]any{"id": "review-tx", "status": f.status, "mechantId": "fixture-merchant", "paymentDetails": map[string]any{"amount": f.amount, "currency": "RUB"}, "payload": plategaPayloadPrefix + sub}
		if !f.omitRefund {
			body["refundId"] = "refund-1"
			body["refundStatus"] = f.refundStatus
			body["refundedAmount"] = f.refund
		}
		json.NewEncoder(w).Encode(body)
	}))
	t.Cleanup(server.Close)
	a.Settings.Payments = &PlategaProvider{MerchantID: "fixture-merchant", Secret: "fixture-secret", BaseURL: server.URL}
	return f
}
func (f *reviewFixture) admin(r *http.Request) {
	r.Header.Set("Authorization", "Bearer "+f.api.Settings.AdminToken)
}
func (f *reviewFixture) path() string {
	return "/api/v1/admin/payments/" + f.before.Payment + "/review"
}

func TestPaymentReviewCompletionAuthorizationAndFreshProvider(t *testing.T) {
	f := newReviewFixture(t)
	if status, _ := f.client.do(t, "POST", f.path()+"/resolve", f.q); status != 401 {
		t.Fatal("cookie authorized financial review", status)
	}
	if status, _ := f.client.do(t, "GET", f.path(), nil, f.admin); status != 404 {
		t.Fatal("default enabled", status)
	}
	f.api.Settings.PaymentReviewResolution = true
	if status, _ := f.client.do(t, "POST", f.path()+"/resolve", f.q, func(r *http.Request) { r.Header.Set("Authorization", "Bearer "+strings.Repeat("v", 32)) }); status != 401 {
		t.Fatal("unscoped token", status)
	}
	status, preview := f.client.do(t, "GET", f.path(), nil, f.admin)
	if status != 200 || preview["review_required"] != true || preview["provider_payment_id"] != nil || preview["refund_id"] != nil {
		t.Fatal("preview", status, preview)
	}
	for _, kind := range []string{"provider_unavailable", "missing_refund", "changed_amount", "changed_refund", "disputed", "refund_pending", "full_refund"} {
		t.Run(kind, func(t *testing.T) {
			f.mu.Lock()
			f.httpStatus = 200
			f.omitRefund = false
			f.amount = 3.99
			f.refund = 3.95
			f.status = "PARTIALLY_REFUNDED"
			f.refundStatus = "Succeeded"
			switch kind {
			case "provider_unavailable":
				f.httpStatus = 503
			case "missing_refund":
				f.omitRefund = true
			case "changed_amount":
				f.amount = 4
			case "changed_refund":
				f.refund = 3.94
			case "disputed":
				f.status = "DISPUTED"
			case "refund_pending":
				f.refundStatus = "Pending"
			case "full_refund":
				f.refund = 3.99
			}
			f.mu.Unlock()
			status, _ := f.client.do(t, "POST", f.path()+"/resolve", f.q, f.admin)
			if status != 409 && status != 502 {
				t.Fatal("unsafe review accepted", status)
			}
			var n int
			if err := f.store.DB.QueryRow(context.Background(), "SELECT count(*) FROM payment_review_resolutions").Scan(&n); err != nil || n != 0 {
				t.Fatal("negative changed audit", n, err)
			}
		})
	}
	f.mu.Lock()
	f.refund = 3.95
	f.mu.Unlock()
	status, result := f.client.do(t, "POST", f.path()+"/resolve", f.q, f.admin)
	if status != 200 || result["review_completed"] != true || result["created"] != true {
		t.Fatal(status, result)
	}
	if f.calls.Load() < 8 {
		t.Fatal("fresh provider check absent")
	}
	status, result = f.client.do(t, "POST", f.path()+"/resolve", f.q, f.admin)
	if status != 200 || result["created"] != false {
		t.Fatal("retry not idempotent", status, result)
	}
	_, view := f.client.do(t, "GET", "/api/v1/account", nil)
	p := view["payments"].([]any)[0].(map[string]any)
	if p["review_required"] != false || p["review_completed"] != true || p["reviewed_refund_kopecks"] != float64(395) {
		t.Fatal("account hid actual refund", p)
	}
}

func TestPaymentReviewCompletionCASConcurrentAuditAndReopen(t *testing.T) {
	f := newReviewFixture(t)
	ctx := context.Background()
	checkAdmission := func(wanted bool) {
		tx, err := f.store.DB.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback(ctx)
		blocked, err := unresolvedPersonalPayment(ctx, tx, f.before.Account)
		if err != nil || blocked != wanted {
			t.Fatal("checkout review state", blocked, err)
		}
	}
	checkAdmission(true)
	var oldUntil time.Time
	if err := f.store.DB.QueryRow(ctx, "SELECT paid_until FROM subscriptions WHERE id=$1", f.before.Subscription).Scan(&oldUntil); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	var created atomic.Int32
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ok, err := f.store.resolvePaymentReview(ctx, f.before, f.q, f.fresh)
			if err != nil {
				t.Error(err)
			}
			if ok {
				created.Add(1)
			}
		}()
	}
	wg.Wait()
	if created.Load() != 1 {
		t.Fatal("duplicate resolutions", created.Load())
	}
	checkAdmission(false)
	conflict := f.q
	conflict.EvidenceSHA256 = strings.Repeat("b", 64)
	if _, err := f.store.resolvePaymentReview(ctx, f.before, conflict, f.fresh); err == nil || err.Error() != "PAYMENT_REVIEW_RESOLUTION_CONFLICT" {
		t.Fatal("evidence overwritten", err)
	}
	for _, sql := range []string{"UPDATE payment_review_resolutions SET evidence_sha256=repeat('c',64)", "DELETE FROM payment_review_resolutions"} {
		if _, err := f.store.DB.Exec(ctx, sql); err == nil {
			t.Fatal("resolution mutable")
		}
	}
	for i := 0; i < 2; i++ {
		if err := f.store.Migrate(ctx); err != nil {
			t.Fatal("migration retry", err)
		}
	}
	until, extended, err := f.store.RecordProviderPayment(ctx, "platega", f.fresh.ProviderID, f.before.Subscription, 399, "succeeded", "fixture", time.Now())
	if err != nil || extended || !until.Equal(oldUntil) {
		t.Fatal("review completion changed credit", until, extended, err)
	}
	newEvent := f.fresh
	newEvent.ProviderStatus = "DISPUTED"
	newEvent.RefundStatus = "Pending"
	if _, _, err = f.store.RecordProviderPayment(ctx, "platega", newEvent.ProviderID, f.before.Subscription, 399, "review", "fixture", time.Now(), newEvent); err != nil {
		t.Fatal(err)
	}
	if _, err = f.store.resolvePaymentReview(ctx, f.before, f.q, f.fresh); err == nil || err.Error() != "PAYMENT_REVIEW_CHANGED" {
		t.Fatal("stale receipt accepted", err)
	}
	now, err := f.store.paymentReview(ctx, f.before.Payment)
	if err != nil || !now.Required || now.LastEventID == f.before.LastEventID {
		t.Fatal("new evidence did not reopen", now, err)
	}
	checkAdmission(true)
	var resolutions, events, audits int
	err = f.store.DB.QueryRow(ctx, "SELECT (SELECT count(*) FROM payment_review_resolutions),(SELECT count(*) FROM payment_review_events),(SELECT count(*) FROM audit_log WHERE action='payment.review.completed_no_access_change')").Scan(&resolutions, &events, &audits)
	if err != nil || resolutions != 1 || events != 2 || audits != 1 {
		t.Fatal("audit lost/duplicated", resolutions, events, audits, err)
	}
}

func TestPaymentReviewCompletionFinishesOldOrderWithoutRecredit(t *testing.T) {
	f := newPersonalRollforwardFixture(t)
	ctx := context.Background()
	var providerID string
	if err := f.store.DB.QueryRow(ctx, "SELECT provider_payment_id FROM payments WHERE id=$1", f.id).Scan(&providerID); err != nil {
		t.Fatal(err)
	}
	ev := PaymentEvent{ProviderID: providerID, Subscription: f.sub, AmountKopecks: 113715, Status: "review", ProviderStatus: "PARTIALLY_REFUNDED", RefundID: "old-order-refund", RefundStatus: "Succeeded", RefundedKopecks: 1000}
	if _, _, err := f.store.RecordProviderPayment(ctx, "platega", providerID, f.sub, 113715, "review", "fixture", time.Now(), ev); err != nil {
		t.Fatal(err)
	}
	before, err := f.store.paymentReview(ctx, f.id)
	if err != nil {
		t.Fatal(err)
	}
	frozen := f.frozen(t)
	if f.state(t) != "open" {
		t.Fatal("fixture did not preserve old open tracking")
	}
	q := paymentReviewResolutionRequest{LastEventID: before.LastEventID, EvidenceSHA256: strings.Repeat("a", 64), Outcome: "review_completed_no_access_change"}
	for i := 0; i < 2; i++ {
		created, err := f.store.resolvePaymentReview(ctx, before, q, ev)
		if err != nil || created != (i == 0) {
			t.Fatal("resolution repeat", created, err)
		}
	}
	if f.state(t) != "consumed" || f.frozen(t) != frozen {
		t.Fatal("tracking incomplete or financial beforeimage changed")
	}
	tx, err := f.store.DB.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	blocked, err := unresolvedPersonalPayment(ctx, tx, before.Account)
	if err != nil || blocked {
		t.Fatal("closed review still blocks new checkout", blocked, err)
	}
}

func TestPaymentReviewCompletionCancelledApplyLeavesReviewOpen(t *testing.T) {
	f := newReviewFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	created, err := f.store.resolvePaymentReview(ctx, f.before, f.q, f.fresh)
	if created || err == nil {
		t.Fatal("cancelled evidence applied", created, err)
	}
	var n int
	if err = f.store.DB.QueryRow(context.Background(), "SELECT count(*) FROM payment_review_resolutions").Scan(&n); err != nil || n != 0 {
		t.Fatal("cancelled apply changed audit", n, err)
	}
	state, err := f.store.paymentReview(context.Background(), f.before.Payment)
	if err != nil || !state.Required {
		t.Fatal("cancelled review disappeared", state, err)
	}
}

func TestPaymentReviewCompletionNeverClosesDifferentHistoricalCase(t *testing.T) {
	for _, prior := range []string{"DISPUTED", "CHARGEBACKED", "other_refund", "other_amount", "same_pending"} {
		t.Run(prior, func(t *testing.T) {
			f := newReviewFixtureHistory(t, prior)
			created, err := f.store.resolvePaymentReview(context.Background(), f.before, f.q, f.fresh)
			if prior == "same_pending" {
				if !created || err != nil {
					t.Fatal("same confirmed refund did not supersede its pending observation", created, err)
				}
				return
			}
			if created || err == nil || err.Error() != "PAYMENT_REVIEW_FINANCIAL_DECISION_REQUIRED" {
				t.Fatal("different historical case silently resolved", created, err)
			}
			var count int
			if err = f.store.DB.QueryRow(context.Background(), "SELECT count(*) FROM payment_review_resolutions").Scan(&count); err != nil || count != 0 {
				t.Fatal("unsafe resolution audit written", count, err)
			}
		})
	}
}
