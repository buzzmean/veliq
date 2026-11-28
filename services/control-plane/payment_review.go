package controlplane

import (
	"context"
	"encoding/hex"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

type paymentReviewSnapshot struct {
	Payment        string `json:"payment_id"`
	Subscription   string `json:"-"`
	Account        string `json:"-"`
	Provider       string `json:"provider"`
	ProviderID     string `json:"-"`
	Amount         int64  `json:"amount_kopecks"`
	Status         string `json:"status"`
	LastEventID    int64  `json:"last_event_id"`
	ProviderStatus string `json:"provider_status"`
	RefundID       string `json:"-"`
	RefundStatus   string `json:"refund_status"`
	Refunded       int64  `json:"reviewed_refund_kopecks"`
	Required       bool   `json:"review_required"`
}

func (s *Store) paymentReview(ctx context.Context, id string) (v paymentReviewSnapshot, err error) {
	err = s.DB.QueryRow(ctx, `SELECT p.id,p.subscription_id,s.account_id,p.provider,p.provider_payment_id,p.amount_kopecks,p.status,
 e.id,e.provider_status,e.refund_id,e.refund_status,e.refunded_kopecks,payment_review_required(p.id)
 FROM payments p JOIN subscriptions s ON s.id=p.subscription_id
 JOIN LATERAL(SELECT * FROM payment_review_events WHERE payment_id=p.id ORDER BY id DESC LIMIT 1)e ON true
 WHERE p.id=$1`, id).Scan(&v.Payment, &v.Subscription, &v.Account, &v.Provider, &v.ProviderID, &v.Amount, &v.Status, &v.LastEventID, &v.ProviderStatus, &v.RefundID, &v.RefundStatus, &v.Refunded, &v.Required)
	return
}

type paymentReviewResolutionRequest struct {
	LastEventID    int64  `json:"last_event_id"`
	EvidenceSHA256 string `json:"evidence_sha256"`
	Outcome        string `json:"outcome"`
}

func validReviewResolution(q paymentReviewResolutionRequest) bool {
	b, e := hex.DecodeString(q.EvidenceSHA256)
	return e == nil && len(b) == 32 && q.EvidenceSHA256 == strings.ToLower(q.EvidenceSHA256) && q.LastEventID > 0 && q.Outcome == "review_completed_no_access_change"
}

// Administrative workflow only: historical credit/referral/checkout guards stay.
func (s *Store) resolvePaymentReview(ctx context.Context, before paymentReviewSnapshot, q paymentReviewResolutionRequest, fresh PaymentEvent) (bool, error) {
	if !validReviewResolution(q) {
		return false, errors.New("PAYMENT_REVIEW_INVALID")
	}
	if fresh.ProviderID != before.ProviderID || fresh.Subscription != before.Subscription || fresh.AmountKopecks != before.Amount ||
		fresh.Status != "review" || fresh.ProviderStatus != "PARTIALLY_REFUNDED" || before.ProviderStatus != fresh.ProviderStatus ||
		fresh.RefundID == "" || fresh.RefundID != before.RefundID || fresh.RefundStatus != "Succeeded" || fresh.RefundStatus != before.RefundStatus ||
		fresh.RefundedKopecks != before.Refunded || fresh.RefundedKopecks <= 0 || fresh.RefundedKopecks >= before.Amount || before.Status != "succeeded" {
		return false, errors.New("PAYMENT_REVIEW_FINANCIAL_DECISION_REQUIRED")
	}
	tx, err := s.DB.Begin(ctx)
	if err != nil {
		return false, err
	}
	defer tx.Rollback(ctx)
	// Same lock order as callbacks; provider I/O happens before these locks.
	if _, err = tx.Exec(ctx, "SELECT id FROM accounts WHERE id=$1 FOR NO KEY UPDATE", before.Account); err != nil {
		return false, err
	}
	var actualOwner string
	if err = tx.QueryRow(ctx, "SELECT account_id FROM subscriptions WHERE id=$1 FOR UPDATE", before.Subscription).Scan(&actualOwner); err != nil {
		return false, err
	}
	if actualOwner != before.Account {
		return false, errors.New("PAYMENT_REVIEW_CHANGED")
	}
	var status, provider, providerID, subscription string
	var amount, last int64
	err = tx.QueryRow(ctx, "SELECT status,provider,provider_payment_id,subscription_id,amount_kopecks FROM payments WHERE id=$1 FOR UPDATE", before.Payment).Scan(&status, &provider, &providerID, &subscription, &amount)
	if err != nil {
		return false, err
	}
	var eventStatus, refundID, refundStatus string
	var refunded int64
	err = tx.QueryRow(ctx, "SELECT id,provider_status,refund_id,refund_status,refunded_kopecks FROM payment_review_events WHERE payment_id=$1 ORDER BY id DESC LIMIT 1", before.Payment).Scan(&last, &eventStatus, &refundID, &refundStatus, &refunded)
	if err != nil {
		return false, err
	}
	if last != q.LastEventID || last != before.LastEventID || status != before.Status || provider != before.Provider || providerID != before.ProviderID || subscription != before.Subscription || amount != before.Amount || eventStatus != before.ProviderStatus || refundID != before.RefundID || refundStatus != before.RefundStatus || refunded != before.Refunded {
		return false, errors.New("PAYMENT_REVIEW_CHANGED")
	}
	// The watermark covers earlier observations too. A final partial refund
	// cannot silently resolve an earlier dispute, another refund or an ambiguous
	// amount. Only this one refund's matching history is within this outcome.
	var differentCase bool
	err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM payment_review_events WHERE payment_id=$1
 AND (provider_status<>'PARTIALLY_REFUNDED' OR refund_id<>$2 OR refunded_kopecks<>$3))`, before.Payment, before.RefundID, before.Refunded).Scan(&differentCase)
	if err != nil {
		return false, err
	}
	if differentCase {
		return false, errors.New("PAYMENT_REVIEW_FINANCIAL_DECISION_REQUIRED")
	}
	var oldEvidence, oldOutcome string
	err = tx.QueryRow(ctx, "SELECT evidence_sha256,outcome FROM payment_review_resolutions WHERE payment_id=$1 AND through_event_id=$2", before.Payment, last).Scan(&oldEvidence, &oldOutcome)
	if err == nil {
		if oldEvidence != q.EvidenceSHA256 || oldOutcome != q.Outcome {
			return false, errors.New("PAYMENT_REVIEW_RESOLUTION_CONFLICT")
		}
		return false, tx.Commit(ctx)
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return false, err
	}
	_, err = tx.Exec(ctx, `INSERT INTO payment_review_resolutions(payment_id,through_event_id,evidence_sha256,outcome,reviewed_refund_kopecks) VALUES($1,$2,$3,$4,$5)`, before.Payment, last, q.EvidenceSHA256, q.Outcome, before.Refunded)
	if err != nil {
		return false, err
	}
	// A known successful old payment may have an unfinished durable-order marker.
	// Close only that tracking row; never replay credit or release another order.
	if _, err = tx.Exec(ctx, "UPDATE personal_payment_orders SET state='consumed' WHERE payment_id=$1 AND account_id=$2 AND state='open'", before.Payment, before.Account); err != nil {
		return false, err
	}
	if _, err = tx.Exec(ctx, "INSERT INTO audit_log(actor,action,entity_id) VALUES('payment-review:admin','payment.review.completed_no_access_change',$1)", before.Payment); err != nil {
		return false, err
	}
	return true, tx.Commit(ctx)
}

func (a *API) paymentReviewAdmin(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if !a.admin(r) {
		a.fail(w, 401, "UNAUTHORIZED")
		return
	}
	if !a.Settings.PaymentReviewResolution {
		a.fail(w, 404, "PAYMENT_REVIEW_DISABLED")
		return
	}
	id := r.PathValue("id")
	if !subIDFormat.MatchString(id) {
		a.fail(w, 400, "PAYMENT_INVALID")
		return
	}
	before, err := a.Store.paymentReview(r.Context(), id)
	if errors.Is(err, pgx.ErrNoRows) {
		a.fail(w, 404, "PAYMENT_REVIEW_NOT_FOUND")
		return
	}
	if err != nil {
		a.fail(w, 503, "ACCOUNT_UNAVAILABLE")
		return
	}
	if r.Method == "GET" {
		respond(w, 200, before)
		return
	}
	var q paymentReviewResolutionRequest
	if body(r, &q) != nil || !validReviewResolution(q) {
		a.fail(w, 400, "PAYMENT_REVIEW_INVALID")
		return
	}
	checker, ok := a.Settings.Payments.(PaymentStatusProvider)
	if !ok || a.Settings.Payments.Name() != before.Provider {
		a.fail(w, 503, "PAYMENT_NOT_CONFIGURED")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	fresh, err := checker.CheckPayment(ctx, before.ProviderID)
	if err != nil {
		a.fail(w, 502, "PAYMENT_CHECK_UNAVAILABLE")
		return
	}
	created, err := a.Store.resolvePaymentReview(ctx, before, q, fresh)
	if err != nil {
		switch err.Error() {
		case "PAYMENT_REVIEW_CHANGED", "PAYMENT_REVIEW_RESOLUTION_CONFLICT", "PAYMENT_REVIEW_FINANCIAL_DECISION_REQUIRED":
			a.fail(w, 409, err.Error())
		default:
			a.fail(w, 503, "ACCOUNT_UNAVAILABLE")
		}
		return
	}
	respond(w, 200, map[string]any{"review_required": false, "review_completed": true, "created": created, "outcome": q.Outcome, "reviewed_refund_kopecks": before.Refunded})
}
