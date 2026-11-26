package controlplane

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/buzzmean/veliq/core/security"
	"github.com/jackc/pgx/v5"
)

type PersonalQuote struct {
	PaymentQuote
	SubscriptionID string `json:"subscription_id"`
	PlanID         string `json:"plan_id"`
	Seats          int    `json:"seats"`
}

type PersonalOrder struct {
	ID             string        `json:"id"`
	Quote          PersonalQuote `json:"quote"`
	Status         string        `json:"status"`
	ReviewRequired bool          `json:"review_required"`
	Redirect       string        `json:"redirect,omitempty"`
	Existing       bool          `json:"-"`
}

const personalOrderSelect = `SELECT o.payment_id,o.request_hash,o.snapshot,o.redirect_url,p.status,p.provider,
 EXISTS(SELECT 1 FROM payment_review_events e WHERE e.payment_id=p.id)
 FROM personal_payment_orders o JOIN payments p ON p.id=o.payment_id`

func scanPersonalOrder(row pgx.Row) (out PersonalOrder, hash, provider string, err error) {
	var raw []byte
	if err = row.Scan(&out.ID, &hash, &raw, &out.Redirect, &out.Status, &provider, &out.ReviewRequired); err != nil {
		return
	}
	err = json.Unmarshal(raw, &out.Quote)
	if out.Status != "pending" || out.ReviewRequired {
		out.Redirect = ""
	}
	return
}

// ReservePersonalOrder commits the sole creation claim before provider I/O.
// A committed claim is never leased or retried: even a timeout may have created
// a payable provider transaction. Repeats use its saved result or require review.
func (s *Store) ReservePersonalOrder(ctx context.Context, acc Account, subID string, p Plan, months int, expected *int64, key, provider string) (PersonalOrder, error) {
	var out PersonalOrder
	if !clubOrderKey.MatchString(key) {
		return out, errors.New("PAYMENT_IDEMPOTENCY_REQUIRED")
	}
	if expected == nil {
		return out, errors.New("PAYMENT_CONFIRMATION_REQUIRED")
	}
	if provider == "" || len(provider) > 32 {
		return out, errors.New("PAYMENT_INVALID")
	}
	tx, err := s.DB.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return out, err
	}
	defer tx.Rollback(ctx)
	var disabled bool
	if err = tx.QueryRow(ctx, "SELECT disabled FROM accounts WHERE id=$1 FOR NO KEY UPDATE", acc.ID).Scan(&disabled); err != nil {
		return out, err
	}
	// Preserve the existing per-subscription ownership contract, including old
	// accounts whose profile predates their player subscription.
	if disabled {
		return out, errors.New("PAYMENT_INVALID")
	}
	hash := clubDigest([]any{subID, months, *expected})
	out, oldHash, oldProvider, err := scanPersonalOrder(tx.QueryRow(ctx, personalOrderSelect+" WHERE o.account_id=$1 AND o.idempotency_key=$2", acc.ID, key))
	if err == nil {
		if oldHash != hash || oldProvider != provider {
			return PersonalOrder{}, errors.New("PAYMENT_IDEMPOTENCY_CONFLICT")
		}
		out.Existing = true
		return out, tx.Commit(ctx)
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return PersonalOrder{}, err
	}
	var sub Subscription
	err = tx.QueryRow(ctx, "SELECT id,plan_id,kind,seats,lifetime FROM subscriptions WHERE id=$1 AND account_id=$2 FOR UPDATE", subID, acc.ID).Scan(&sub.ID, &sub.PlanID, &sub.Kind, &sub.Seats, &sub.Lifetime)
	if errors.Is(err, pgx.ErrNoRows) {
		return out, errors.New("SUBSCRIPTION_NOT_FOUND")
	}
	if err != nil {
		return out, err
	}
	if sub.Lifetime {
		return out, errors.New("PAYMENT_NOT_REQUIRED")
	}
	if sub.Kind != "player" || p.ID != sub.PlanID || p.Kind != "player" || p.PricePerSeatRub == 0 {
		return out, errors.New("PRICE_NOT_SET")
	}
	amount, term, err := p.QuotePayment(sub.Seats, months)
	if err != nil {
		return out, err
	}
	if amount != *expected {
		return out, errors.New("PAYMENT_PRICE_CHANGED")
	}
	unresolved, err := unresolvedPersonalPayment(ctx, tx, acc.ID)
	if err != nil {
		return out, err
	}
	if unresolved {
		return out, errors.New("PAYMENT_IN_PROGRESS")
	}
	id, err := security.NewID()
	if err != nil {
		return out, err
	}
	q := PersonalQuote{PaymentQuote: PaymentQuote{BaseAmount: p.PricePerSeatRub * int64(sub.Seats) * int64(months) * 100,
		Amount: amount, Discount: term.Discount, Months: months, Days: term.Days}, SubscriptionID: sub.ID, PlanID: sub.PlanID, Seats: sub.Seats}
	raw, err := json.Marshal(q)
	if err != nil {
		return out, err
	}
	reference := fmt.Sprintf("personal-order-v1;months=%d;discount=%d;seats=%d;base_rub=%d", months, term.Discount, sub.Seats, p.PricePerSeatRub)
	if _, err = tx.Exec(ctx, `INSERT INTO payments(id,subscription_id,provider,provider_payment_id,amount_kopecks,period_days,status,reference)
 VALUES($1,$2,$3,$4,$5,$6,'pending',$7)`, id, sub.ID, provider, "reservation:"+id, amount, term.Days, reference); err != nil {
		return out, err
	}
	if _, err = tx.Exec(ctx, `INSERT INTO personal_payment_orders(payment_id,account_id,idempotency_key,request_hash,snapshot)
 VALUES($1,$2,$3,$4,$5)`, id, acc.ID, key, hash, raw); err != nil {
		return out, err
	}
	if _, err = tx.Exec(ctx, "INSERT INTO audit_log(actor,action,entity_id) VALUES($1,'personal-order.reserved',$2)", "account:"+acc.ID, id); err != nil {
		return out, err
	}
	return PersonalOrder{ID: id, Quote: q, Status: "pending"}, tx.Commit(ctx)
}

// Both ordinary and promotion reservation callers hold the same account lock
// in READ COMMITTED. Historical canceled links can confirm late; an existing
// order/refund must never be classified as synthetic or silently released.
func unresolvedPersonalPayment(ctx context.Context, tx pgx.Tx, account string) (bool, error) {
	// A successful callback handled by an older server may never be replayed.
	// The caller's account lock serializes this tracking-only reconciliation
	// with callbacks and reservations; no money or subscription terms change.
	if _, err := tx.Exec(ctx, consumeSucceededPersonalOrderSQL+" AND o.account_id=$1", account); err != nil {
		return false, err
	}
	var unresolved bool
	err := tx.QueryRow(ctx, `SELECT
 EXISTS(SELECT 1 FROM personal_payment_orders WHERE account_id=$1 AND state='open') OR
 EXISTS(SELECT 1 FROM payments p JOIN subscriptions s ON s.id=p.subscription_id
  WHERE s.account_id=$1 AND s.kind='player' AND
   (p.status IN ('pending','canceled') OR EXISTS(SELECT 1 FROM payment_review_events e WHERE e.payment_id=p.id))) OR
 EXISTS(SELECT 1 FROM promotion_reservations WHERE account_id=$1 AND state='reserved')`, account).Scan(&unresolved)
	return unresolved, err
}

func (s *Store) PersonalOrder(ctx context.Context, account, id string) (PersonalOrder, error) {
	out, _, _, err := scanPersonalOrder(s.DB.QueryRow(ctx, personalOrderSelect+" WHERE o.account_id=$1 AND o.payment_id=$2", account, id))
	return out, err
}

// AttachPersonalPayment accepts only the trusted provider create result or an
// authenticated status reconciliation. No browser-supplied transaction is bound.
// An empty redirect is allowed for status-only operator reconciliation.
func (s *Store) AttachPersonalPayment(ctx context.Context, id, provider, providerID, redirect string) error {
	if providerID == "" || len(providerID) > 128 || strings.HasPrefix(providerID, "reservation:") || len(redirect) > 4096 {
		return errors.New("PAYMENT_INVALID")
	}
	if redirect != "" {
		u, err := url.Parse(redirect)
		if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Fragment != "" {
			return errors.New("PAYMENT_INVALID")
		}
	}
	tx, err := s.DB.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	var account, sub string
	if err = tx.QueryRow(ctx, `SELECT o.account_id,p.subscription_id FROM personal_payment_orders o
 JOIN payments p ON p.id=o.payment_id WHERE o.payment_id=$1 AND p.provider=$2`, id, provider).Scan(&account, &sub); err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, "SELECT id FROM accounts WHERE id=$1 FOR NO KEY UPDATE", account); err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, "SELECT id FROM subscriptions WHERE id=$1 FOR UPDATE", sub); err != nil {
		return err
	}
	var oldID, oldRedirect string
	if err = tx.QueryRow(ctx, `SELECT p.provider_payment_id,o.redirect_url FROM payments p
 JOIN personal_payment_orders o ON o.payment_id=p.id WHERE p.id=$1 FOR UPDATE OF p,o`, id).Scan(&oldID, &oldRedirect); err != nil {
		return err
	}
	if oldID != "reservation:"+id && oldID != providerID || oldRedirect != "" && redirect != "" && oldRedirect != redirect {
		return errors.New("PAYMENT_MISMATCH")
	}
	if oldID != providerID {
		if _, err = tx.Exec(ctx, "UPDATE payments SET provider_payment_id=$2 WHERE id=$1", id, providerID); err != nil {
			return err
		}
	}
	if redirect != "" && oldRedirect == "" {
		if _, err = tx.Exec(ctx, "UPDATE personal_payment_orders SET redirect_url=$2 WHERE payment_id=$1", id, redirect); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}

// Only a known, owner-bound successful payment without a review can complete
// an order. Pending, canceled and ambiguous creation claims remain unresolved.
const consumeSucceededPersonalOrderSQL = `UPDATE personal_payment_orders o SET state='consumed'
 FROM payments p JOIN subscriptions s ON s.id=p.subscription_id
 WHERE p.id=o.payment_id AND s.account_id=o.account_id AND o.state='open'
 AND p.status='succeeded' AND p.provider<>'' AND p.provider_payment_id<>''
 AND p.provider_payment_id NOT LIKE 'reservation:%'
 AND NOT EXISTS(SELECT 1 FROM payment_review_events e WHERE e.payment_id=p.id)`

func consumePersonalOrder(ctx context.Context, tx pgx.Tx, provider, providerID string) error {
	_, err := tx.Exec(ctx, consumeSucceededPersonalOrderSQL+" AND p.provider=$1 AND p.provider_payment_id=$2", provider, providerID)
	return err
}

func (a *API) personalPaymentFail(w http.ResponseWriter, err error) {
	switch err.Error() {
	case "PAYMENT_IDEMPOTENCY_REQUIRED":
		a.fail(w, 400, err.Error())
	case "SUBSCRIPTION_NOT_FOUND":
		a.fail(w, 404, err.Error())
	case "PAYMENT_CONFIRMATION_REQUIRED", "PAYMENT_IDEMPOTENCY_CONFLICT", "PAYMENT_PRICE_CHANGED", "PAYMENT_NOT_REQUIRED", "PAYMENT_IN_PROGRESS", "PAYMENT_INVALID", "PAYMENT_PERIOD_INVALID", "PRICE_NOT_SET":
		a.fail(w, 409, err.Error())
	default:
		a.fail(w, 503, "ACCOUNT_UNAVAILABLE")
	}
}

func (a *API) payPersonal(w http.ResponseWriter, r *http.Request, acc Account, sub Subscription, p Plan, months int, expected *int64, key string) {
	o, err := a.Store.ReservePersonalOrder(r.Context(), acc, sub.ID, p, months, expected, key, a.Settings.Payments.Name())
	if err != nil {
		a.personalPaymentFail(w, err)
		return
	}
	if o.Existing {
		if !o.ReviewRequired && (o.Status == "succeeded" || o.Redirect != "" && o.Status == "pending") {
			respond(w, 200, o)
		} else {
			a.fail(w, 409, "PAYMENT_RECONCILIATION_REQUIRED")
		}
		return
	}
	redirect, providerID, err := a.Settings.Payments.CreatePayment(r.Context(), PaymentRequest{Subscription: sub.ID,
		AmountKopecks: o.Quote.Amount, PeriodDays: o.Quote.Days, Description: "Подписка VELIQ «" + p.Title + "»", Email: acc.Email,
		AccountID: acc.ID, ReturnURL: a.Settings.AccountOrigin + "/account.html?payment=return&order=" + o.ID + "&subscription=" + sub.ID})
	if err != nil {
		a.fail(w, 409, "PAYMENT_RECONCILIATION_REQUIRED")
		return
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), 5*time.Second)
	defer cancel()
	if redirect == "" || a.Store.AttachPersonalPayment(ctx, o.ID, a.Settings.Payments.Name(), providerID, redirect) != nil {
		a.fail(w, 503, "PAYMENT_RECONCILIATION_REQUIRED")
		return
	}
	current, err := a.Store.PersonalOrder(ctx, acc.ID, o.ID)
	if err != nil {
		a.fail(w, 503, "PAYMENT_RECONCILIATION_REQUIRED")
		return
	}
	respond(w, 200, current)
}
