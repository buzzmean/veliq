package controlplane

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/buzzmean/neexitlag/core/security"
	"github.com/jackc/pgx/v5"
)

// Identity checked against the previously verified account, not a browser email.
const OwnerPromoAccountID = "00000000000000000000000000000000"
const OwnerPromoEmail = "redacted-owner@example.invalid"

type PaymentQuote struct {
	BaseAmount  int64  `json:"base_amount_kopecks"`
	Amount      int64  `json:"amount_kopecks"`
	Discount    int    `json:"discount"`
	Days        int    `json:"days"`
	Months      int    `json:"months"`
	PromotionID string `json:"-"`
}

func promotionHash(code string) ([]byte, error) {
	// Canonical hexadecimal codes have 256 random bits. Never log raw input.
	code = strings.ToLower(strings.TrimSpace(code))
	b, e := hex.DecodeString(code)
	if e != nil || len(b) != 32 {
		return nil, errors.New("PROMO_INVALID")
	}
	h := sha256.Sum256(append([]byte("veliq:promotion:v1\x00"), b...))
	return h[:], nil
}

// CreatePromotion creates a DISABLED campaign; the caller must deliver the secret
// privately. No secret is stored in the database, audit, payment or provider payload.
func (s *Store) CreatePromotion(ctx context.Context, kind string) (id, code string, err error) {
	var account any
	discount, capacity := 30, 20
	switch kind {
	case "owner-test":
		var matches bool
		err = s.DB.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM accounts WHERE id=$1 AND email=$2 AND account_type='player' AND NOT disabled)", OwnerPromoAccountID, OwnerPromoEmail).Scan(&matches)
		if err != nil {
			return
		}
		if !matches {
			err = errors.New("OWNER_IDENTITY_NOT_VERIFIED")
			return
		}
		account = OwnerPromoAccountID
		discount = 99
		capacity = 1
	case "club-launch":
	default:
		err = errors.New("PROMO_KIND_INVALID")
		return
	}
	raw := make([]byte, 32)
	if _, err = rand.Read(raw); err != nil {
		return
	}
	code = hex.EncodeToString(raw)
	hash, _ := promotionHash(code)
	if id, err = security.NewID(); err != nil {
		return
	}
	_, err = s.DB.Exec(ctx, "INSERT INTO promotions(id,code_hash,kind,account_id,discount,capacity) VALUES($1,$2,$3,$4,$5,$6)", id, hash, kind, account, discount, capacity)
	return
}

// All promo decisions and capacity reservations serialize on the campaign row.
// Reserved + redeemed slots count against capacity. Never expire a reservation:
// the provider can confirm a previously canceled or timed-out order later.
func promoQuote(ctx context.Context, tx pgx.Tx, acc Account, sub Subscription, p Plan, months int, code string) (PaymentQuote, error) {
	amount, term, err := p.QuotePayment(sub.Seats, months)
	q := PaymentQuote{BaseAmount: p.PricePerSeatRub * int64(sub.Seats) * int64(months) * 100, Amount: amount, Discount: term.Discount, Days: term.Days, Months: months}
	if err != nil {
		return q, err
	}
	if code == "" {
		return q, nil
	}
	// Same account lock as ordinary club orders/manual bookings: an order must
	// not appear between eligibility checking and committing the promo reserve.
	var accountKind, email string
	var disabled bool
	if err = tx.QueryRow(ctx, "SELECT account_type,disabled,email FROM accounts WHERE id=$1 FOR NO KEY UPDATE", acc.ID).Scan(&accountKind, &disabled, &email); err != nil {
		return q, err
	}
	hash, err := promotionHash(code)
	if err != nil {
		return q, err
	}
	var kind string
	var target *string
	var enabled bool
	var discount, capacity int
	err = tx.QueryRow(ctx, "SELECT id,kind,account_id,discount,capacity,enabled FROM promotions WHERE code_hash=$1 FOR UPDATE", hash).Scan(&q.PromotionID, &kind, &target, &discount, &capacity, &enabled)
	if errors.Is(err, pgx.ErrNoRows) || err == nil && !enabled {
		return q, errors.New("PROMO_INVALID")
	}
	if err != nil {
		return q, err
	}
	if disabled || accountKind != sub.Kind {
		return q, errors.New("PROMO_INVALID")
	}
	if kind == "owner-test" {
		if target == nil || *target != acc.ID || acc.ID != OwnerPromoAccountID || email != OwnerPromoEmail || sub.Kind != "player" || months != 1 || sub.Seats != 1 || p.PricePerSeatRub != 399 {
			return q, errors.New("PROMO_INVALID")
		}
	} else {
		var approved bool
		if err = tx.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM promotion_club_approvals WHERE account_id=$1)", acc.ID).Scan(&approved); err != nil {
			return q, err
		}
		if sub.Kind != "club" || !approved {
			return q, errors.New("PROMO_INVALID")
		}
	}
	var used, held bool
	var count int
	if err = tx.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM promotion_reservations WHERE promotion_id=$1 AND account_id=$2 AND state='redeemed'),EXISTS(SELECT 1 FROM promotion_reservations WHERE promotion_id=$1 AND account_id=$2), (SELECT count(*) FROM promotion_reservations WHERE promotion_id=$1)", q.PromotionID, acc.ID).Scan(&used, &held, &count); err != nil {
		return q, err
	}
	if used {
		return q, errors.New("PROMO_USED")
	}
	if held {
		return q, errors.New("PROMO_RESERVED")
	}
	if kind == "club-launch" {
		var purchased, unresolved bool
		err = tx.QueryRow(ctx, `SELECT
 EXISTS(SELECT 1 FROM payments p JOIN subscriptions s ON s.id=p.subscription_id WHERE s.account_id=$1 AND p.status='succeeded' AND p.amount_kopecks>0),
 EXISTS(SELECT 1 FROM payments p JOIN subscriptions s ON s.id=p.subscription_id WHERE s.account_id=$1 AND p.status IN ('pending','canceled'))`, acc.ID).Scan(&purchased, &unresolved)
		if err != nil {
			return q, err
		}
		if purchased {
			return q, errors.New("PROMO_FIRST_PURCHASE_ONLY")
		}
		// Do not reprice an existing link. Even CANCELED may confirm late.
		if unresolved {
			return q, errors.New("PROMO_RECONCILIATION_REQUIRED")
		}
	}
	if count >= capacity {
		return q, errors.New("PROMO_EXHAUSTED")
	}
	// Replaces, never stacks with, a period discount. Integer kopecks, round half up.
	q.Discount = discount
	q.Amount = (q.BaseAmount*int64(100-discount) + 50) / 100
	if q.Amount < 1 {
		return q, errors.New("PAYMENT_INVALID")
	}
	return q, nil
}

// Record an ordinary club order before provider I/O as well. Otherwise an
// in-flight full-price purchase could be invisible to a concurrent promo check.
// The provider contract and old orders remain unchanged.
func (s *Store) ReserveClubPurchase(ctx context.Context, acc Account, sub Subscription, p Plan, months int, expected *int64, provider string) (string, error) {
	key, e := security.NewID()
	if e != nil {
		return "", e
	}
	o, e := s.ReserveClubOrder(ctx, acc, sub, p, months, "", expected, "", key, provider, time.Now())
	return o.ID, e
}

func (s *Store) QuotePromotion(ctx context.Context, acc Account, sub Subscription, p Plan, months int, code string) (PaymentQuote, error) {
	if sub.Kind == "club" {
		q, e := s.QuoteClubOrder(ctx, acc, sub, p, months, code, time.Now())
		return q.PaymentQuote, e
	}
	tx, e := s.DB.Begin(ctx)
	if e != nil {
		return PaymentQuote{}, e
	}
	defer tx.Rollback(ctx)
	return promoQuote(ctx, tx, acc, sub, p, months, code)
}

// ReservePromotion commits before network I/O. Failure/timeout leaves a durable
// pending payment without exposing a link. It must be reconciled, never retried
// with a new provider request. The placeholder cannot match a provider UUID.
func (s *Store) ReservePromotion(ctx context.Context, acc Account, sub Subscription, p Plan, months int, code string, expected *int64, provider string) (string, PaymentQuote, error) {
	if sub.Kind == "club" {
		key, e := security.NewID()
		if e != nil {
			return "", PaymentQuote{}, e
		}
		o, e := s.ReserveClubOrder(ctx, acc, sub, p, months, code, expected, "", key, provider, time.Now())
		return o.ID, o.Quote.PaymentQuote, e
	}
	tx, e := s.DB.Begin(ctx)
	if e != nil {
		return "", PaymentQuote{}, e
	}
	defer tx.Rollback(ctx)
	q, e := promoQuote(ctx, tx, acc, sub, p, months, code)
	if e != nil {
		return "", q, e
	}
	if q.PromotionID == "" {
		return "", q, errors.New("PROMO_INVALID")
	}
	if expected != nil && *expected != q.Amount {
		return "", q, errors.New("PAYMENT_PRICE_CHANGED")
	}
	id, e := security.NewID()
	if e != nil {
		return "", q, e
	}
	_, e = tx.Exec(ctx, "INSERT INTO payments(id,subscription_id,provider,provider_payment_id,amount_kopecks,period_days,status,reference) VALUES($1,$2,$3,$4,$5,$6,'pending','promotion')", id, sub.ID, provider, "reservation:"+id, q.Amount, q.Days)
	if e != nil {
		return "", q, e
	}
	_, e = tx.Exec(ctx, "INSERT INTO promotion_reservations(id,promotion_id,account_id,payment_id) VALUES($1,$2,$3,$1)", id, q.PromotionID, acc.ID)
	if e != nil {
		return "", q, e
	}
	_, e = tx.Exec(ctx, "INSERT INTO audit_log(actor,action,entity_id) VALUES($1,'promotion.reserved',$2)", "account:"+acc.ID, id)
	if e != nil {
		return "", q, e
	}
	return id, q, tx.Commit(ctx)
}

func (s *Store) AttachPromotionPayment(ctx context.Context, id, provider, providerID string) error {
	if providerID == "" || len(providerID) > 128 || strings.HasPrefix(providerID, "reservation:") {
		return errors.New("PAYMENT_INVALID")
	}
	result, e := s.DB.Exec(ctx, "UPDATE payments SET provider_payment_id=$3 WHERE id=$1 AND provider=$2 AND provider_payment_id=$4 AND status='pending'", id, provider, providerID, "reservation:"+id)
	if e != nil {
		return e
	}
	if result.RowsAffected() != 1 {
		return errors.New("PAYMENT_INVALID")
	}
	return nil
}

func redeemPromotion(ctx context.Context, tx pgx.Tx, provider, providerID string, now time.Time) error {
	_, e := tx.Exec(ctx, `WITH redeemed AS (
 UPDATE promotion_reservations r SET state='redeemed',redeemed_at=$3 FROM payments p
 WHERE p.id=r.payment_id AND p.provider=$1 AND p.provider_payment_id=$2 AND r.state='reserved' RETURNING r.id)
 INSERT INTO audit_log(actor,action,entity_id) SELECT 'payment:promotion','promotion.redeemed',id FROM redeemed`, provider, providerID, now)
	return e
}

func (a *API) promoFail(w http.ResponseWriter, err error) {
	switch err.Error() {
	case "PROMO_REVIEW_REQUIRED", "PAYMENT_CONFIRMATION_REQUIRED", "PAYMENT_IDEMPOTENCY_REQUIRED", "PAYMENT_IDEMPOTENCY_CONFLICT", "SUBSCRIPTION_NOT_FOUND", "PROMO_INVALID", "PROMO_USED", "PROMO_RESERVED", "PROMO_EXHAUSTED", "PROMO_FIRST_PURCHASE_ONLY", "PROMO_RECONCILIATION_REQUIRED", "PAYMENT_PRICE_CHANGED", "PAYMENT_INVALID", "PAYMENT_PERIOD_INVALID", "PRICE_NOT_SET":
		a.fail(w, 409, err.Error())
	default:
		a.fail(w, 503, "ACCOUNT_UNAVAILABLE")
	}
}
