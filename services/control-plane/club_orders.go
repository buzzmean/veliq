package controlplane

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/buzzmean/veliq/core/security"
	"github.com/jackc/pgx/v5"
)

const clubMonthSeconds int64 = 30 * 24 * 60 * 60
const clubWindowSeconds int64 = 3 * clubMonthSeconds
const clubDiscountDenominator int64 = 100 * clubMonthSeconds

// One cohort is one immutable subscription in this release. Seat management is
// deliberately not exposed; changed historical cohorts require evidence review.
type ClubQuote struct {
	PaymentQuote
	Version         string     `json:"quote_version"`
	SubscriptionID  string     `json:"subscription_id"`
	ClubReference   string     `json:"club_reference,omitempty"`
	Seats           int        `json:"seats"`
	EligibleSeats   int        `json:"eligible_seats"`
	EligibleSeconds int64      `json:"eligible_seconds"`
	DiscountAmount  int64      `json:"discount_kopecks"`
	Fee             int64      `json:"fee_kopecks"`
	Operation       string     `json:"operation"`
	ServiceStart    time.Time  `json:"expected_start"`
	ServiceEnd      time.Time  `json:"expected_end"`
	WindowStart     *time.Time `json:"window_start,omitempty"`
	WindowEnd       *time.Time `json:"window_end,omitempty"`
	BenefitFrom     int64      `json:"benefit_from_seconds"`
	BenefitTo       int64      `json:"benefit_to_seconds"`
	Numerator       int64      `json:"-"`
	PriorNumerator  int64      `json:"-"`
	PriorDiscount   int64      `json:"-"`
	Entitlement     bool       `json:"-"`
	NewEntitlement  bool       `json:"-"`
}

type clubEntitlement struct {
	promotion, club, subscription string
	seats                         int
	review                        bool
	start, end                    *time.Time
	cursor, numerator, discount   int64
}

// Round the aggregate payable amount half up. Carry the exact rational discount
// across orders: splitting an identical covered interval cannot save a kopeck.
func clubBenefitPrice(base, price int64, seats int, seconds, priorNumerator, priorDiscount int64) (amount, numerator, discount int64, err error) {
	if base < 1 || base > 10000000000 || price != 29900 || seats < 0 || seats > 10000 || seconds < 0 || seconds > clubWindowSeconds || priorNumerator < 0 || priorDiscount < 0 {
		return 0, 0, 0, errors.New("PAYMENT_INVALID")
	}
	numerator = priorNumerator + price*int64(seats)*30*seconds
	totalDiscount := (numerator + clubDiscountDenominator/2 - 1) / clubDiscountDenominator
	discount = totalDiscount - priorDiscount
	amount = base - discount
	if discount < 0 || amount < 1 {
		err = errors.New("PAYMENT_INVALID")
	}
	return
}

var clubOrderKey = regexp.MustCompile(`^[a-zA-Z0-9_-]{16,96}$`)

func clubDigest(v any) string {
	b, _ := json.Marshal(v)
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}
func clubRequestHash(sub string, months int, code string) string {
	// Hash the promotion credential rather than storing it in the order snapshot.
	return clubDigest([]any{sub, months, clubDigest(code)})
}
func lockClubAccount(ctx context.Context, tx pgx.Tx, account string) error {
	var kind string
	var disabled bool
	if e := tx.QueryRow(ctx, "SELECT account_type,disabled FROM accounts WHERE id=$1 FOR NO KEY UPDATE", account).Scan(&kind, &disabled); e != nil {
		return e
	}
	if disabled || (kind != "club" && kind != "") {
		return errors.New("PAYMENT_INVALID")
	}
	return nil
}
func clubOpenOrder(ctx context.Context, tx pgx.Tx, account string) (bool, error) {
	var open bool
	e := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM payments p JOIN subscriptions s ON s.id=p.subscription_id
 WHERE s.account_id=$1 AND (p.status IN ('pending','canceled') OR EXISTS(SELECT 1 FROM payment_review_events e WHERE e.payment_id=p.id)))`, account).Scan(&open)
	return open, e
}
func clubQuoteLocked(ctx context.Context, tx pgx.Tx, acc Account, requested Subscription, p Plan, months int, code string, now time.Time) (ClubQuote, error) {
	var q ClubQuote
	var sub Subscription
	e := tx.QueryRow(ctx, "SELECT id,plan_id,kind,seats,paid_until,lifetime FROM subscriptions WHERE id=$1 AND account_id=$2 FOR UPDATE", requested.ID, acc.ID).Scan(&sub.ID, &sub.PlanID, &sub.Kind, &sub.Seats, &sub.PaidUntil, &sub.Lifetime)
	if errors.Is(e, pgx.ErrNoRows) {
		return q, errors.New("SUBSCRIPTION_NOT_FOUND")
	}
	if e != nil {
		return q, e
	}
	if sub.Lifetime || sub.Kind != "club" || p.Kind != "club" || sub.PlanID != p.ID || p.PricePerSeatRub != 299 {
		return q, errors.New("PAYMENT_INVALID")
	}
	amount, term, e := p.QuotePayment(sub.Seats, months)
	if e != nil {
		return q, e
	}
	q.PaymentQuote = PaymentQuote{BaseAmount: amount, Amount: amount, Days: term.Days, Months: months}
	q.SubscriptionID = sub.ID
	q.Seats = sub.Seats
	q.Operation = "purchase"
	q.ServiceStart = now.UTC()
	if sub.PaidUntil != nil {
		q.Operation = "renewal"
		if sub.PaidUntil.After(q.ServiceStart) {
			q.ServiceStart = *sub.PaidUntil
		}
	}
	q.ServiceEnd = q.ServiceStart.Add(time.Duration(q.Days) * 24 * time.Hour)
	var ent clubEntitlement
	e = tx.QueryRow(ctx, `SELECT promotion_id,coalesce(club_reference,''),coalesce(initial_subscription_id,''),coalesce(initial_seats,0),review_required,starts_at,ends_at,allocated_until_seconds,discount_numerator,discount_kopecks FROM club_promotion_entitlements WHERE account_id=$1 FOR UPDATE`, acc.ID).Scan(&ent.promotion, &ent.club, &ent.subscription, &ent.seats, &ent.review, &ent.start, &ent.end, &ent.cursor, &ent.numerator, &ent.discount)
	exists := e == nil
	if e != nil && !errors.Is(e, pgx.ErrNoRows) {
		return q, e
	}
	if exists && ent.review {
		return q, errors.New("PROMO_REVIEW_REQUIRED")
	}
	q.Entitlement = exists
	if exists || code != "" {
		open, err := clubOpenOrder(ctx, tx, acc.ID)
		if err != nil {
			return q, err
		}
		if open {
			return q, errors.New("PROMO_RECONCILIATION_REQUIRED")
		}
	}
	if code != "" {
		hash, err := promotionHash(code)
		if err != nil {
			return q, err
		}
		var campaign, kind string
		var enabled bool
		var count, capacity int
		err = tx.QueryRow(ctx, "SELECT id,kind,enabled,capacity FROM promotions WHERE code_hash=$1 FOR UPDATE", hash).Scan(&campaign, &kind, &enabled, &capacity)
		if errors.Is(err, pgx.ErrNoRows) || err == nil && (!enabled || kind != "club-launch") {
			return q, errors.New("PROMO_INVALID")
		}
		if err != nil {
			return q, err
		}
		if exists && ent.promotion != campaign {
			return q, errors.New("PROMO_INVALID")
		}
		if !exists {
			err = tx.QueryRow(ctx, "SELECT p.club_reference FROM promotion_club_approvals p JOIN accounts a ON a.id=p.account_id WHERE p.account_id=$1 AND a.account_type='club'", acc.ID).Scan(&ent.club)
			if errors.Is(err, pgx.ErrNoRows) {
				return q, errors.New("PROMO_INVALID")
			}
			if err != nil {
				return q, err
			}
			var purchased bool
			if err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM payments p JOIN subscriptions s ON s.id=p.subscription_id WHERE s.account_id=$1 AND p.status='succeeded' AND p.amount_kopecks>0)`, acc.ID).Scan(&purchased); err != nil {
				return q, err
			}
			if purchased {
				return q, errors.New("PROMO_FIRST_PURCHASE_ONLY")
			}
			if err = tx.QueryRow(ctx, "SELECT count(*) FROM promotion_reservations WHERE promotion_id=$1", campaign).Scan(&count); err != nil {
				return q, err
			}
			if count >= capacity {
				return q, errors.New("PROMO_EXHAUSTED")
			}
			ent.promotion = campaign
			ent.subscription = sub.ID
			ent.seats = sub.Seats
			q.Entitlement = true
			q.NewEntitlement = true
		}
	}
	if q.Entitlement {
		q.PromotionID = ent.promotion
		q.ClubReference = ent.club
		q.WindowStart = ent.start
		q.WindowEnd = ent.end
		q.PriorNumerator = ent.numerator
		q.PriorDiscount = ent.discount
		q.Numerator = ent.numerator
		if sub.ID == ent.subscription {
			if sub.Seats != ent.seats {
				return q, errors.New("PROMO_REVIEW_REQUIRED")
			}
			q.EligibleSeats = ent.seats
			from := ent.cursor
			if ent.start != nil {
				// Whole UTC seconds; ceil the service boundary, never allocate a covered second twice.
				elapsed := int64((q.ServiceStart.Sub(*ent.start) + time.Second - 1) / time.Second)
				if elapsed > from {
					from = elapsed
				}
			}
			if from > clubWindowSeconds {
				from = clubWindowSeconds
			}
			if from < 0 {
				from = 0
			}
			to := from + int64(q.Days)*86400
			if to > clubWindowSeconds {
				to = clubWindowSeconds
			}
			q.BenefitFrom = from
			q.BenefitTo = to
			q.EligibleSeconds = to - from
			q.Amount, q.Numerator, q.DiscountAmount, e = clubBenefitPrice(q.BaseAmount, 29900, q.EligibleSeats, q.EligibleSeconds, ent.numerator, ent.discount)
			if e != nil {
				return q, e
			}
			if q.EligibleSeconds > 0 {
				q.Discount = 30
			}
		}
	}
	// Bind the confirmed money and term to the locked subscription and benefit
	// state. An expired subscription advances its estimated service start with
	// now. Reservation recomputes that interval without invalidating the same
	// offer on every elapsed second.
	q.Version = clubDigest([]any{
		3, q.SubscriptionID, sub.PlanID, sub.PaidUntil,
		q.Seats, q.Months, q.Days, q.BaseAmount, q.Amount, q.Discount, q.DiscountAmount, q.Fee,
		q.PromotionID, q.ClubReference, q.Entitlement, q.NewEntitlement, q.EligibleSeats,
		ent.subscription, ent.seats, ent.start, ent.end, ent.cursor, ent.numerator, ent.discount,
	})
	return q, nil
}

func (s *Store) QuoteClubOrder(ctx context.Context, acc Account, sub Subscription, p Plan, months int, code string, now time.Time) (ClubQuote, error) {
	tx, e := s.DB.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if e != nil {
		return ClubQuote{}, e
	}
	defer tx.Rollback(ctx)
	if e = lockClubAccount(ctx, tx, acc.ID); e != nil {
		return ClubQuote{}, e
	}
	return clubQuoteLocked(ctx, tx, acc, sub, p, months, code, now)
}

type ClubOrder struct {
	ReviewRequired bool      `json:"review_required"`
	ID             string    `json:"id"`
	Quote          ClubQuote `json:"quote"`
	Redirect       string    `json:"redirect,omitempty"`
	Status         string    `json:"status"`
	Existing       bool      `json:"-"`
}

func (s *Store) ReserveClubOrder(ctx context.Context, acc Account, sub Subscription, p Plan, months int, code string, expected *int64, version, key, provider string, now time.Time) (ClubOrder, error) {
	var out ClubOrder
	if !clubOrderKey.MatchString(key) || provider == "" {
		return out, errors.New("PAYMENT_IDEMPOTENCY_REQUIRED")
	}
	tx, e := s.DB.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if e != nil {
		return out, e
	}
	defer tx.Rollback(ctx)
	if e = lockClubAccount(ctx, tx, acc.ID); e != nil {
		return out, e
	}
	requestHash := clubRequestHash(sub.ID, months, code)
	var oldHash string
	var raw []byte
	e = tx.QueryRow(ctx, `SELECT o.payment_id,o.request_hash,o.snapshot,o.redirect_url,p.status,EXISTS(SELECT 1 FROM payment_review_events e WHERE e.payment_id=p.id) FROM club_payment_orders o JOIN payments p ON p.id=o.payment_id WHERE o.account_id=$1 AND o.idempotency_key=$2`, acc.ID, key).Scan(&out.ID, &oldHash, &raw, &out.Redirect, &out.Status, &out.ReviewRequired)
	if e == nil {
		if oldHash != requestHash {
			return out, errors.New("PAYMENT_IDEMPOTENCY_CONFLICT")
		}
		if e = json.Unmarshal(raw, &out.Quote); e != nil {
			return out, e
		}
		if out.ReviewRequired || out.Status != "pending" {
			out.Redirect = ""
		}
		out.Existing = true
		return out, tx.Commit(ctx)
	}
	if !errors.Is(e, pgx.ErrNoRows) {
		return out, e
	}
	q, e := clubQuoteLocked(ctx, tx, acc, sub, p, months, code, now)
	if e != nil {
		return out, e
	}
	if expected != nil && *expected != q.Amount || version != "" && version != q.Version {
		return out, errors.New("PAYMENT_PRICE_CHANGED")
	}
	id, e := security.NewID()
	if e != nil {
		return out, e
	}
	if _, e = tx.Exec(ctx, `INSERT INTO payments(id,subscription_id,provider,provider_payment_id,amount_kopecks,period_days,status,reference) VALUES($1,$2,$3,$4,$5,$6,'pending','club-order-v2')`, id, sub.ID, provider, "reservation:"+id, q.Amount, q.Days); e != nil {
		return out, e
	}
	if q.NewEntitlement {
		if _, e = tx.Exec(ctx, `INSERT INTO club_promotion_entitlements(account_id,promotion_id,club_reference,initial_subscription_id,initial_seats) VALUES($1,$2,$3,$4,$5)`, acc.ID, q.PromotionID, q.ClubReference, sub.ID, q.Seats); e != nil {
			return out, e
		}
		if _, e = tx.Exec(ctx, "INSERT INTO promotion_reservations(id,promotion_id,account_id,payment_id) VALUES($1,$2,$3,$1)", id, q.PromotionID, acc.ID); e != nil {
			return out, e
		}
	}
	var entitlement any
	if q.Entitlement {
		entitlement = acc.ID
		if _, e = tx.Exec(ctx, `UPDATE club_promotion_entitlements SET allocated_until_seconds=greatest(allocated_until_seconds,$2),discount_numerator=$3,discount_kopecks=discount_kopecks+$4 WHERE account_id=$1`, acc.ID, q.BenefitTo, q.Numerator, q.DiscountAmount); e != nil {
			return out, e
		}
	}
	raw, e = json.Marshal(q)
	if e != nil {
		return out, e
	}
	if _, e = tx.Exec(ctx, `INSERT INTO club_payment_orders(payment_id,account_id,idempotency_key,request_hash,snapshot,entitlement_account_id,benefit_from_seconds,benefit_to_seconds) VALUES($1,$2,$3,$4,$5,$6,$7,$8)`, id, acc.ID, key, requestHash, raw, entitlement, q.BenefitFrom, q.BenefitTo); e != nil {
		return out, e
	}
	if _, e = tx.Exec(ctx, "INSERT INTO audit_log(actor,action,entity_id) VALUES($1,'club-order.reserved',$2)", "account:"+acc.ID, id); e != nil {
		return out, e
	}
	out = ClubOrder{ID: id, Quote: q, Status: "pending"}
	return out, tx.Commit(ctx)
}

// Called only inside the shared authenticated success transaction, after the
// account/subscription/payment locks. Cancellation intentionally does nothing.
func consumeClubOrder(ctx context.Context, tx pgx.Tx, provider, providerID string, start time.Time) error {
	_, e := tx.Exec(ctx, `UPDATE club_promotion_entitlements e SET starts_at=$3::timestamptz,ends_at=$3::timestamptz+interval '2160 hours'
 FROM club_payment_orders o JOIN payments p ON p.id=o.payment_id
 WHERE e.account_id=o.entitlement_account_id AND p.provider=$1 AND p.provider_payment_id=$2 AND e.starts_at IS NULL AND NOT e.review_required`, provider, providerID, start.UTC().Truncate(time.Microsecond))
	if e != nil {
		return e
	}
	_, e = tx.Exec(ctx, `UPDATE club_payment_orders o SET state='consumed' FROM payments p WHERE p.id=o.payment_id AND p.provider=$1 AND p.provider_payment_id=$2 AND o.state='open'`, provider, providerID)
	return e
}
func (s *Store) AttachClubRedirect(ctx context.Context, id, provider, providerID, redirect string) error {
	if providerID == "" || len(providerID) > 128 || strings.HasPrefix(providerID, "reservation:") || redirect == "" {
		return errors.New("PAYMENT_INVALID")
	}
	tx, e := s.DB.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if e != nil {
		return e
	}
	defer tx.Rollback(ctx)
	result, e := tx.Exec(ctx, "UPDATE payments SET provider_payment_id=$3 WHERE id=$1 AND provider=$2 AND provider_payment_id=$4 AND status='pending'", id, provider, providerID, "reservation:"+id)
	if e != nil {
		return e
	}
	if result.RowsAffected() != 1 {
		return errors.New("PAYMENT_INVALID")
	}
	if _, e = tx.Exec(ctx, "UPDATE club_payment_orders SET redirect_url=$2 WHERE payment_id=$1", id, redirect); e != nil {
		return e
	}
	return tx.Commit(ctx)
}
func (a *API) payClub(w http.ResponseWriter, r *http.Request, acc Account, sub Subscription, p Plan, months int, code string, expected *int64, version, key string, quoteOnly bool) {
	if quoteOnly {
		q, e := a.Store.QuoteClubOrder(r.Context(), acc, sub, p, months, code, time.Now())
		if e != nil {
			a.promoFail(w, e)
			return
		}
		respond(w, 200, q)
		return
	}
	if expected == nil || version == "" {
		a.fail(w, 409, "PAYMENT_CONFIRMATION_REQUIRED")
		return
	}
	o, e := a.Store.ReserveClubOrder(r.Context(), acc, sub, p, months, code, expected, version, key, a.Settings.Payments.Name(), time.Now())
	if e != nil {
		a.promoFail(w, e)
		return
	}
	if o.Existing {
		if o.Redirect != "" && o.Status == "pending" && !o.ReviewRequired {
			respond(w, 200, o)
			return
		}
		a.fail(w, 409, "PROMO_RECONCILIATION_REQUIRED")
		return
	}
	redirect, providerID, e := a.Settings.Payments.CreatePayment(r.Context(), PaymentRequest{Subscription: sub.ID, AmountKopecks: o.Quote.Amount, PeriodDays: o.Quote.Days, Description: "Подписка VELIQ «" + p.Title + "»", Email: acc.Email, AccountID: acc.ID, ReturnURL: a.Settings.AccountOrigin + "/account.html?payment=return&order=" + o.ID + "&subscription=" + sub.ID})
	if e != nil {
		a.fail(w, 409, "PROMO_RECONCILIATION_REQUIRED")
		return
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), 5*time.Second)
	defer cancel()
	if providerID == "" || len(providerID) > 128 || redirect == "" {
		a.fail(w, 503, "PROMO_RECONCILIATION_REQUIRED")
		return
	}
	if e = a.Store.AttachClubRedirect(ctx, o.ID, a.Settings.Payments.Name(), providerID, redirect); e != nil {
		a.fail(w, 503, "PROMO_RECONCILIATION_REQUIRED")
		return
	}
	o.Redirect = redirect
	respond(w, 200, o)
}

// Account-owned snapshots are returned alongside history, never by an unscoped ID.
func (s *Store) AccountClubOrders(ctx context.Context, acc Account) ([]ClubOrder, error) {
	rows, e := s.DB.Query(ctx, `SELECT o.payment_id,o.snapshot,o.redirect_url,p.status,EXISTS(SELECT 1 FROM payment_review_events e WHERE e.payment_id=p.id) FROM club_payment_orders o JOIN payments p ON p.id=o.payment_id WHERE o.account_id=$1 ORDER BY o.created_at DESC LIMIT 100`, acc.ID)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []ClubOrder{}
	for rows.Next() {
		var o ClubOrder
		var b []byte
		if e = rows.Scan(&o.ID, &b, &o.Redirect, &o.Status, &o.ReviewRequired); e != nil {
			return nil, e
		}
		if e = json.Unmarshal(b, &o.Quote); e != nil {
			return nil, e
		}
		if o.Status != "pending" || o.ReviewRequired {
			o.Redirect = ""
		}
		out = append(out, o)
	}
	return out, rows.Err()
}

// No release API exists: CANCELED is not proof that a payment cannot confirm.
