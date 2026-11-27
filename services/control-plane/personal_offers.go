package controlplane

import (
	"context"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5"
)

type TrialOffer struct {
	Enabled       bool       `json:"enabled"`
	DurationHours int        `json:"duration_hours"`
	Eligible      bool       `json:"eligible"`
	Active        bool       `json:"active"`
	Until         *time.Time `json:"trial_until,omitempty"`
	Code          string     `json:"code,omitempty"`
}
type FirstPurchaseOffer struct {
	Enabled            bool           `json:"enabled"`
	Eligible           bool           `json:"eligible"`
	PaymentInProgress  bool           `json:"payment_in_progress"`
	Discount           int            `json:"discount_percent"`
	BaseMonth          int64          `json:"base_month_kopecks"`
	Terms              []PaymentQuote `json:"terms"`
	FirstMonthConsumes bool           `json:"first_month_consumes"`
	Stackable          bool           `json:"stackable"`
}
type CommercialOffers struct {
	Trial TrialOffer         `json:"trial"`
	First FirstPurchaseOffer `json:"personal_first_purchase"`
	Club  map[string]any     `json:"club_first20"`
}

func firstPurchaseEligible(ctx context.Context, q interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}, account string) (bool, error) {
	var eligible bool
	err := q.QueryRow(ctx, `SELECT account_type='player' AND NOT disabled AND NOT EXISTS
 (SELECT 1 FROM subscriptions s WHERE s.account_id=accounts.id AND s.kind='player' AND (s.lifetime OR s.seats<>1)) AND NOT EXISTS
 (SELECT 1 FROM payments p JOIN subscriptions s ON s.id=p.subscription_id
  WHERE s.account_id=accounts.id AND s.kind='player' AND p.status='succeeded' AND p.amount_kopecks>0)
 FROM accounts WHERE id=$1`, account).Scan(&eligible)
	return eligible, err
}

// The account lock used by every checkout/callback is already held by callers.
// Eligibility is consumed by the confirmed ledger, never by preview or trial.
func personalQuoteTx(ctx context.Context, tx pgx.Tx, account string, sub Subscription, p Plan, months int, enabled bool) (PaymentQuote, error) {
	amount, term, err := p.QuotePayment(sub.Seats, months)
	q := PaymentQuote{BaseAmount: p.PricePerSeatRub * int64(sub.Seats) * int64(months) * 100, Amount: amount, Discount: term.Discount, Days: term.Days, Months: months}
	if err != nil {
		return q, err
	}
	if !enabled || sub.Kind != "player" || sub.Lifetime || sub.Seats != 1 || p.PricePerSeatRub != 399 || p.PeriodDays != 30 {
		return q, nil
	}
	q.FirstPurchaseEligible, err = firstPurchaseEligible(ctx, tx, account)
	if err != nil {
		return q, err
	}
	q.FirstMonthConsumesOffer = q.FirstPurchaseEligible && months == 1
	if q.FirstPurchaseEligible && (months == 3 || months == 6 || months == 12) {
		q.Discount = 30
		q.Amount = q.BaseAmount * 70 / 100
		q.Promotion = "personal_first_purchase"
	}
	return q, nil
}
func (s *Store) QuotePersonal(ctx context.Context, acc Account, sub Subscription, p Plan, months int, enabled bool) (PaymentQuote, error) {
	tx, err := s.DB.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return PaymentQuote{}, err
	}
	defer tx.Rollback(ctx)
	if _, err = tx.Exec(ctx, "SELECT id FROM accounts WHERE id=$1 AND NOT disabled FOR NO KEY UPDATE", acc.ID); err != nil {
		return PaymentQuote{}, err
	}
	return personalQuoteTx(ctx, tx, acc.ID, sub, p, months, enabled)
}

func (a *API) offers(ctx context.Context) (CommercialOffers, error) {
	_, trial := a.personalTrialPlan()
	o := CommercialOffers{Trial: TrialOffer{Enabled: trial, DurationHours: 24}, First: FirstPurchaseOffer{Discount: 30, BaseMonth: 39900, Terms: []PaymentQuote{}, FirstMonthConsumes: true}, Club: map[string]any{"enabled": false, "discount_percent": 30, "duration_days": 90, "limit": 20}}
	for _, p := range a.Settings.Plans {
		if p.Kind == "player" && p.PricePerSeatRub == 399 && p.PeriodDays == 30 && p.supportsSeats(1) {
			o.First.Enabled = a.Settings.PersonalFirstPurchase && a.Settings.Payments != nil && a.accountLinkAvailable()
			break
		}
	}
	if o.First.Enabled {
		for _, m := range []int{3, 6, 12} {
			base := int64(39900 * m)
			o.First.Terms = append(o.First.Terms, PaymentQuote{BaseAmount: base, Amount: base * 70 / 100, Discount: 30, Days: m * 30, Months: m})
		}
	}
	var club bool
	if err := a.Store.DB.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM promotions WHERE kind='club-launch' AND enabled AND discount=30 AND capacity=20 AND (account_id IS NULL OR EXISTS(SELECT 1 FROM accounts a WHERE a.id=promotions.account_id AND NOT a.disabled)) AND (SELECT count(*) FROM promotion_reservations r WHERE r.promotion_id=promotions.id)<capacity)`).Scan(&club); err != nil {
		return o, err
	}
	o.Club["enabled"] = club && a.Settings.Payments != nil && a.Settings.ClubVerificationToken != "" && a.accountLinkAvailable()
	return o, nil
}
func (a *API) publicOffers(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	o, err := a.offers(r.Context())
	if err != nil {
		a.fail(w, 503, "OFFERS_UNAVAILABLE")
		return
	}
	respond(w, 200, o)
}
func (a *API) accountOffers(w http.ResponseWriter, r *http.Request) {
	if !a.accountRequest(w, r) {
		return
	}
	acc, _, ok := a.session(w, r)
	if !ok {
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	o, err := a.offers(r.Context())
	if err != nil {
		a.fail(w, 503, "OFFERS_UNAVAILABLE")
		return
	}
	if o.Trial.Enabled {
		o.Trial.Code, err = a.Store.trialOffer(r.Context(), acc)
		o.Trial.Eligible = o.Trial.Code != ""
	}
	if err == nil {
		err = a.Store.DB.QueryRow(r.Context(), `SELECT max(trial_until) FROM subscriptions WHERE account_id=$1`, acc.ID).Scan(&o.Trial.Until)
	}
	if o.Trial.Until != nil {
		o.Trial.Active = time.Now().Before(*o.Trial.Until)
	}
	if err == nil && o.First.Enabled {
		o.First.Eligible, err = firstPurchaseEligible(r.Context(), a.Store.DB, acc.ID)
	}
	if err == nil {
		err = a.Store.DB.QueryRow(r.Context(), `SELECT EXISTS(SELECT 1 FROM payments p JOIN subscriptions s ON s.id=p.subscription_id WHERE s.account_id=$1 AND s.kind='player' AND (p.status IN ('pending','canceled') OR EXISTS(SELECT 1 FROM payment_review_events e WHERE e.payment_id=p.id)))`, acc.ID).Scan(&o.First.PaymentInProgress)
	}
	if err != nil {
		a.fail(w, 503, "OFFERS_UNAVAILABLE")
		return
	}
	respond(w, 200, o)
}
