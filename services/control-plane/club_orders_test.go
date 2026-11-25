package controlplane

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

var fixtureOrderSequence atomic.Int64

func confirmedPayRequest(t *testing.T, c *call, sub string, request map[string]any) map[string]any {
	t.Helper()
	st, q := c.do(t, "POST", "/api/v1/account/subscriptions/"+sub+"/quote", request)
	if st != 200 {
		t.Fatalf("quote: %d %v", st, q)
	}
	request["expected_amount_kopecks"] = q["amount_kopecks"]
	request["quote_version"] = q["quote_version"]
	request["idempotency_key"] = fmt.Sprintf("fixture-order-%016d", fixtureOrderSequence.Add(1))
	return request
}

func TestClubV2FormulaAndSplitRounding(t *testing.T) {
	for _, seats := range []int{1, 3, 36} {
		for i, days := range []int{30, 90, 180, 360} {
			want := []int64{20930, 62790, 152490, 331890}[i] * int64(seats)
			seconds := int64(days) * 86400
			if seconds > clubWindowSeconds {
				seconds = clubWindowSeconds
			}
			got, _, _, e := clubBenefitPrice(29900*int64(seats)*int64(days/30), 29900, seats, seconds, 0, 0)
			if e != nil || got != want {
				t.Fatal(seats, days, got, want, e)
			}
		}
	}
	// Deliberately split at awkward seconds; rounding carries rather than restarting.
	for _, seats := range []int{1, 3, 36} {
		var numerator, discount int64
		for _, seconds := range []int64{1, 7, 111, 2591881, 2592000, 2592000} {
			_, n, d, e := clubBenefitPrice(29900*int64(seats), 29900, seats, seconds, numerator, discount)
			if e != nil {
				t.Fatal(e)
			}
			numerator = n
			discount += d
		}
		if discount != 26910*int64(seats) {
			t.Fatal("split rounding benefit", seats, discount)
		}
	}
}
func clubFixture(t *testing.T) (*Store, Account, Subscription, Plan, string) {
	s := codeStore(t)
	a, sub, p := promoAccount(t, s, "club", 1)
	approve(t, s, a)
	_, code := campaign(t, s, "club-launch")
	return s, a, sub, p, code
}
func reserveFixture(t *testing.T, s *Store, a Account, sub Subscription, p Plan, months int, code string, now time.Time) ClubOrder {
	t.Helper()
	q, e := s.QuoteClubOrder(context.Background(), a, sub, p, months, code, now)
	if e != nil {
		t.Fatal(e)
	}
	o, e := s.ReserveClubOrder(context.Background(), a, sub, p, months, code, &q.Amount, q.Version, fmt.Sprintf("fixture-%024d", fixtureOrderSequence.Add(1)), "platega", now)
	if e != nil {
		t.Fatal(e)
	}
	return o
}
func confirmFixture(t *testing.T, s *Store, o ClubOrder, at time.Time) {
	t.Helper()
	ctx := context.Background()
	if e := s.AttachPromotionPayment(ctx, o.ID, "platega", "tx-"+o.ID); e != nil {
		t.Fatal(e)
	}
	if _, extended, e := s.RecordProviderPayment(ctx, "platega", "tx-"+o.ID, o.Quote.SubscriptionID, o.Quote.Amount, "succeeded", "fixture", at); e != nil || !extended {
		t.Fatal(e, extended)
	}
}

func TestClubQuoteRemainsConfirmableAfterShortPause(t *testing.T) {
	s, a, sub, plan, code := clubFixture(t)
	ctx := context.Background()
	begin := time.Date(2026, 11, 19, 0, 0, 0, 0, time.UTC)
	confirmFixture(t, s, reserveFixture(t, s, a, sub, plan, 1, code, begin), begin)

	shownAt := begin.Add(80 * 24 * time.Hour)
	confirmedAt := shownAt.Add(5 * time.Second)
	shown, err := s.QuoteClubOrder(ctx, a, sub, plan, 12, code, shownAt)
	if err != nil {
		t.Fatal(err)
	}
	later, err := s.QuoteClubOrder(ctx, a, sub, plan, 12, code, confirmedAt)
	if err != nil {
		t.Fatal(err)
	}
	if shown.Amount != later.Amount || later.BenefitFrom != shown.BenefitFrom+5 {
		t.Fatalf("fixture must move the allocation while keeping the same price: before=%+v after=%+v", shown, later)
	}
	order, err := s.ReserveClubOrder(ctx, a, sub, plan, 12, code, &shown.Amount, shown.Version,
		"delayed-confirm-fixture-1", "platega", confirmedAt)
	if err != nil {
		t.Fatalf("same offer should remain confirmable: %v", err)
	}
	if order.Quote.Amount != shown.Amount || order.Quote.BenefitFrom != later.BenefitFrom ||
		order.Quote.BenefitTo != later.BenefitTo || !order.Quote.ServiceStart.Equal(confirmedAt) {
		t.Fatalf("reservation must use current server allocation: %+v", order.Quote)
	}
}

func TestClubQuoteRejectsChangedPriceOrSubscription(t *testing.T) {
	for _, change := range []string{"price", "subscription"} {
		t.Run(change, func(t *testing.T) {
			s, a, sub, plan, code := clubFixture(t)
			ctx := context.Background()
			begin := time.Date(2026, 11, 19, 0, 0, 0, 0, time.UTC)
			confirmFixture(t, s, reserveFixture(t, s, a, sub, plan, 1, code, begin), begin)

			shownAt := begin.Add(10 * 24 * time.Hour)
			months := 1
			if change == "price" {
				shownAt = begin.Add(80 * 24 * time.Hour)
				months = 12
			}
			shown, err := s.QuoteClubOrder(ctx, a, sub, plan, months, code, shownAt)
			if err != nil {
				t.Fatal(err)
			}
			confirmedAt := shownAt
			if change == "price" {
				confirmedAt = shownAt.Add(24 * time.Hour)
			} else if _, err := s.DB.Exec(ctx, "UPDATE subscriptions SET paid_until=paid_until+interval '1 hour' WHERE id=$1", sub.ID); err != nil {
				t.Fatal(err)
			}
			later, err := s.QuoteClubOrder(ctx, a, sub, plan, months, code, confirmedAt)
			if err != nil {
				t.Fatal(err)
			}
			if (later.Amount != shown.Amount) != (change == "price") {
				t.Fatalf("unexpected fixture prices: %d then %d", shown.Amount, later.Amount)
			}
			_, err = s.ReserveClubOrder(ctx, a, sub, plan, months, code, &shown.Amount, shown.Version,
				"stale-confirm-fixture-1", "platega", confirmedAt)
			if err == nil || err.Error() != "PAYMENT_PRICE_CHANGED" {
				t.Fatalf("stale offer should be rejected: %v", err)
			}
			var orders int
			if err := s.DB.QueryRow(ctx, "SELECT count(*) FROM club_payment_orders WHERE account_id=$1", a.ID).Scan(&orders); err != nil || orders != 1 {
				t.Fatalf("stale quote must not reserve another order: count=%d err=%v", orders, err)
			}
		})
	}
}

func TestClubV2SequentialThirtyAndFixedWindow(t *testing.T) {
	s, a, sub, p, code := clubFixture(t)
	ctx := context.Background()
	t0 := time.Date(2026, 11, 19, 0, 0, 0, 0, time.UTC)
	for i := 0; i < 4; i++ {
		o := reserveFixture(t, s, a, sub, p, 1, code, t0.Add(time.Duration(i)*30*24*time.Hour))
		want := int64(62790)
		if i == 3 {
			want = 89700
		}
		if o.Quote.Amount != want {
			t.Fatal(i, o.Quote)
		}
		confirmFixture(t, s, o, t0.Add(time.Duration(i)*30*24*time.Hour))
	}
	var begin, end time.Time
	var slots int
	var num int64
	if e := s.DB.QueryRow(ctx, "SELECT starts_at,ends_at,allocated_until_seconds FROM club_promotion_entitlements WHERE account_id=$1", a.ID).Scan(&begin, &end, &num); e != nil {
		t.Fatal(e)
	}
	s.DB.QueryRow(ctx, "SELECT count(*) FROM promotion_reservations WHERE account_id=$1", a.ID).Scan(&slots)
	if !begin.Equal(t0) || !end.Equal(t0.Add(90*24*time.Hour)) || num != clubWindowSeconds || slots != 1 {
		t.Fatal(begin, end, num, slots)
	}
}
func TestClubV2Day80LatePaymentCancellationAndNoReset(t *testing.T) {
	s, a, sub, p, code := clubFixture(t)
	ctx := context.Background()
	t0 := time.Date(2026, 11, 19, 0, 0, 0, 0, time.UTC)
	first := reserveFixture(t, s, a, sub, p, 1, code, t0)
	confirmFixture(t, s, first, t0)
	late := reserveFixture(t, s, a, sub, p, 12, code, t0.Add(80*24*time.Hour))
	if late.Quote.Amount != 355810*3 || late.Quote.EligibleSeconds != 10*86400 {
		t.Fatal(late.Quote)
	}
	txid := "tx-" + late.ID
	if e := s.AttachPromotionPayment(ctx, late.ID, "platega", txid); e != nil {
		t.Fatal(e)
	}
	if _, _, e := s.RecordProviderPayment(ctx, "platega", txid, sub.ID, late.Quote.Amount, "canceled", "fixture", t0.Add(81*24*time.Hour)); e != nil {
		t.Fatal(e)
	}
	if _, e := s.QuoteClubOrder(ctx, a, sub, p, 1, code, t0.Add(82*24*time.Hour)); e == nil {
		t.Fatal("canceled released benefit")
	}
	if _, _, e := s.RecordPayment(ctx, sub.ID, "manual", "manual-late", 29900, 30, "succeeded", "fixture", "fixture", t0); e == nil {
		t.Fatal("manual raced held order")
	}
	var wg sync.WaitGroup
	var credits atomic.Int64
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			until, added, e := s.RecordProviderPayment(ctx, "platega", txid, sub.ID, late.Quote.Amount, "succeeded", "fixture", t0.Add(100*24*time.Hour))
			if e != nil {
				t.Error(e)
			}
			if !until.Equal(t0.Add(460 * 24 * time.Hour)) {
				t.Error("full promised term lost", until)
			}
			if added {
				credits.Add(1)
			}
		}()
	}
	wg.Wait()
	if credits.Load() != 1 {
		t.Fatal(credits.Load())
	}
	for _, status := range []string{"pending", "canceled", "succeeded"} {
		if _, added, e := s.RecordProviderPayment(ctx, "platega", txid, sub.ID, late.Quote.Amount, status, "fixture", t0.Add(101*24*time.Hour)); e != nil || added {
			t.Fatal(status, e)
		}
	}
	q, e := s.QuoteClubOrder(ctx, a, sub, p, 1, code, t0.Add(101*24*time.Hour))
	if e != nil || q.Amount != 89700 || q.EligibleSeconds != 0 || !q.WindowEnd.Equal(t0.Add(90*24*time.Hour)) {
		t.Fatal(q, e)
	}
}
func TestClubV2SameKeyConcurrencyAndImmutableSnapshot(t *testing.T) {
	s, a, sub, p, code := clubFixture(t)
	ctx := context.Background()
	now := time.Now().UTC()
	q, e := s.QuoteClubOrder(ctx, a, sub, p, 3, code, now)
	if e != nil {
		t.Fatal(e)
	}
	var wg sync.WaitGroup
	var newCount atomic.Int64
	var ids sync.Map
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			o, e := s.ReserveClubOrder(ctx, a, sub, p, 3, code, &q.Amount, q.Version, "same-order-key-0001", "platega", now)
			if e != nil {
				t.Error(e)
				return
			}
			ids.Store(o.ID, true)
			if !o.Existing {
				newCount.Add(1)
			}
		}()
	}
	wg.Wait()
	n := 0
	var id string
	ids.Range(func(k, v any) bool { n++; id = k.(string); return true })
	if n != 1 || newCount.Load() != 1 {
		t.Fatal(n, newCount.Load())
	}
	if _, e = s.ReserveClubOrder(ctx, a, sub, p, 6, code, nil, "", "same-order-key-0001", "platega", now); e == nil || e.Error() != "PAYMENT_IDEMPOTENCY_CONFLICT" {
		t.Fatal(e)
	}
	if _, e = s.ReserveClubOrder(ctx, a, sub, p, 3, code, nil, "", "different-key-0001", "platega", now); e == nil {
		t.Fatal("second open order")
	}
	if _, e = s.DB.Exec(ctx, "UPDATE payments SET amount_kopecks=1 WHERE id=$1", id); e == nil {
		t.Fatal("mutable amount")
	}
	if _, e = s.DB.Exec(ctx, "UPDATE club_payment_orders SET snapshot='{}' WHERE payment_id=$1", id); e == nil {
		t.Fatal("mutable snapshot")
	}
	var slots, orders int
	s.DB.QueryRow(ctx, "SELECT count(*) FROM promotion_reservations").Scan(&slots)
	s.DB.QueryRow(ctx, "SELECT count(*) FROM club_payment_orders").Scan(&orders)
	if slots != 1 || orders != 1 {
		t.Fatal(slots, orders)
	}
}
func TestClubV2NewSubscriptionAndChangedCohortCannotReset(t *testing.T) {
	s, a, sub, p, code := clubFixture(t)
	now := time.Now().UTC().Truncate(time.Second)
	o := reserveFixture(t, s, a, sub, p, 1, code, now)
	confirmFixture(t, s, o, now)
	id, e := s.CreateSubscription(context.Background(), a, p, 1)
	if e != nil {
		t.Fatal(e)
	}
	other := Subscription{ID: id, PlanID: p.ID, Kind: "club", Seats: 1}
	q, e := s.QuoteClubOrder(context.Background(), a, other, p, 1, code, now)
	if e != nil || q.Amount != 29900 || q.EligibleSeconds != 0 {
		t.Fatal(q, e)
	}
	if _, e = s.DB.Exec(context.Background(), "UPDATE subscriptions SET seats=4 WHERE id=$1", sub.ID); e != nil {
		t.Fatal(e)
	}
	if _, e = s.QuoteClubOrder(context.Background(), a, sub, p, 1, code, now); e == nil || e.Error() != "PROMO_REVIEW_REQUIRED" {
		t.Fatal("guessed changed cohort", e)
	}
}
func TestClubV2MissingConfirmationAndUncertainProviderNeverReposts(t *testing.T) {
	api, s, m := accountAPI(t, true)
	a, sub, p := promoAccount(t, s, "club", 1)
	api.Settings.Plans = []Plan{p}
	approve(t, s, a)
	_, code := campaign(t, s, "club-launch")
	provider := &failingPromoProvider{failure: context.DeadlineExceeded}
	api.Settings.Payments = provider
	c := &call{api: api}
	login(t, c, m, a.Email)
	path := "/api/v1/account/subscriptions/" + sub.ID
	if st, _ := c.do(t, "POST", path+"/pay", map[string]any{"months": 1, "promo_code": code}); st != 409 {
		t.Fatal(st)
	}
	request := confirmedPayRequest(t, c, sub.ID, map[string]any{"months": 1, "promo_code": code})
	for i := 0; i < 3; i++ {
		if st, out := c.do(t, "POST", path+"/pay", request); st != 409 || out["error"] != "PROMO_RECONCILIATION_REQUIRED" {
			t.Fatal(st, out)
		}
	}
	if provider.calls.Load() != 1 {
		t.Fatal("blind retry", provider.calls.Load())
	}
	// Early authenticated event cannot attach an arbitrary ID; reconciliation must bind it.
	if _, _, e := s.RecordProviderPayment(context.Background(), "platega", "early", sub.ID, 62790, "succeeded", "fixture", time.Now()); e == nil || e.Error() != "PAYMENT_UNKNOWN" {
		t.Fatal(e)
	}
	var id string
	s.DB.QueryRow(context.Background(), "SELECT id FROM payments WHERE subscription_id=$1", sub.ID).Scan(&id)
	if e := s.AttachPromotionPayment(context.Background(), id, "platega", "early"); e != nil {
		t.Fatal(e)
	}
	if _, added, e := s.RecordProviderPayment(context.Background(), "platega", "early", sub.ID, 62790, "succeeded", "fixture", time.Now()); e != nil || !added {
		t.Fatal(e)
	}
}

func TestClubV2LegacyMigrationUnknownThenEvidenceOnly(t *testing.T) {
	for _, days := range []int{30, 90, 180, 360} {
		t.Run(fmt.Sprint(days), func(t *testing.T) {
			s, a, sub, p, code := clubFixture(t)
			ctx := context.Background()
			t0 := time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC)
			// Reconstruct schema8 only in this fresh synthetic schema. No production dump.
			if _, e := s.DB.Exec(ctx, "DROP TRIGGER club_payment_terms_immutable ON payments; DROP TABLE club_payment_orders,club_promotion_entitlements; DROP FUNCTION club_payment_terms_immutable(),club_order_immutable(); DELETE FROM schema_migrations WHERE version=9"); e != nil {
				t.Fatal(e)
			}
			var promotion string
			s.DB.QueryRow(ctx, "SELECT id FROM promotions WHERE kind='club-launch'").Scan(&promotion)
			oldID := fmt.Sprintf("%032x", 9000+days)
			amount := int64(299 * 3 * (days / 30) * 70)
			if _, e := s.DB.Exec(ctx, "INSERT INTO payments(id,subscription_id,provider,provider_payment_id,amount_kopecks,period_days,status,reference) VALUES($1,$2,'platega',$3,$4,$5,'canceled','historical')", oldID, sub.ID, "old-"+oldID, amount, days); e != nil {
				t.Fatal(e)
			}
			if _, e := s.DB.Exec(ctx, "INSERT INTO promotion_reservations(id,promotion_id,account_id,payment_id) VALUES($1,$2,$3,$1)", oldID, promotion, a.ID); e != nil {
				t.Fatal(e)
			}
			snapshot := func() string {
				var v string
				if e := s.DB.QueryRow(ctx, "SELECT row_to_json(p)::text FROM payments p WHERE id=$1", oldID).Scan(&v); e != nil {
					t.Fatal(e)
				}
				return v
			}
			before := snapshot()
			if e := s.Migrate(ctx); e != nil {
				t.Fatal(e)
			}
			if e := s.Migrate(ctx); e != nil {
				t.Fatal(e)
			}
			if before != snapshot() {
				t.Fatal("legacy rewritten")
			}
			if _, e := s.QuoteClubOrder(ctx, a, sub, p, 1, code, t0); e == nil || e.Error() != "PROMO_REVIEW_REQUIRED" {
				t.Fatal("unknown invented", e)
			}
			if _, added, e := s.RecordProviderPayment(ctx, "platega", "old-"+oldID, sub.ID, amount, "succeeded", "fixture", t0); e != nil || !added {
				t.Fatal("old promise lost", e)
			}
			// Synthetic independently known evidence, NOT automatic migration heuristics.
			covered := int64(min(days, 90)) * 86400
			_, numerator, discount, e := clubBenefitPrice(29900*3*12, 29900, 3, covered, 0, 0)
			if e != nil {
				t.Fatal(e)
			}
			if _, e = s.DB.Exec(ctx, "UPDATE club_promotion_entitlements SET review_required=false,initial_subscription_id=$2,initial_seats=3,starts_at=$3::timestamptz,ends_at=$3::timestamptz+interval '2160 hours',allocated_until_seconds=$4,discount_numerator=$5,discount_kopecks=$6 WHERE account_id=$1", a.ID, sub.ID, t0, covered, numerator, discount); e != nil {
				t.Fatal(e)
			}
			q, e := s.QuoteClubOrder(ctx, a, sub, p, 3, code, t0.Add(30*24*time.Hour))
			if e != nil {
				t.Fatal(e)
			}
			want := int64(269100)
			if days == 30 {
				want = 215280
			}
			if q.Amount != want {
				t.Fatal("legacy remainder", days, q, want)
			}
			if days >= 90 && q.EligibleSeconds != 0 {
				t.Fatal("extra ninety days")
			}
		})
	}
}
func TestClubV2PartialSecondBoundaryAndForeignOwner(t *testing.T) {
	s, a, sub, p, code := clubFixture(t)
	ctx := context.Background()
	t0 := time.Date(2026, 11, 19, 0, 0, 0, 123000000, time.UTC)
	first := reserveFixture(t, s, a, sub, p, 1, code, t0)
	confirmFixture(t, s, first, t0)
	q, e := s.QuoteClubOrder(ctx, a, sub, p, 12, code, t0.Add(90*24*time.Hour-time.Second))
	if e != nil || q.EligibleSeconds != 1 {
		t.Fatal(q, e)
	}
	q, e = s.QuoteClubOrder(ctx, a, sub, p, 12, code, t0.Add(90*24*time.Hour))
	if e != nil || q.EligibleSeconds != 0 {
		t.Fatal(q, e)
	}
	other, _, _ := promoAccount(t, s, "club", 2)
	if _, e = s.QuoteClubOrder(ctx, other, sub, p, 1, code, t0); e == nil || e.Error() != "SUBSCRIPTION_NOT_FOUND" {
		t.Fatal("foreign subscription", e)
	}
}

func TestClubV2ConcurrentAPIKeysPostOnce(t *testing.T) {
	api, s, m := accountAPI(t, true)
	a, sub, p := promoAccount(t, s, "club", 1)
	api.Settings.Plans = []Plan{p}
	approve(t, s, a)
	_, code := campaign(t, s, "club-launch")
	mock := newMockPlatega(t)
	api.Settings.Payments = mock.provider()
	c := &call{api: api}
	login(t, c, m, a.Email)
	request := confirmedPayRequest(t, c, sub.ID, map[string]any{"months": 3, "promo_code": code})
	var wg sync.WaitGroup
	var successes atomic.Int64
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			cc := &call{api: api, cookie: c.cookie}
			q := map[string]any{}
			for k, v := range request {
				q[k] = v
			}
			q["idempotency_key"] = fmt.Sprintf("parallel-order-%016d", i)
			st, out := cc.do(t, "POST", "/api/v1/account/subscriptions/"+sub.ID+"/pay", q)
			if st == 200 {
				successes.Add(1)
			} else if st != 409 || out["error"] != "PROMO_RECONCILIATION_REQUIRED" {
				t.Error(st, out)
			}
		}(i)
	}
	wg.Wait()
	if successes.Load() != 1 || mock.requests.Load() != 1 {
		t.Fatal(successes.Load(), mock.requests.Load())
	}
	var id, key string
	s.DB.QueryRow(context.Background(), "SELECT payment_id,idempotency_key FROM club_payment_orders WHERE account_id=$1", a.ID).Scan(&id, &key)
	request["idempotency_key"] = key
	if st, out := c.do(t, "POST", "/api/v1/account/subscriptions/"+sub.ID+"/pay", request); st != 200 || out["id"] != id || mock.requests.Load() != 1 {
		t.Fatal("retry POST", st, out)
	}
	if _, _, e := s.RecordPayment(context.Background(), sub.ID, "platega", mock.nextTx.Load().(string), 188370, 30, "succeeded", "fixture", "fixture", time.Now()); e == nil || e.Error() != "PAYMENT_MISMATCH" {
		t.Fatal("manual changed frozen days", e)
	}
}

func TestClubV2ReviewNeverOffersAnotherPaymentLink(t *testing.T) {
	s, a, sub, p, code := clubFixture(t)
	ctx := context.Background()
	o := reserveFixture(t, s, a, sub, p, 1, code, time.Now())
	if e := s.AttachClubRedirect(ctx, o.ID, "platega", "reservation:forged", "https://fixture.invalid"); e == nil {
		t.Fatal("placeholder provider id")
	}
	if e := s.AttachClubRedirect(ctx, o.ID, "platega", "review-fixture", "https://fixture.invalid"); e != nil {
		t.Fatal(e)
	}
	if _, _, e := s.RecordProviderPayment(ctx, "platega", "review-fixture", sub.ID, o.Quote.Amount, "review", "fixture", time.Now(), PaymentEvent{ProviderStatus: "DISPUTED"}); e != nil {
		t.Fatal(e)
	}
	orders, e := s.AccountClubOrders(ctx, a)
	if e != nil || len(orders) != 1 || orders[0].Redirect != "" || !orders[0].ReviewRequired {
		t.Fatal(orders, e)
	}
	if _, e = s.QuoteClubOrder(ctx, a, sub, p, 1, code, time.Now()); e == nil {
		t.Fatal("review reopened quota")
	}
}
