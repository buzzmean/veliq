package controlplane

import (
	"context"
	"sync"
	"testing"
	"time"
)

func TestClubPromotionRejectsPreviouslyPaidAccountAcrossSubscriptions(t *testing.T) {
	for _, provider := range []string{"manual", "platega"} {
		t.Run(provider, func(t *testing.T) {
			s := codeStore(t)
			ctx := context.Background()
			acc, old, p := promoAccount(t, s, "club", 1)
			approve(t, s, acc)
			_, code := campaign(t, s, "club-launch")
			if _, _, e := s.RecordPayment(ctx, old.ID, provider, "previous-purchase", 19900, 30, "succeeded", "old price", "fixture", time.Now().Add(-365*24*time.Hour)); e != nil {
				t.Fatal(e)
			}
			nextID, e := s.CreateSubscription(ctx, acc, p, 2)
			if e != nil {
				t.Fatal(e)
			}
			next := Subscription{ID: nextID, Kind: "club", PlanID: p.ID, Seats: 2}
			for _, months := range []int{1, 3, 6, 12} {
				if _, e = s.QuotePromotion(ctx, acc, next, p, months, code); e == nil || e.Error() != "PROMO_FIRST_PURCHASE_ONLY" {
					t.Fatal("old payment escaped", e)
				}
				if _, _, e = s.ReservePromotion(ctx, acc, next, p, months, code, nil, "platega"); e == nil || e.Error() != "PROMO_FIRST_PURCHASE_ONLY" {
					t.Fatal("repeat purchase reserved", e)
				}
			}
			var count int
			s.DB.QueryRow(ctx, "SELECT count(*) FROM promotion_reservations").Scan(&count)
			if count != 0 {
				t.Fatal("rejected club used slot")
			}
			// A refund/dispute does not turn a paid purchase into a first purchase.
			if provider == "platega" {
				if _, _, e = s.RecordProviderPayment(ctx, provider, "previous-purchase", old.ID, 19900, "review", "payment:platega", time.Now(), PaymentEvent{ProviderStatus: "CHARGEBACKED"}); e != nil {
					t.Fatal(e)
				}
				if _, e = s.QuotePromotion(ctx, acc, next, p, 1, code); e == nil {
					t.Fatal("refund reset first purchase")
				}
			}
		})
	}
}

func TestClubPromotionUnverifiedProfileCannotSelfApprove(t *testing.T) {
	api, s, m := accountAPI(t, true)
	ctx := context.Background()
	a, sub, p := promoAccount(t, s, "club", 1)
	api.Settings.Plans = []Plan{p}
	_, code := campaign(t, s, "club-launch")
	provider := &failingPromoProvider{failure: context.DeadlineExceeded}
	api.Settings.Payments = provider
	c := &call{api: api}
	login(t, c, m, a.Email)
	for _, action := range []string{"quote", "pay"} {
		st, out := c.do(t, "POST", "/api/v1/account/subscriptions/"+sub.ID+"/"+action, map[string]any{"months": 1, "promo_code": code})
		if st != 409 || (out["error"] != "PROMO_INVALID" && out["error"] != "PAYMENT_CONFIRMATION_REQUIRED") {
			t.Fatal(st, out)
		}
	}
	st, _ := c.do(t, "POST", "/api/v1/account/profile", map[string]any{"kind": "club", "name": "Self-declared", "verified": true})
	if st < 400 {
		t.Fatal("self verification accepted")
	}
	var approved bool
	s.DB.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM promotion_club_approvals WHERE account_id=$1)", a.ID).Scan(&approved)
	if approved || provider.calls.Load() != 0 {
		t.Fatal("self-declared club reached provider")
	}
	approve(t, s, a)
	other, _, _ := promoAccount(t, s, "club", 2)
	if _, e := s.DB.Exec(ctx, "INSERT INTO promotion_club_approvals(account_id,club_reference) VALUES($1,$2)", other.ID, "club_"+a.ID); e == nil {
		t.Fatal("same real club approved twice")
	}
}

func TestClubPromotionFirstPurchaseAllTermsThenRemainingWindow(t *testing.T) {
	for _, months := range []int{1, 3, 6, 12} {
		s := codeStore(t)
		ctx := context.Background()
		a, sub, p := promoAccount(t, s, "club", 1)
		approve(t, s, a)
		_, code := campaign(t, s, "club-launch")
		id, q, e := s.ReservePromotion(ctx, a, sub, p, months, code, nil, "platega")
		if e != nil || q.Amount != 299*3*(int64(months)*100-int64(min(months, 3))*30) {
			t.Fatal(q, e)
		}
		providerID := "first-" + id
		if e = s.AttachPromotionPayment(ctx, id, "platega", providerID); e != nil {
			t.Fatal(e)
		}
		now := time.Now().UTC().Truncate(time.Microsecond)
		for i := 0; i < 2; i++ {
			until, extended, e := s.RecordProviderPayment(ctx, "platega", providerID, sub.ID, q.Amount, "succeeded", "payment:platega", now)
			if e != nil || extended != (i == 0) || !until.Equal(now.Add(time.Duration(months*30)*24*time.Hour)) {
				t.Fatal("first/duplicate confirmation", e)
			}
		}
		renewal, e := s.ReserveClubPurchase(ctx, a, sub, p, months, nil, "platega")
		if e != nil {
			t.Fatal(e)
		}
		var amount int64
		s.DB.QueryRow(ctx, "SELECT amount_kopecks FROM payments WHERE id=$1", renewal).Scan(&amount)
		want := 299 * 3 * int64(months) * 100
		if months == 1 {
			want = 62790
		}
		if amount != want {
			t.Fatal("permanent discount", amount)
		}
	}
}

func TestClubPromotionExistingUnfinishedOrdersRequireReconciliation(t *testing.T) {
	for _, status := range []string{"pending", "canceled"} {
		s := codeStore(t)
		ctx := context.Background()
		a, sub, p := promoAccount(t, s, "club", 1)
		approve(t, s, a)
		_, code := campaign(t, s, "club-launch")
		if _, _, e := s.RecordPayment(ctx, sub.ID, "platega", "previous-link", 19900, 30, status, "old price", "fixture", time.Now()); e != nil {
			t.Fatal(e)
		}
		if _, _, e := s.ReservePromotion(ctx, a, sub, p, 1, code, nil, "platega"); e == nil || e.Error() != "PROMO_RECONCILIATION_REQUIRED" {
			t.Fatal("old link raced promo", e)
		}
		if _, _, e := s.RecordProviderPayment(ctx, "platega", "previous-link", sub.ID, 19900, "succeeded", "payment:platega", time.Now()); e != nil {
			t.Fatal("old order lost", e)
		}
		if _, e := s.QuotePromotion(ctx, a, sub, p, 1, code); e == nil || e.Error() != "PROMO_FIRST_PURCHASE_ONLY" {
			t.Fatal("late payment ignored", e)
		}
	}
}

func TestClubFirstPurchaseSerializedAgainstOrdinaryAndManualOrders(t *testing.T) {
	for _, manual := range []bool{false, true} {
		s := codeStore(t)
		ctx := context.Background()
		_, code := campaign(t, s, "club-launch")
		for i := 0; i < 12; i++ {
			a, sub, p := promoAccount(t, s, "club", i)
			approve(t, s, a)
			start := make(chan struct{})
			results := make(chan error, 2)
			var wg sync.WaitGroup
			wg.Add(2)
			go func() {
				defer wg.Done()
				<-start
				_, _, e := s.ReservePromotion(ctx, a, sub, p, 1, code, nil, "platega")
				results <- e
			}()
			go func() {
				defer wg.Done()
				<-start
				var e error
				if manual {
					_, _, e = s.RecordPayment(ctx, sub.ID, "manual", "manual-"+a.ID, 29900, 30, "succeeded", "invoice", "admin", time.Now())
				} else {
					_, e = s.ReserveClubPurchase(ctx, a, sub, p, 1, nil, "platega")
				}
				results <- e
			}()
			close(start)
			wg.Wait()
			close(results)
			success := 0
			for e := range results {
				if e == nil {
					success++
				} else if e.Error() != "PROMO_FIRST_PURCHASE_ONLY" && e.Error() != "PROMO_RECONCILIATION_REQUIRED" {
					t.Fatal(e)
				}
			}
			if success != 1 {
				t.Fatal("ordinary/promo race", manual, success)
			}
		}
	}
}
