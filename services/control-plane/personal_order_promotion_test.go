package controlplane

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

func personalPromotionFixture(t *testing.T, isolation string) (*API, *Store, *call, string, string) {
	t.Helper()
	api, store, mail := accountAPI(t, true)
	config := store.DB.Config()
	config.ConnConfig.RuntimeParams["default_transaction_isolation"] = isolation
	pool, err := pgxpool.NewWithConfig(context.Background(), config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	store = &Store{pool}
	api.Store = store
	account, sub, plan := promoAccount(t, store, "player", 1)
	api.Settings.Plans = []Plan{plan}
	_, code := campaign(t, store, "owner-test")
	caller := &call{api: api}
	login(t, caller, mail, account.Email)
	return api, store, caller, sub.ID, code
}

func TestPersonalOrderAndOwnerPromotionCannotBypassEachOther(t *testing.T) {
	for _, first := range []string{"ordinary", "owner-promotion"} {
		t.Run(first, func(t *testing.T) {
			api, store, caller, sub, code := personalPromotionFixture(t, "read committed")
			provider := newPersonalProviderEmulator(t, "error", nil)
			api.Settings.Payments = provider.provider()
			path := "/api/v1/account/subscriptions/" + sub
			ordinary := personalPayFixture("owner-ordinary-payment-0001", 1, 39900)
			promotion := map[string]any{"months": 1, "promo_code": code, "expected_amount_kopecks": 399}
			initial, next := ordinary, promotion
			if first == "owner-promotion" {
				initial, next = promotion, ordinary
			}
			if status, _ := caller.do(t, "POST", path+"/pay", initial); status != 409 || provider.creates.Load() != 1 {
				t.Fatal("initial ambiguous provider fixture failed", status, provider.creates.Load())
			}
			// A preview remains advisory; the reciprocal guard belongs to the
			// reservation, not the promotion calculation or its approved terms.
			if first == "ordinary" {
				if status, quote := caller.do(t, "POST", path+"/quote", promotion); status != 200 || quote["amount_kopecks"] != float64(399) {
					t.Fatal("reciprocal guard changed quote-only promo pricing", status, quote)
				}
			}
			if status, result := caller.do(t, "POST", path+"/pay", next); status != 409 || provider.creates.Load() != 1 {
				t.Fatal("other checkout bypassed unresolved personal payment", status, result, provider.creates.Load())
			}
			var count int
			var paid *time.Time
			if err := store.DB.QueryRow(context.Background(), "SELECT (SELECT count(*) FROM payments),paid_until FROM subscriptions WHERE id=$1", sub).Scan(&count, &paid); err != nil || count != 1 || paid != nil {
				t.Fatal("reciprocal guard duplicated or credited payment", count, err)
			}
		})
	}
}

func TestPersonalOrderAndOwnerPromotionConcurrentReservationsSerialize(t *testing.T) {
	for _, isolation := range []string{"read committed", "repeatable read"} {
		t.Run(isolation, func(t *testing.T) {
			api, store, caller, sub, code := personalPromotionFixture(t, isolation)
			provider := newPersonalProviderEmulator(t, "error", nil)
			api.Settings.Payments = provider.provider()
			start := make(chan struct{})
			var wg sync.WaitGroup
			for i := range 16 {
				wg.Add(1)
				go func(i int) {
					defer wg.Done()
					<-start
					parallel := &call{api: api, cookie: caller.cookie}
					request := personalPayFixture(fmt.Sprintf("parallel-personal-key-%04d", i), 1, 39900)
					if i%2 == 1 {
						request = map[string]any{"months": 1, "promo_code": code, "expected_amount_kopecks": 399}
					}
					if status, result := parallel.do(t, "POST", "/api/v1/account/subscriptions/"+sub+"/pay", request); status != 409 {
						t.Error("parallel ambiguous checkout unexpectedly succeeded", status, result)
					}
				}(i)
			}
			close(start)
			wg.Wait()
			var payments, claims int
			if err := store.DB.QueryRow(context.Background(), `SELECT (SELECT count(*) FROM payments),
 (SELECT count(*) FROM personal_payment_orders)+(SELECT count(*) FROM promotion_reservations)`).Scan(&payments, &claims); err != nil || payments != 1 || claims != 1 || provider.creates.Load() != 1 {
				t.Fatal("account lock did not serialize ordinary/promotion creation", payments, claims, provider.creates.Load(), err)
			}
		})
	}
}
