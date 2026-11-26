package controlplane

import (
	"context"
	"strconv"
	"testing"
)

func TestPersonalCheckoutUsesConfiguredSeatCount(t *testing.T) {
	for _, seats := range []int{1, 2, 3} {
		t.Run(strconv.Itoa(seats), func(t *testing.T) {
			api, store, mailer := accountAPI(t, true)
			plan := &api.Settings.Plans[0]
			plan.MaxSeats = 3
			api.Settings.PersonalTrials = true
			mock := newMockPlatega(t)
			api.Settings.Payments = mock.provider()
			customer := &call{api: api}
			login(t, customer, mailer, "personal@example.test")
			if st, out := customer.do(t, "GET", "/api/v1/account/trial", nil); st != 200 || out["available"] != true {
				t.Fatal("seat option disabled one-device trial", st, out)
			}
			create := func(n int) (int, map[string]any) {
				return customer.do(t, "POST", "/api/v1/account/subscriptions", map[string]any{"plan_id": plan.ID, "seats": n})
			}
			if st, _ := create(4); st != 400 {
				t.Fatal("unoffered seat count accepted", st)
			}
			st, created := create(seats)
			if st != 201 {
				t.Fatal("create", st, created)
			}
			subscription := created["id"].(string)
			if st, out := create(seats); st != 201 || out["id"] != subscription {
				t.Fatal("retry created another subscription", st, out)
			}
			if st, out := create(seats%3 + 1); st != 409 || out["error"] != "PERSONAL_SEAT_CHANGE_NOT_AVAILABLE" {
				t.Fatal("duplicate request silently changed seats", st, out)
			}
			path := "/api/v1/account/subscriptions/" + subscription
			st, quote := customer.do(t, "POST", path+"/quote", map[string]any{"months": 1})
			amount := plan.PricePerSeatRub * int64(seats) * 100
			if st != 200 || quote["amount_kopecks"] != float64(amount) {
				t.Fatal("seat quote", st, quote)
			}
			if st, out := customer.do(t, "POST", path+"/pay", map[string]any{"months": 1, "expected_amount_kopecks": amount, "idempotency_key": "personal-seats-fixture-key"}); st != 200 || out["redirect"] == "" {
				t.Fatal("checkout", st, out)
			}
			var ordered int64
			if err := store.DB.QueryRow(context.Background(), "SELECT amount_kopecks FROM payments WHERE subscription_id=$1", subscription).Scan(&ordered); err != nil || ordered != amount {
				t.Fatal("recorded order differs from quote", ordered, err)
			}
			var licensed int
			if err := store.DB.QueryRow(context.Background(), "SELECT seat_limit FROM activation_codes WHERE subscription_id=$1", subscription).Scan(&licensed); err != nil || licensed != seats {
				t.Fatal("activation seat limit differs from the order", licensed, err)
			}
			if st, out := customer.do(t, "GET", "/api/v1/account", nil); st != 200 || len(out["subscriptions"].([]any)) != 1 {
				t.Fatal("account did not retain one subscription", st, out)
			}
		})
	}
}
