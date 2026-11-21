package controlplane

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestOneOffApprovedPricesAndPublicPolicy(t *testing.T) {
	plans, err := LoadPlans("../../deploy/vps/plans.platega.json")
	if err != nil {
		t.Fatal(err)
	}
	var policy struct {
		Prices map[string]int64 `json:"prices"`
		Terms  []struct {
			Months   int
			Discount int
		} `json:"terms"`
	}
	raw, err := os.ReadFile("../../website/assets/pricing-policy.json")
	if err != nil {
		t.Fatal(err)
	}
	if err = json.Unmarshal(raw, &policy); err != nil {
		t.Fatal(err)
	}
	expected := map[string][]int64{"player": {39900, 113715, 215460, 383040}, "club": {29900, 89700, 179400, 358800}}
	for _, plan := range plans {
		if plan.PricePerSeatRub != policy.Prices[plan.Kind] {
			t.Fatal("public/server price mismatch")
		}
		for i, term := range paymentTerms() {
			if policy.Terms[i].Months != term.Months || policy.Terms[i].Discount != term.Discount {
				t.Fatal("public/server terms mismatch")
			}
			for _, seats := range []int{1, 3, 500} {
				if plan.Kind == "player" && seats != 1 {
					continue
				}
				got, gotTerm, err := plan.QuotePayment(seats, term.Months)
				if err != nil || got != expected[plan.Kind][i]*int64(seats) || gotTerm.Days != term.Months*30 {
					t.Fatal(plan.Kind, seats, term, got, err)
				}
			}
		}
		for _, months := range []int{-1, 0, 2, 5, 13, 1000000} {
			if _, _, err := plan.QuotePayment(1, months); err == nil {
				t.Fatal("accepted invalid period", months)
			}
		}
		for _, seats := range []int{0, -1, plan.MaxSeats + 1} {
			if _, _, err := plan.QuotePayment(seats, 1); err == nil {
				t.Fatal("accepted invalid seats", seats)
			}
		}
	}
}

func TestOneOffAllPeriodsPurchaseRenewalAndFrozenOrder(t *testing.T) {
	for _, kind := range []string{"player", "club"} {
		for _, term := range paymentTermsFor(kind) {
			for _, active := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/%d/active=%t", kind, term.Months, active), func(t *testing.T) {
					api, store, mail := accountAPI(t, true)
					mock := newMockPlatega(t)
					api.Settings.Payments = mock.provider()
					plans, err := LoadPlans("../../deploy/vps/plans.platega.json")
					if err != nil {
						t.Fatal(err)
					}
					api.Settings.Plans = plans
					c := &call{api: api}
					login(t, c, mail, "buyer@example.com")
					seats := 1
					if kind == "club" {
						seats = 3
					}
					st, out := c.do(t, "POST", "/api/v1/account/subscriptions", map[string]any{"plan_id": kind + "-month", "seats": seats})
					if st != 201 {
						t.Fatal(st, out)
					}
					sub := out["id"].(string)
					start := time.Now().UTC().Add(-48 * time.Hour).Truncate(time.Microsecond)
					if active {
						start = time.Now().UTC().Add(48 * time.Hour).Truncate(time.Microsecond)
					}
					if _, err = store.DB.Exec(context.Background(), "UPDATE subscriptions SET paid_until=$2 WHERE id=$1", sub, start); err != nil {
						t.Fatal(err)
					}
					plan, _ := api.plan(kind + "-month")
					amount, _, _ := plan.QuotePayment(seats, term.Months)
					st, out = c.do(t, "POST", "/api/v1/account/subscriptions/"+sub+"/pay", confirmedPayRequest(t, c, sub, map[string]any{"months": term.Months, "expected_amount_kopecks": amount}))
					if st != 200 {
						t.Fatal(st, out)
					}
					if mock.last["paymentDetails"].(map[string]any)["amount"].(json.Number).String() != rubles(amount).String() {
						t.Fatal("wrong provider amount", mock.last)
					}
					var stored int64
					var days int
					var ref string
					if err = store.DB.QueryRow(context.Background(), "SELECT amount_kopecks,period_days,reference FROM payments WHERE subscription_id=$1", sub).Scan(&stored, &days, &ref); err != nil || stored != amount || days != term.Days || (kind == "player" && !strings.Contains(ref, fmt.Sprintf("discount=%d", term.Discount))) || (kind == "club" && ref != "club-order-v2") {
						t.Fatal(stored, days, ref, err)
					}
					// Config changes after link creation must not change either price or credit duration.
					api.Settings.Plans = nil
					body, _ := json.Marshal(map[string]any{"id": mock.nextTx.Load().(string), "amount": rubles(amount), "currency": "RUB", "status": "CONFIRMED", "payload": plategaPayloadPrefix + sub})
					before := time.Now().UTC()
					var first time.Time
					for i := 0; i < 2; i++ {
						w := httptest.NewRecorder()
						api.Handler().ServeHTTP(w, plategaWebhookRequest(mock.provider(), string(body)))
						if w.Code != 200 {
							t.Fatal(w.Code, w.Body.String())
						}
						var paid time.Time
						store.DB.QueryRow(context.Background(), "SELECT paid_until FROM subscriptions WHERE id=$1", sub).Scan(&paid)
						if i == 0 {
							first = paid
						} else if !paid.Equal(first) {
							t.Fatal("duplicate credit")
						}
					}
					if active && !first.Equal(start.Add(time.Duration(term.Days)*24*time.Hour)) {
						t.Fatal("active renewal lost remainder", first, start)
					}
					if !active && (first.Before(before.Add(time.Duration(term.Days)*24*time.Hour-time.Second)) || first.After(time.Now().Add(time.Duration(term.Days)*24*time.Hour+time.Second))) {
						t.Fatal("expired renewal not based on confirmation", first)
					}
				})
			}
		}
	}
}

func TestOneOffInvalidRequestsNeverReachProvider(t *testing.T) {
	api, _, mail := accountAPI(t, true)
	mock := newMockPlatega(t)
	api.Settings.Payments = mock.provider()
	c := &call{api: api}
	login(t, c, mail, "buyer@example.com")
	_, out := c.do(t, "POST", "/api/v1/account/subscriptions", map[string]any{"plan_id": "player-month", "seats": 1})
	sub := out["id"].(string)
	for _, q := range []any{map[string]any{"months": 0}, map[string]any{"months": 2}, map[string]any{"months": -1}, map[string]any{"months": 1.5}, map[string]any{"months": "3"}, map[string]any{"months": 3, "expected_amount_kopecks": 1}, map[string]any{"auto_renew": true}, map[string]any{"amount_kopecks": 1}, map[string]any{"promo": "fake"}, nil} {
		if st, out := c.do(t, "POST", "/api/v1/account/subscriptions/"+sub+"/pay", q); st < 400 {
			t.Fatal("accepted", q, st, out)
		}
	}
	if mock.requests.Load() != 0 {
		t.Fatal("invalid request reached provider")
	}
}

func TestPlategaStatusContractAndRefreshOwnership(t *testing.T) {
	api, store, mail := accountAPI(t, true)
	c := &call{api: api}
	login(t, c, mail, "buyer@example.com")
	_, out := c.do(t, "POST", "/api/v1/account/subscriptions", map[string]any{"plan_id": "club-month", "seats": 2})
	sub := out["id"].(string)
	_, _, err := store.RecordPayment(context.Background(), sub, "platega", "tx-1", 40000, 90, "pending", "", "test", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	var id string
	store.DB.QueryRow(context.Background(), "SELECT id FROM payments WHERE subscription_id=$1", sub).Scan(&id)
	var mu sync.Mutex
	calls := 0
	status := "PENDING"
	amount := 400
	merchant := "merchant-1"
	txID := "tx-1"
	payload := plategaPayloadPrefix + sub
	responseCode := 200
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		calls++
		if r.Method != "GET" || r.URL.Path != "/transaction/tx-1" || r.Header.Get("X-Secret") != "test-secret" || r.Header.Get("X-MerchantId") != "merchant-1" {
			t.Error("incorrect status contract")
		}
		w.WriteHeader(responseCode)
		json.NewEncoder(w).Encode(map[string]any{"id": txID, "status": status, "mechantId": merchant, "paymentDetails": map[string]any{"amount": amount, "currency": "RUB"}, "payload": payload})
	}))
	defer server.Close()
	api.Settings.Payments = &PlategaProvider{MerchantID: "merchant-1", Secret: "test-secret", BaseURL: server.URL}
	path := "/api/v1/account/payments/" + id + "/refresh"
	other := &call{api: api}
	login(t, other, mail, "other@example.com")
	if st, _ := other.do(t, "POST", path, map[string]any{}); st != 404 {
		t.Fatal("foreign payment", st)
	}
	if st, _ := c.do(t, "POST", path, map[string]any{}, func(r *http.Request) { r.Header.Set("Origin", "https://evil.test") }); st != 403 {
		t.Fatal("CSRF", st)
	}
	if calls != 0 {
		t.Fatal("foreign request reached provider")
	}
	if st, out := c.do(t, "POST", path, map[string]any{}); st != 200 || out["status"] != "pending" {
		t.Fatal(st, out)
	}
	if st, _ := c.do(t, "POST", path, map[string]any{}); st != 429 {
		t.Fatal("missing throttle", st)
	}
	reset := func() {
		store.DB.Exec(context.Background(), "UPDATE payments SET last_checked_at=NULL WHERE id=$1", id)
	}
	for _, scenario := range []string{"wrong-id", "wrong-merchant", "wrong-payload", "wrong-amount", "network-error", "confirmed"} {
		reset()
		mu.Lock()
		status = "CONFIRMED"
		amount = 400
		merchant = "merchant-1"
		txID = "tx-1"
		payload = plategaPayloadPrefix + sub
		responseCode = 200
		switch scenario {
		case "wrong-id":
			txID = "tx-other"
		case "wrong-merchant":
			merchant = "foreign"
		case "wrong-payload":
			payload = plategaPayloadPrefix + strings.Repeat("a", 32)
		case "wrong-amount":
			amount = 401
		case "network-error":
			responseCode = 503
		}
		mu.Unlock()
		st, out := c.do(t, "POST", path, map[string]any{})
		if scenario == "confirmed" {
			if st != 200 || out["status"] != "succeeded" {
				t.Fatal(scenario, st, out)
			}
		} else if st < 400 {
			t.Fatal(scenario, st, out)
		}
		var paid *time.Time
		store.DB.QueryRow(context.Background(), "SELECT paid_until FROM subscriptions WHERE id=$1", sub).Scan(&paid)
		if scenario != "confirmed" && paid != nil {
			t.Fatal("failure credited", scenario)
		}
	}
	var before time.Time
	store.DB.QueryRow(context.Background(), "SELECT paid_until FROM subscriptions WHERE id=$1", sub).Scan(&before)
	// Concurrent authentic webhook and refresh share the same atomic credit path.
	reset()
	body := fmt.Sprintf(`{"id":"tx-1","amount":400,"currency":"RUB","status":"CONFIRMED","payload":"veliq:sub:%s"}`, sub)
	var wg sync.WaitGroup
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			w := httptest.NewRecorder()
			api.Handler().ServeHTTP(w, plategaWebhookRequest(api.Settings.Payments.(*PlategaProvider), body))
			if w.Code != 200 {
				t.Error(w.Code)
			}
		}()
	}
	c.do(t, "POST", path, map[string]any{})
	wg.Wait()
	var after time.Time
	store.DB.QueryRow(context.Background(), "SELECT paid_until FROM subscriptions WHERE id=$1", sub).Scan(&after)
	if !before.Equal(after) {
		t.Fatal("repeated confirmation extended")
	}
}

func TestPlategaReviewEventsPreserveAccessAndBlockLateCredit(t *testing.T) {
	for _, credited := range []bool{false, true} {
		for _, status := range []string{"CHARGEBACKED", "DISPUTED", "PARTIALLY_REFUNDED"} {
			t.Run(fmt.Sprint(credited, status), func(t *testing.T) {
				api, store, mail := accountAPI(t, true)
				mock := newMockPlatega(t)
				api.Settings.Payments = mock.provider()
				c := &call{api: api}
				login(t, c, mail, "buyer@example.com")
				_, out := c.do(t, "POST", "/api/v1/account/subscriptions", map[string]any{"plan_id": "club-month", "seats": 2})
				sub := out["id"].(string)
				initial := "pending"
				if credited {
					initial = "succeeded"
				}
				before, _, err := store.RecordPayment(context.Background(), sub, "platega", "tx", 40000, 90, initial, "", "test", time.Now())
				if err != nil {
					t.Fatal(err)
				}
				for i := 0; i < 2; i++ {
					body := fmt.Sprintf(`{"id":"tx","amount":400,"currency":"RUB","status":"%s","payload":"veliq:sub:%s","refundId":"refund-1","refundStatus":"Succeeded","refundedAmount":100}`, status, sub)
					w := httptest.NewRecorder()
					api.Handler().ServeHTTP(w, plategaWebhookRequest(mock.provider(), body))
					if w.Code != 200 {
						t.Fatal(w.Code, w.Body.String())
					}
				}
				var count int
				store.DB.QueryRow(context.Background(), "SELECT count(*) FROM payment_review_events").Scan(&count)
				if count != 1 {
					t.Fatal("review not deduplicated", count)
				}
				after, extended, err := store.RecordProviderPayment(context.Background(), "platega", "tx", sub, 40000, "succeeded", "test", time.Now())
				if err != nil || extended || !after.Equal(before) {
					t.Fatal("review changed access", after, before, extended, err)
				}
				_, view := c.do(t, "GET", "/api/v1/account", nil)
				if view["payments"].([]any)[0].(map[string]any)["review_required"] != true {
					t.Fatal("review invisible")
				}
			})
		}
	}
}
