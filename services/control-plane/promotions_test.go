package controlplane

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func promoAccount(t *testing.T, s *Store, kind string, n int) (Account, Subscription, Plan) {
	t.Helper()
	id := fmt.Sprintf("%032x", n+100)
	email := fmt.Sprintf("club%d@example.test", n)
	if kind == "player" {
		id = OwnerPromoAccountID
		email = OwnerPromoEmail
	}
	acc := Account{ID: id, Email: email}
	_, e := s.DB.Exec(context.Background(), "INSERT INTO accounts(id,email,account_type,display_name) VALUES($1,$2,$3,'Test')", id, email, kind)
	if e != nil {
		t.Fatal(e)
	}
	p := Plan{ID: kind + "-month", Kind: kind, Title: "Test", PricePerSeatRub: 299, PeriodDays: 30, MaxSeats: 500}
	seats := 3
	if kind == "player" {
		p.PricePerSeatRub = 399
		p.MaxSeats = 1
		seats = 1
	}
	subID, e := s.CreateSubscription(context.Background(), acc, p, seats)
	if e != nil {
		t.Fatal(e)
	}
	return acc, Subscription{ID: subID, PlanID: p.ID, Kind: kind, Seats: seats}, p
}
func campaign(t *testing.T, s *Store, kind string) (string, string) {
	t.Helper()
	id, code, e := s.CreatePromotion(context.Background(), kind)
	if e != nil {
		t.Fatal("create disabled campaign", e)
	}
	var on bool
	s.DB.QueryRow(context.Background(), "SELECT enabled FROM promotions WHERE id=$1", id).Scan(&on)
	if on {
		t.Fatal("enabled by default")
	}
	if _, e = s.DB.Exec(context.Background(), "UPDATE promotions SET enabled=true WHERE id=$1", id); e != nil {
		t.Fatal(e)
	}
	return id, code
}
func approve(t *testing.T, s *Store, acc Account) {
	t.Helper()
	if _, e := s.DB.Exec(context.Background(), "INSERT INTO promotion_club_approvals(account_id,club_reference) VALUES($1,$2)", acc.ID, "club_"+acc.ID); e != nil {
		t.Fatal(e)
	}
}

func TestPromotionOwnerIdentityAndQuote(t *testing.T) {
	s := codeStore(t)
	ctx := context.Background()
	if _, _, e := s.CreatePromotion(ctx, "owner-test"); e == nil {
		t.Fatal("identity not verified")
	}
	acc, sub, p := promoAccount(t, s, "player", 1)
	_, code := campaign(t, s, "owner-test")
	q, e := s.QuotePromotion(ctx, acc, sub, p, 1, code)
	if e != nil || q.Amount != 399 || q.BaseAmount != 39900 || q.Discount != 99 || q.Days != 30 {
		t.Fatal("owner quote", q, e)
	}
	for _, months := range []int{3, 6, 12} {
		if _, e = s.QuotePromotion(ctx, acc, sub, p, months, code); e == nil {
			t.Fatal("wrong period accepted")
		}
	}
	other, club, cp := promoAccount(t, s, "club", 2)
	approve(t, s, other)
	if _, e = s.QuotePromotion(ctx, other, club, cp, 1, code); e == nil {
		t.Fatal("transferred owner code")
	}
	if _, e = s.QuotePromotion(ctx, acc, sub, p, 1, strings.Repeat("0", 64)); e == nil {
		t.Fatal("forged code")
	}
	if _, _, e = s.CreatePromotion(ctx, "owner-test"); e == nil {
		t.Fatal("second owner campaign")
	}
	var count int
	s.DB.QueryRow(ctx, "SELECT count(*) FROM promotion_reservations").Scan(&count)
	if count != 0 {
		t.Fatal("quote consumed slot")
	}
	wrong := int64(1)
	if _, _, e = s.ReservePromotion(ctx, acc, sub, p, 1, code, &wrong, "platega"); e == nil {
		t.Fatal("browser price trusted")
	}
}

func TestPromotionClubCapacityAndConcurrentAccounts(t *testing.T) {
	s := codeStore(t)
	ctx := context.Background()
	_, code := campaign(t, s, "club-launch")
	type buyer struct {
		a   Account
		sub Subscription
		p   Plan
	}
	buyers := make([]buyer, 21)
	for i := range buyers {
		a, sub, p := promoAccount(t, s, "club", i)
		buyers[i] = buyer{a, sub, p}
		if _, e := s.QuotePromotion(ctx, a, sub, p, 1, code); e == nil {
			t.Fatal("self-declared club approved")
		}
		approve(t, s, a)
		for _, months := range []int{1, 3, 6, 12} {
			q, e := s.QuotePromotion(ctx, a, sub, p, months, code)
			if e != nil || q.Amount != 299*3*(int64(months)*100-int64(min(months, 3))*30) || q.Days != 30*months {
				t.Fatal("club term quote", q, e)
			}
		}
	}
	var wg sync.WaitGroup
	var reserved atomic.Int32
	var exhausted atomic.Int32
	for i := range buyers {
		b := buyers[i]
		wg.Add(1)
		go func() {
			defer wg.Done()
			id, q, e := s.ReservePromotion(ctx, b.a, b.sub, b.p, 12, code, nil, "platega")
			if e != nil {
				if e.Error() == "PROMO_EXHAUSTED" {
					exhausted.Add(1)
				} else {
					t.Error(e)
				}
				return
			}
			if q.Amount != 331890*3 || q.Discount != 30 {
				t.Error("stacked discount", q)
			}
			if e = s.AttachPromotionPayment(ctx, id, "platega", "tx-"+id); e != nil {
				t.Error(e)
				return
			}
			reserved.Add(1)
		}()
	}
	wg.Wait()
	if reserved.Load() != 20 || exhausted.Load() != 1 {
		t.Fatal(reserved.Load(), exhausted.Load())
	}
	rows, e := s.DB.Query(ctx, "SELECT p.provider_payment_id,p.subscription_id,p.amount_kopecks FROM payments p JOIN promotion_reservations r ON r.payment_id=p.id")
	if e != nil {
		t.Fatal(e)
	}
	type order struct {
		id, sub string
		amount  int64
	}
	var orders []order
	for rows.Next() {
		var o order
		rows.Scan(&o.id, &o.sub, &o.amount)
		orders = append(orders, o)
	}
	rows.Close()
	for _, o := range orders {
		if _, _, e = s.RecordProviderPayment(ctx, "platega", o.id, o.sub, o.amount, "succeeded", "payment:platega", time.Now()); e != nil {
			t.Fatal(e)
		}
	}
	var used int
	s.DB.QueryRow(ctx, "SELECT count(*) FROM promotion_reservations WHERE state='redeemed'").Scan(&used)
	if used != 20 {
		t.Fatal(used)
	}
	late, lateSub, latePlan := promoAccount(t, s, "club", 50)
	approve(t, s, late)
	if _, e = s.QuotePromotion(ctx, late, lateSub, latePlan, 1, code); e == nil || e.Error() != "PROMO_EXHAUSTED" {
		t.Fatal("21st confirmed slot accepted")
	}
	for _, o := range orders {
		if _, extended, e := s.RecordProviderPayment(ctx, "platega", o.id, o.sub, o.amount, "succeeded", "payment:platega", time.Now()); e != nil || extended {
			t.Fatal("duplicate")
		}
	}
	// Owner's campaign does not share the club budget.
	a, sub, p := promoAccount(t, s, "player", 999)
	_, ownerCode := campaign(t, s, "owner-test")
	if _, q, e := s.ReservePromotion(ctx, a, sub, p, 1, ownerCode, nil, "platega"); e != nil || q.Amount != 399 {
		t.Fatal("campaign budgets coupled", e)
	}
}

func TestPromotionConcurrentSameAccountCancellationLateConfirmationAndRefund(t *testing.T) {
	s := codeStore(t)
	ctx := context.Background()
	a, sub, p := promoAccount(t, s, "player", 1)
	_, code := campaign(t, s, "owner-test")
	var wg sync.WaitGroup
	ids := make(chan string, 16)
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			id, _, e := s.ReservePromotion(ctx, a, sub, p, 1, code, nil, "platega")
			if e == nil {
				ids <- id
			} else if e.Error() != "PROMO_RESERVED" {
				t.Error(e)
			}
		}()
	}
	wg.Wait()
	close(ids)
	if len(ids) != 1 {
		t.Fatal("duplicate reservation", len(ids))
	}
	id := <-ids
	providerID := "tx-" + id
	if e := s.AttachPromotionPayment(ctx, id, "platega", providerID); e != nil {
		t.Fatal(e)
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	if _, _, e := s.RecordProviderPayment(ctx, "platega", providerID, sub.ID, 399, "canceled", "payment:platega", now); e != nil {
		t.Fatal(e)
	}
	if _, _, e := s.ReservePromotion(ctx, a, sub, p, 1, code, nil, "platega"); e == nil {
		t.Fatal("canceled link released")
	}
	if _, _, e := s.RecordProviderPayment(ctx, "platega", providerID, sub.ID, 0, "succeeded", "payment:platega", now); e == nil {
		t.Fatal("free extension")
	}
	var credits atomic.Int32
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			until, extended, e := s.RecordProviderPayment(ctx, "platega", providerID, sub.ID, 399, "succeeded", "payment:platega", now)
			if e != nil {
				t.Error(e)
				return
			}
			if !until.Equal(now.Add(30 * 24 * time.Hour)) {
				t.Error("duration")
			}
			if extended {
				credits.Add(1)
			}
		}()
	}
	wg.Wait()
	if credits.Load() != 1 {
		t.Fatal("duplicate credit", credits.Load())
	}
	if _, e := s.QuotePromotion(ctx, a, sub, p, 1, code); e == nil || e.Error() != "PROMO_USED" {
		t.Fatal("spent reusable")
	}
	for _, status := range []string{"DISPUTED", "CHARGEBACKED", "PARTIALLY_REFUNDED"} {
		ev := PaymentEvent{ProviderStatus: status, RefundedKopecks: 1}
		if _, _, e := s.RecordProviderPayment(ctx, "platega", providerID, sub.ID, 399, "review", "payment:platega", now, ev); e != nil {
			t.Fatal(e)
		}
	}
	var redeemed, audits int
	s.DB.QueryRow(ctx, "SELECT count(*) FROM promotion_reservations WHERE state='redeemed'").Scan(&redeemed)
	s.DB.QueryRow(ctx, "SELECT count(*) FROM audit_log WHERE action='payment.succeeded'").Scan(&audits)
	if redeemed != 1 || audits != 1 {
		t.Fatal("invalid minimal audit", redeemed, audits)
	}
}

type failingPromoProvider struct {
	calls   atomic.Int32
	failure error
}

func (p *failingPromoProvider) Name() string { return "platega" }
func (p *failingPromoProvider) CreatePayment(context.Context, PaymentRequest) (string, string, error) {
	p.calls.Add(1)
	return "", "", p.failure
}
func (p *failingPromoProvider) HandleWebhook(*http.Request) (PaymentEvent, error) {
	return PaymentEvent{}, errors.New("rejected")
}

func TestPromotionCreateFailuresNeverRetryOrCredit(t *testing.T) {
	for _, failure := range []error{context.DeadlineExceeded, context.Canceled, errors.New("provider error")} {
		t.Run(failure.Error(), func(t *testing.T) {
			api, s, m := accountAPI(t, true)
			a, sub, p := promoAccount(t, s, "player", 1)
			api.Settings.Plans = []Plan{p}
			_, code := campaign(t, s, "owner-test")
			provider := &failingPromoProvider{failure: failure}
			api.Settings.Payments = provider
			c := &call{api: api}
			login(t, c, m, a.Email)
			path := "/api/v1/account/subscriptions/" + sub.ID
			st, out := c.do(t, "POST", path+"/quote", map[string]any{"months": 1, "promo_code": code})
			if st != 200 || out["amount_kopecks"] != float64(399) {
				t.Fatal(st, out)
			}
			st, _ = c.do(t, "POST", path+"/quote/", map[string]any{"months": 1, "promo_code": code})
			if st != 200 || provider.calls.Load() != 0 {
				t.Fatal("preview created a payment")
			}
			for i := 0; i < 2; i++ {
				st, _ = c.do(t, "POST", path+"/pay", map[string]any{"months": 1, "promo_code": code, "expected_amount_kopecks": 399})
				if st != 409 {
					t.Fatal(st)
				}
			}
			st, _ = c.do(t, "POST", path+"/pay", map[string]any{"months": 1})
			if st != 409 || provider.calls.Load() != 1 {
				t.Fatal("retry escaped", st, provider.calls.Load())
			}
			var paid *time.Time
			s.DB.QueryRow(context.Background(), "SELECT paid_until FROM subscriptions WHERE id=$1", sub.ID).Scan(&paid)
			if paid != nil {
				t.Fatal("credited failure")
			}
		})
	}
}

func TestPromotionRealAdapterWebhookAndRefreshContract(t *testing.T) {
	api, s, m := accountAPI(t, true)
	a, sub, p := promoAccount(t, s, "player", 1)
	api.Settings.Plans = []Plan{p}
	_, code := campaign(t, s, "owner-test")
	mock := newMockPlatega(t)
	api.Settings.Payments = mock.provider()
	c := &call{api: api}
	login(t, c, m, a.Email)
	st, out := c.do(t, "POST", "/api/v1/account/subscriptions/"+sub.ID+"/pay", map[string]any{"months": 1, "promo_code": code, "expected_amount_kopecks": 399})
	if st != 200 {
		t.Fatal(st, out)
	}
	raw, _ := json.Marshal(mock.last)
	if strings.Contains(string(raw), code) {
		t.Fatal("secret sent to provider")
	}
	body, _ := json.Marshal(map[string]any{"id": mock.nextTx.Load().(string), "amount": 3.99, "currency": "RUB", "status": "CONFIRMED", "payload": plategaPayloadPrefix + sub.ID})
	for i := 0; i < 2; i++ {
		w := httptest.NewRecorder()
		api.Handler().ServeHTTP(w, plategaWebhookRequest(mock.provider(), string(body)))
		if w.Code != 200 {
			t.Fatal(w.Code)
		}
	}
	var used int
	s.DB.QueryRow(context.Background(), "SELECT count(*) FROM promotion_reservations WHERE state='redeemed'").Scan(&used)
	if used != 1 {
		t.Fatal("not consumed")
	}
	var paymentID string
	s.DB.QueryRow(context.Background(), "SELECT id FROM payments WHERE subscription_id=$1", sub.ID).Scan(&paymentID)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" || r.URL.Path != "/transaction/"+mock.nextTx.Load().(string) || r.Header.Get("X-Secret") != "test-secret" {
			t.Error("status contract")
		}
		json.NewEncoder(w).Encode(map[string]any{"id": mock.nextTx.Load().(string), "status": "CONFIRMED", "mechantId": "merchant-1", "payload": plategaPayloadPrefix + sub.ID, "paymentDetails": map[string]any{"amount": 3.99, "currency": "RUB"}})
	}))
	defer server.Close()
	api.Settings.Payments = &PlategaProvider{MerchantID: "merchant-1", Secret: "test-secret", BaseURL: server.URL}
	var before, after time.Time
	s.DB.QueryRow(context.Background(), "SELECT paid_until FROM subscriptions WHERE id=$1", sub.ID).Scan(&before)
	st, out = c.do(t, "POST", "/api/v1/account/payments/"+paymentID+"/refresh", map[string]any{})
	if st != 200 || out["status"] != "succeeded" {
		t.Fatal(st, out)
	}
	s.DB.QueryRow(context.Background(), "SELECT paid_until FROM subscriptions WHERE id=$1", sub.ID).Scan(&after)
	if !before.Equal(after) {
		t.Fatal("refresh credited twice")
	}
}

func TestPromotionUncertainCreationReconciliation(t *testing.T) {
	api, s, m := accountAPI(t, true)
	ctx := context.Background()
	a, sub, p := promoAccount(t, s, "player", 1)
	api.Settings.Plans = []Plan{p}
	_, code := campaign(t, s, "owner-test")
	id, _, e := s.ReservePromotion(ctx, a, sub, p, 1, code, nil, "platega")
	if e != nil {
		t.Fatal(e)
	}
	amount := 3.99
	status := "CANCELED"
	var queries atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		queries.Add(1)
		json.NewEncoder(w).Encode(map[string]any{"id": "recovered-tx", "status": status, "mechantId": "merchant-1", "payload": plategaPayloadPrefix + sub.ID, "paymentDetails": map[string]any{"amount": amount, "currency": "RUB"}})
	}))
	defer server.Close()
	api.Settings.Payments = &PlategaProvider{MerchantID: "merchant-1", Secret: "test-secret", BaseURL: server.URL}
	c := &call{api: api}
	login(t, c, m, a.Email)
	st, _ := c.do(t, "POST", "/api/v1/account/payments/"+id+"/refresh", map[string]any{})
	if st != 409 || queries.Load() != 0 {
		t.Fatal("placeholder sent to provider")
	}
	path := "/api/v1/admin/promotions/reconcile"
	q := map[string]any{"payment_id": id, "provider_payment_id": "recovered-tx"}
	if st, _ = c.do(t, "POST", path, q); st != 401 || queries.Load() != 0 {
		t.Fatal("nonadmin reconciliation")
	}
	admin := func(r *http.Request) { r.Header.Set("Authorization", "Bearer "+strings.Repeat("a", 32)) }
	amount = 399
	if st, _ = c.do(t, "POST", path, q, admin); st != 409 {
		t.Fatal("mismatch bound")
	}
	amount = 3.99
	st, out := c.do(t, "POST", path, q, admin)
	if st != 200 || out["status"] != "canceled" || out["promotion_state"] != "reserved" {
		t.Fatal(st, out)
	}
	status = "CONFIRMED"
	for i := 0; i < 2; i++ {
		st, out = c.do(t, "POST", path, q, admin)
		if st != 200 || out["promotion_state"] != "redeemed" {
			t.Fatal(st, out)
		}
	}
	var credits int
	s.DB.QueryRow(ctx, "SELECT count(*) FROM audit_log WHERE action='payment.succeeded'").Scan(&credits)
	if credits != 1 {
		t.Fatal("double reconciliation credit")
	}
}

func TestPromotionMigration008PreservesOldOrdersAndLifetime(t *testing.T) {
	s := codeStore(t)
	ctx := context.Background()
	_, owner, _ := promoAccount(t, s, "player", 1)
	_, club, _ := promoAccount(t, s, "club", 2)
	if _, e := s.DB.Exec(ctx, "UPDATE subscriptions SET lifetime=true WHERE id=$1", owner.ID); e != nil {
		t.Fatal(e)
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	if _, _, e := s.RecordPayment(ctx, club.ID, "platega", "old-199-order", 19900, 30, "pending", "old price", "fixture", now); e != nil {
		t.Fatal(e)
	}
	// Simulate the exact additive boundary in this isolated test schema only.
	if _, e := s.DB.Exec(ctx, "DROP TRIGGER club_payment_terms_immutable ON payments; DROP TABLE club_payment_orders,club_promotion_entitlements; DROP FUNCTION club_payment_terms_immutable(),club_order_immutable(); DROP TABLE promotion_reservations,promotion_club_approvals,promotions; DELETE FROM schema_migrations WHERE version IN (8,9)"); e != nil {
		t.Fatal(e)
	}
	tables := []string{"subscriptions", "payments", "activation_codes", "activation_slots", "account_device_bindings", "devices"}
	snapshot := func(table string) string {
		var v string
		if e := s.DB.QueryRow(ctx, "SELECT coalesce(json_agg(row_to_json(t) ORDER BY row_to_json(t)::text)::text,'[]') FROM "+table+" t").Scan(&v); e != nil {
			t.Fatal(e)
		}
		return v
	}
	before := map[string]string{}
	for _, table := range tables {
		before[table] = snapshot(table)
	}
	if e := s.Migrate(ctx); e != nil {
		t.Fatal(e)
	}
	for _, table := range tables {
		if before[table] != snapshot(table) {
			t.Fatal("migration rewrote", table)
		}
	}
	var campaigns int
	s.DB.QueryRow(ctx, "SELECT count(*) FROM promotions").Scan(&campaigns)
	if campaigns != 0 {
		t.Fatal("migration seeded real code")
	}
	until, extended, e := s.RecordProviderPayment(ctx, "platega", "old-199-order", club.ID, 19900, "succeeded", "payment:platega", now)
	if e != nil || !extended || !until.Equal(now.Add(30*24*time.Hour)) {
		t.Fatal("old frozen order invalidated", e)
	}
}
