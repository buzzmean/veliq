package controlplane

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

// mockPlatega is a test double of the Platega API: it records the create
// request and answers with a configurable transaction.
type mockPlatega struct {
	t        *testing.T
	requests atomic.Int32
	last     map[string]any
	sawAuth  atomic.Bool
	nextTx   atomic.Value // string: transaction id for the next create response
	server   *httptest.Server
}

func newMockPlatega(t *testing.T) *mockPlatega {
	m := &mockPlatega{t: t}
	m.nextTx.Store("497f6eca-6276-4993-bfeb-53cbbbba6f08")
	m.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		m.requests.Add(1)
		if r.URL.Path != "/v2/transaction/process" || r.Method != "POST" {
			http.Error(w, "not found", 404)
			return
		}
		if r.Header.Get("X-MerchantId") != "merchant-1" || r.Header.Get("X-Secret") != "test-secret" {
			w.WriteHeader(401)
			json.NewEncoder(w).Encode(map[string]any{"code": "Auth:GEN_1001", "message": "Access denied.", "traceId": "trace-42"})
			return
		}
		m.sawAuth.Store(true)
		var body map[string]any
		d := json.NewDecoder(r.Body)
		d.UseNumber()
		if d.Decode(&body) != nil {
			w.WriteHeader(400)
			return
		}
		m.last = body
		tx := m.nextTx.Load().(string)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"transactionId": tx,
			"status":        "PENDING",
			"url":           "https://pay.platega.io/?id=" + tx,
			"expiresIn":     "00:15:00",
		})
	}))
	t.Cleanup(m.server.Close)
	return m
}

func (m *mockPlatega) provider() *PlategaProvider {
	return &PlategaProvider{MerchantID: "merchant-1", Secret: "test-secret", BaseURL: m.server.URL}
}

func plategaRequest(sub string) PaymentRequest {
	return PaymentRequest{Subscription: sub, AmountKopecks: 40000, PeriodDays: 30, Description: "Подписка VELIQ «Клуб»", Email: "Club@Example.com", AccountID: "acc-1", ReturnURL: "https://veliq.app/account.html"}
}

func TestPlategaCreatePaymentMatchesDocumentedContract(t *testing.T) {
	m := newMockPlatega(t)
	redirect, id, e := m.provider().CreatePayment(context.Background(), plategaRequest(strings.Repeat("a", 32)))
	if e != nil || id != "497f6eca-6276-4993-bfeb-53cbbbba6f08" || !strings.HasPrefix(redirect, "https://pay.platega.io/") {
		t.Fatal("create", id, redirect, e)
	}
	if !m.sawAuth.Load() {
		t.Fatal("merchant headers not sent")
	}
	// No paymentMethod: the payer picks the method on Platega's page.
	if _, present := m.last["paymentMethod"]; present {
		t.Fatal("paymentMethod must be omitted", m.last)
	}
	details := m.last["paymentDetails"].(map[string]any)
	// Kopecks must become an exact two-decimal ruble number, never a float tail.
	if details["amount"].(json.Number).String() != "400.00" || details["currency"] != "RUB" {
		t.Fatal("amount conversion", details)
	}
	if m.last["return"] != "https://veliq.app/account.html" || m.last["failedUrl"] != m.last["return"] {
		t.Fatal("return urls", m.last)
	}
	if m.last["payload"] != "veliq:sub:"+strings.Repeat("a", 32) {
		t.Fatal("payload", m.last["payload"])
	}
	meta := m.last["metadata"].(map[string]any)
	if meta["user_email"] != "club@example.com" || meta["userId"] != "acc-1" {
		t.Fatal("metadata", meta)
	}
}

func TestPlategaCreatePaymentRefusesAutoRenew(t *testing.T) {
	m := newMockPlatega(t)
	q := plategaRequest(strings.Repeat("b", 32))
	q.SaveMethod = true
	_, _, e := m.provider().CreatePayment(context.Background(), q)
	if !errors.Is(e, ErrAutoRenewUnavailable) {
		t.Fatal("auto-renew must be refused explicitly", e)
	}
	if m.requests.Load() != 0 {
		t.Fatal("no Platega call allowed for auto-renew")
	}
}

func TestPlategaCreatePaymentSurfacesAPIError(t *testing.T) {
	m := newMockPlatega(t)
	p := m.provider()
	p.Secret = "wrong"
	_, id, e := p.CreatePayment(context.Background(), plategaRequest(strings.Repeat("c", 32)))
	if e == nil || id != "" || !strings.Contains(e.Error(), "Auth:GEN_1001") || !strings.Contains(e.Error(), "trace-42") {
		t.Fatal("api error must surface code and trace id", id, e)
	}
	if strings.Contains(e.Error(), "wrong") {
		t.Fatal("secret must not leak into errors")
	}
}

func TestPlategaCreatePaymentRejectsUnexpectedResponse(t *testing.T) {
	p := &PlategaProvider{MerchantID: "merchant-1", Secret: "test-secret"}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"transactionId": "x", "status": "CONFIRMED", "url": "https://pay.platega.io/?id=x"})
	}))
	defer server.Close()
	p.BaseURL = server.URL
	if _, _, e := p.CreatePayment(context.Background(), plategaRequest(strings.Repeat("d", 32))); e == nil {
		t.Fatal("a freshly created payment must be PENDING")
	}
}

func plategaWebhookRequest(p *PlategaProvider, body string, mutate ...func(*http.Request)) *http.Request {
	r := httptest.NewRequest("POST", "/api/v1/payments/webhook", strings.NewReader(body))
	r.Header.Set("X-MerchantId", "merchant-1")
	r.Header.Set("X-Secret", "test-secret")
	for _, f := range mutate {
		f(r)
	}
	return r
}

func TestPlategaWebhookConfirmedMapsToInternalEvent(t *testing.T) {
	p := &PlategaProvider{MerchantID: "merchant-1", Secret: "test-secret"}
	sub := strings.Repeat("ab", 16)
	body := `{"id":"497f6eca-6276-4993-bfeb-53cbbbba6f08","amount":400,"currency":"RUB","status":"CONFIRMED","paymentMethod":2,"payload":"veliq:sub:` + sub + `"}`
	ev, e := p.HandleWebhook(plategaWebhookRequest(p, body))
	if e != nil {
		t.Fatal(e)
	}
	if ev.ProviderID != "497f6eca-6276-4993-bfeb-53cbbbba6f08" || ev.Subscription != sub || ev.AmountKopecks != 40000 || ev.Status != "succeeded" {
		t.Fatal("event", ev)
	}
}

func TestPlategaWebhookRejectsWrongSecretAndMerchant(t *testing.T) {
	p := &PlategaProvider{MerchantID: "merchant-1", Secret: "test-secret"}
	body := `{"id":"1","amount":400,"currency":"RUB","status":"CONFIRMED","paymentMethod":2,"payload":"veliq:sub:` + strings.Repeat("ab", 16) + `"}`
	if _, e := p.HandleWebhook(plategaWebhookRequest(p, body, func(r *http.Request) { r.Header.Set("X-Secret", "test-secret-") })); e == nil {
		t.Fatal("wrong secret accepted")
	}
	if _, e := p.HandleWebhook(plategaWebhookRequest(p, body, func(r *http.Request) { r.Header.Set("X-MerchantId", "merchant-2") })); e == nil {
		t.Fatal("wrong merchant accepted")
	}
	if _, e := p.HandleWebhook(plategaWebhookRequest(p, body, func(r *http.Request) { r.Header.Del("X-Secret") })); e == nil {
		t.Fatal("missing secret accepted")
	}
}

func TestPlategaWebhookValidatesPayloadCurrencyAndAmount(t *testing.T) {
	p := &PlategaProvider{MerchantID: "merchant-1", Secret: "test-secret"}
	base := `"id":"1","amount":400,"currency":"RUB","status":"CONFIRMED","paymentMethod":2`
	for _, body := range []string{
		`{` + base + `,"payload":"other:` + strings.Repeat("ab", 16) + `"}`,      // foreign payload
		`{` + base + `,"payload":"veliq:sub:not-hex"}`,                            // malformed subscription id
		`{` + base + `,"payload":""}`,                                             // missing payload
		`{"id":"1","amount":400,"currency":"USD","status":"CONFIRMED","paymentMethod":2,"payload":"veliq:sub:` + strings.Repeat("ab", 16) + `"}`, // foreign currency
		`{"id":"1","amount":400.005,"currency":"RUB","status":"CONFIRMED","paymentMethod":2,"payload":"veliq:sub:` + strings.Repeat("ab", 16) + `"}`, // sub-kopeck amount
		`{"id":"1","amount":-1,"currency":"RUB","status":"CONFIRMED","paymentMethod":2,"payload":"veliq:sub:` + strings.Repeat("ab", 16) + `"}`,      // negative
	} {
		if _, e := p.HandleWebhook(plategaWebhookRequest(p, body)); e == nil {
			t.Fatal("accepted", body)
		}
	}
}

func TestPlategaWebhookCanceledAndIgnoredStatuses(t *testing.T) {
	p := &PlategaProvider{MerchantID: "merchant-1", Secret: "test-secret"}
	sub := strings.Repeat("ab", 16)
	for _, s := range []string{"CANCELED", "CHARGEBACKED", "DISPUTED"} {
		ev, e := p.HandleWebhook(plategaWebhookRequest(p, `{"id":"1","amount":400,"currency":"RUB","status":"`+s+`","paymentMethod":2,"payload":"veliq:sub:`+sub+`"}`))
		if e != nil || ev.Status != "canceled" {
			t.Fatal(s, ev, e)
		}
	}
	// PARTIALLY_REFUNDED must not credit; unknown future statuses must not fail.
	for _, s := range []string{"PARTIALLY_REFUNDED", "SOME_FUTURE_STATUS"} {
		if _, e := p.HandleWebhook(plategaWebhookRequest(p, `{"id":"1","amount":400,"currency":"RUB","status":"`+s+`","paymentMethod":2,"payload":"veliq:sub:`+sub+`"}`)); !errors.Is(e, ErrPaymentEventIgnored) {
			t.Fatal(s, "must be ignored", e)
		}
	}
}

func TestPlategaWebhookAmountPrecision(t *testing.T) {
	p := &PlategaProvider{MerchantID: "merchant-1", Secret: "test-secret"}
	sub := strings.Repeat("ab", 16)
	ev, e := p.HandleWebhook(plategaWebhookRequest(p, `{"id":"1","amount":19.99,"currency":"RUB","status":"CONFIRMED","paymentMethod":2,"payload":"veliq:sub:`+sub+`"}`))
	if e != nil || ev.AmountKopecks != 1999 {
		t.Fatal("19.99 RUB must be exactly 1999 kopecks", ev, e)
	}
}

// TestPlategaPaymentEndToEnd drives the whole path against PostgreSQL: cabinet
// pay -> Platega create -> pending row -> webhook -> exactly one credit,
// including duplicates, out-of-order delivery, unknown ids and amount mismatch.
func TestPlategaPaymentEndToEnd(t *testing.T) {
	api, _, m := accountAPI(t, true)
	mock := newMockPlatega(t)
	api.Settings.Payments = mock.provider()
	c := &call{api: api}
	login(t, c, m, "club@example.com")
	st, out := c.do(t, "POST", "/api/v1/account/subscriptions", map[string]any{"plan_id": "club-month", "seats": 2})
	if st != 201 {
		t.Fatal("create", st, out)
	}
	sub := out["id"].(string)
	webhook := func(id, status string, amount float64, mutate ...func(*http.Request)) (int, map[string]any) {
		body := map[string]any{"id": id, "amount": amount, "currency": "RUB", "status": status, "paymentMethod": 2, "payload": "veliq:sub:" + sub}
		raw, _ := json.Marshal(body)
		r := httptest.NewRequest("POST", "/api/v1/payments/webhook", strings.NewReader(string(raw)))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("X-MerchantId", "merchant-1")
		r.Header.Set("X-Secret", "test-secret")
		for _, f := range mutate {
			f(r)
		}
		w := httptest.NewRecorder()
		api.Handler().ServeHTTP(w, r)
		res := map[string]any{}
		json.Unmarshal(w.Body.Bytes(), &res)
		return w.Code, res
	}
	paidUntil := func() string {
		st, out := c.do(t, "GET", "/api/v1/account", nil)
		if st != 200 {
			t.Fatal("account", st)
		}
		v := out["subscriptions"].([]any)[0].(map[string]any)["paid_until"]
		if v == nil {
			return ""
		}
		return v.(string)
	}
	// Auto-renew is refused explicitly, without a Platega call.
	callsBefore := mock.requests.Load()
	if st, out = c.do(t, "POST", "/api/v1/account/subscriptions/"+sub+"/pay", map[string]any{"auto_renew": true}); st != 409 || out["error"] != "PAYMENT_AUTORENEW_UNAVAILABLE" {
		t.Fatal("auto-renew", st, out)
	}
	if mock.requests.Load() != callsBefore {
		t.Fatal("auto-renew attempt reached Platega")
	}
	st, out = c.do(t, "POST", "/api/v1/account/subscriptions/"+sub+"/pay", map[string]any{})
	if st != 200 || out["redirect"] == "" {
		t.Fatal("pay", st, out)
	}
	if paidUntil() != "" {
		t.Fatal("paid before the webhook")
	}
	tx := "497f6eca-6276-4993-bfeb-53cbbbba6f08"
	// Wrong secret, unknown payment, foreign amount: all rejected, nothing credits.
	if st, _ = webhook(tx, "CONFIRMED", 400, func(r *http.Request) { r.Header.Set("X-Secret", "nope") }); st != 400 {
		t.Fatal("wrong secret", st)
	}
	if st, out = webhook("00000000-0000-0000-0000-000000000000", "CONFIRMED", 400); st != 400 || out["error"] != "PAYMENT_UNKNOWN" {
		t.Fatal("unknown payment", st, out)
	}
	if st, out = webhook(tx, "CONFIRMED", 500); st != 400 || out["error"] != "PAYMENT_MISMATCH" {
		t.Fatal("amount mismatch", st, out)
	}
	if paidUntil() != "" {
		t.Fatal("credited by rejected webhooks")
	}
	// The real notification credits exactly once; a redelivery is a no-op.
	if st, _ = webhook(tx, "CONFIRMED", 400); st != 200 {
		t.Fatal("confirmed", st)
	}
	first := paidUntil()
	if first == "" {
		t.Fatal("not credited")
	}
	if st, _ = webhook(tx, "CONFIRMED", 400); st != 200 {
		t.Fatal("duplicate", st)
	}
	if paidUntil() != first {
		t.Fatal("duplicate webhook credited twice")
	}
	// A dispute after success must not reopen the payment.
	if st, _ = webhook(tx, "DISPUTED", 400); st != 200 {
		t.Fatal("disputed", st)
	}
	if paidUntil() != first {
		t.Fatal("dispute reopened a succeeded payment")
	}
	// Out of order for the next payment: CANCELED first, CONFIRMED second.
	mock2tx := "11111111-2222-3333-4444-555555555555"
	mock.nextTx.Store(mock2tx)
	if st, _ = c.do(t, "POST", "/api/v1/account/subscriptions/"+sub+"/pay", map[string]any{}); st != 200 {
		t.Fatal("second pay", st)
	}
	if st, _ = webhook(mock2tx, "CANCELED", 400); st != 200 {
		t.Fatal("canceled", st)
	}
	if paidUntil() != first {
		t.Fatal("cancel moved the paid period")
	}
	if st, _ = webhook(mock2tx, "CONFIRMED", 400); st != 200 {
		t.Fatal("late confirm", st)
	}
	if paidUntil() <= first {
		t.Fatal("late confirm did not extend")
	}
}
