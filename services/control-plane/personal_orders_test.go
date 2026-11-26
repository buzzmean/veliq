package controlplane

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

type personalProviderRecord struct {
	Payload, Status, Merchant string
	Amount                    json.Number
}

type personalProviderEmulator struct {
	server  *httptest.Server
	creates atomic.Int64
	mu      sync.Mutex
	records map[string]personalProviderRecord
}

// Uses the real Platega adapter over loopback HTTP. The provider records a
// transaction before optionally losing its create response, just as an
// ambiguous production transport error cannot prove no order was created.
func newPersonalProviderEmulator(t *testing.T, mode string, beforeReply func()) *personalProviderEmulator {
	t.Helper()
	p := &personalProviderEmulator{records: map[string]personalProviderRecord{}}
	p.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-MerchantId") != "merchant-1" || r.Header.Get("X-Secret") != "test-secret" {
			w.WriteHeader(401)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if r.Method == "POST" && r.URL.Path == "/v2/transaction/process" {
			var body struct {
				Payload string `json:"payload"`
				Details struct {
					Amount json.Number `json:"amount"`
				} `json:"paymentDetails"`
			}
			if json.NewDecoder(r.Body).Decode(&body) != nil {
				w.WriteHeader(400)
				return
			}
			id := fmt.Sprintf("personal-fixture-tx-%d", p.creates.Add(1))
			p.mu.Lock()
			p.records[id] = personalProviderRecord{Payload: body.Payload, Amount: body.Details.Amount, Status: "PENDING", Merchant: "merchant-1"}
			p.mu.Unlock()
			if beforeReply != nil {
				beforeReply()
			}
			switch mode {
			case "timeout":
				<-r.Context().Done()
				return
			case "error":
				w.WriteHeader(502)
				_, _ = w.Write([]byte(`{"code":"FIXTURE_UNCERTAIN"}`))
				return
			case "invalid":
				_, _ = w.Write([]byte(`{"status":"PENDING"}`))
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"transactionId": id, "status": "PENDING", "url": "https://pay.example.test/" + id})
			return
		}
		if r.Method == "GET" && strings.HasPrefix(r.URL.Path, "/transaction/") {
			id := strings.TrimPrefix(r.URL.Path, "/transaction/")
			p.mu.Lock()
			record, ok := p.records[id]
			p.mu.Unlock()
			if !ok {
				w.WriteHeader(404)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"id": id, "status": record.Status, "mechantId": record.Merchant,
				"payload": record.Payload, "paymentDetails": map[string]any{"amount": record.Amount, "currency": "RUB"}})
			return
		}
		w.WriteHeader(404)
	}))
	t.Cleanup(func() { p.server.CloseClientConnections(); p.server.Close() })
	return p
}

func (p *personalProviderEmulator) provider() *PlategaProvider {
	return &PlategaProvider{MerchantID: "merchant-1", Secret: "test-secret", BaseURL: p.server.URL}
}

func (p *personalProviderEmulator) update(id string, change func(*personalProviderRecord)) {
	p.mu.Lock()
	defer p.mu.Unlock()
	record := p.records[id]
	change(&record)
	p.records[id] = record
}

func personalOrderFixture(t *testing.T) (*API, *Store, *call, Account, string, Plan) {
	t.Helper()
	api, store, mail := accountAPI(t, true)
	api.Settings.Plans[0].PricePerSeatRub = 399
	caller := &call{api: api}
	login(t, caller, mail, "personal-order@example.test")
	account, err := store.SessionAccount(context.Background(), caller.cookie, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	status, result := caller.do(t, "POST", "/api/v1/account/subscriptions", map[string]any{"plan_id": "player-month", "seats": 1})
	if status != 201 {
		t.Fatal(status, result)
	}
	return api, store, caller, account, result["id"].(string), api.Settings.Plans[0]
}

func personalPayFixture(key string, months int, amount int64) map[string]any {
	return map[string]any{"months": months, "expected_amount_kopecks": amount, "idempotency_key": key, "auto_renew": false}
}

func TestPersonalOrderConcurrentRequestsPersistBeforeSingleProviderCreate(t *testing.T) {
	api, store, caller, account, sub, _ := personalOrderFixture(t)
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	provider := newPersonalProviderEmulator(t, "", func() {
		var durable bool
		err := store.DB.QueryRow(context.Background(), `SELECT EXISTS(SELECT 1 FROM personal_payment_orders o
 JOIN payments p ON p.id=o.payment_id WHERE o.account_id=$1 AND p.subscription_id=$2
 AND p.amount_kopecks=39900 AND p.provider_payment_id='reservation:'||p.id AND o.state='open')`, account.ID, sub).Scan(&durable)
		if err != nil || !durable {
			t.Error("provider called before durable reservation", err)
		}
		once.Do(func() { close(entered) })
		<-release
	})
	api.Settings.Payments = provider.provider()
	secondAPI, err := New(store, api.Settings)
	if err != nil {
		t.Fatal(err)
	}
	if err = secondAPI.Initialize(context.Background()); err != nil {
		t.Fatal(err)
	}
	path := "/api/v1/account/subscriptions/" + sub + "/pay"
	request := personalPayFixture("personal-stable-key-0001", 1, 39900)
	first := make(chan map[string]any, 1)
	go func() {
		status, result := caller.do(t, "POST", path, request)
		if status != 200 {
			t.Error(status, result)
		}
		first <- result
	}()
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		close(release)
		t.Fatal("provider not reached")
	}
	var wg sync.WaitGroup
	for i := range 12 {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			instance := api
			if i%3 == 0 {
				instance = secondAPI
			}
			parallel := &call{api: instance, cookie: caller.cookie}
			key := "personal-stable-key-0001"
			want := "PAYMENT_RECONCILIATION_REQUIRED"
			if i%2 == 1 {
				key, want = fmt.Sprintf("other-tab-key-%016d", i), "PAYMENT_IN_PROGRESS"
			}
			status, result := parallel.do(t, "POST", path, personalPayFixture(key, 1, 39900))
			if status != 409 || result["error"] != want {
				t.Error("parallel request bypassed creation claim", status, result)
			}
		}(i)
	}
	wg.Wait()
	close(release)
	result := <-first
	if provider.creates.Load() != 1 || result["redirect"] == "" || result["id"] == nil {
		t.Fatal("concurrent requests created multiple provider orders", provider.creates.Load(), result)
	}
	for range 4 {
		status, repeated := caller.do(t, "POST", path, request)
		if status != 200 || repeated["id"] != result["id"] || repeated["redirect"] != result["redirect"] {
			t.Fatal("same confirmed order was not reused", status, repeated)
		}
	}
	for _, changed := range []map[string]any{
		personalPayFixture("personal-stable-key-0001", 3, 113715),
		personalPayFixture("personal-stable-key-0001", 1, 1),
	} {
		if status, out := caller.do(t, "POST", path, changed); status != 409 || out["error"] != "PAYMENT_IDEMPOTENCY_CONFLICT" {
			t.Fatal("key reused with changed confirmed terms", status, out)
		}
	}
	// Legacy accounts may contain another independently owned player right.
	// Reusing a key for that ID must conflict rather than silently renew it.
	otherSub := strings.Repeat("b", 32)
	if _, err := store.DB.Exec(context.Background(), `INSERT INTO subscriptions(id,account_id,plan_id,kind,seats)
 SELECT $1,account_id,plan_id,kind,seats FROM subscriptions WHERE id=$2`, otherSub, sub); err != nil {
		t.Fatal(err)
	}
	if status, out := caller.do(t, "POST", "/api/v1/account/subscriptions/"+otherSub+"/pay", request); status != 409 || out["error"] != "PAYMENT_IDEMPOTENCY_CONFLICT" {
		t.Fatal("same key was reassigned to another owned subscription", status, out)
	}
	var payments, orders int
	var paid *time.Time
	if err := store.DB.QueryRow(context.Background(), `SELECT (SELECT count(*) FROM payments),(SELECT count(*) FROM personal_payment_orders),paid_until FROM subscriptions WHERE id=$1`, sub).Scan(&payments, &orders, &paid); err != nil || payments != 1 || orders != 1 || paid != nil || provider.creates.Load() != 1 {
		t.Fatal("reservation duplicated or credited unpaid access", payments, orders, paid, err)
	}
}

func TestPersonalOrderAmbiguousCreateSurvivesNewAPIInstanceWithoutRetry(t *testing.T) {
	for _, mode := range []string{"timeout", "error", "invalid"} {
		t.Run(mode, func(t *testing.T) {
			api, store, caller, _, sub, _ := personalOrderFixture(t)
			provider := newPersonalProviderEmulator(t, mode, nil)
			adapter := provider.provider()
			adapter.HTTP = &http.Client{Timeout: 50 * time.Millisecond}
			api.Settings.Payments = adapter
			path := "/api/v1/account/subscriptions/" + sub + "/pay"
			request := personalPayFixture("personal-ambiguous-key-0001", 1, 39900)
			status, result := caller.do(t, "POST", path, request)
			if status != 409 || result["error"] != "PAYMENT_RECONCILIATION_REQUIRED" {
				t.Fatal("ambiguous creation was not retained", status, result)
			}
			restarted, err := New(store, api.Settings)
			if err != nil {
				t.Fatal(err)
			}
			if err = restarted.Initialize(context.Background()); err != nil {
				t.Fatal(err)
			}
			caller.api = restarted
			for range 2 {
				if status, result = caller.do(t, "POST", path, request); status != 409 || result["error"] != "PAYMENT_RECONCILIATION_REQUIRED" {
					t.Fatal("new server instance retried ambiguous creation", status, result)
				}
			}
			if status, result = caller.do(t, "POST", path, personalPayFixture("new-key-after-timeout-0001", 1, 39900)); status != 409 || result["error"] != "PAYMENT_IN_PROGRESS" {
				t.Fatal("new key bypassed unknown result", status, result)
			}
			if status, result = caller.do(t, "POST", path, map[string]any{"months": 1, "expected_amount_kopecks": 39900}); status != 400 || result["error"] != "PAYMENT_IDEMPOTENCY_REQUIRED" {
				t.Fatal("old tab silently created another payment", status, result)
			}
			var placeholder string
			var paid *time.Time
			if err = store.DB.QueryRow(context.Background(), "SELECT p.provider_payment_id,s.paid_until FROM payments p JOIN subscriptions s ON s.id=p.subscription_id WHERE s.id=$1", sub).Scan(&placeholder, &paid); err != nil || !strings.HasPrefix(placeholder, "reservation:") || paid != nil || provider.creates.Load() != 1 {
				t.Fatal("uncertainty discarded or granted access", err, provider.creates.Load())
			}
		})
	}
}

func TestPersonalOrderCommitFailureCannotReachProvider(t *testing.T) {
	api, store, caller, _, sub, _ := personalOrderFixture(t)
	provider := newPersonalProviderEmulator(t, "", nil)
	api.Settings.Payments = provider.provider()
	ctx := context.Background()
	if _, err := store.DB.Exec(ctx, `CREATE FUNCTION reject_personal_commit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'fixture commit failure'; END $$;
 CREATE CONSTRAINT TRIGGER reject_personal_commit AFTER INSERT ON personal_payment_orders DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION reject_personal_commit()`); err != nil {
		t.Fatal(err)
	}
	path := "/api/v1/account/subscriptions/" + sub + "/pay"
	request := personalPayFixture("personal-commit-failure-0001", 1, 39900)
	if status, result := caller.do(t, "POST", path, request); status != 503 || result["error"] != "ACCOUNT_UNAVAILABLE" {
		t.Fatal("failed commit was accepted", status, result)
	}
	var payments int
	if err := store.DB.QueryRow(ctx, "SELECT count(*) FROM payments").Scan(&payments); err != nil || payments != 0 || provider.creates.Load() != 0 {
		t.Fatal("provider invoked before successful commit", payments, provider.creates.Load(), err)
	}
	if _, err := store.DB.Exec(ctx, "DROP TRIGGER reject_personal_commit ON personal_payment_orders"); err != nil {
		t.Fatal(err)
	}
	if status, result := caller.do(t, "POST", path, request); status != 200 || provider.creates.Load() != 1 {
		t.Fatal("rolled back reservation prevented safe first attempt", status, result)
	}
}

func TestPersonalOrderFrozenCreditAndReplayPreservePaidRemainder(t *testing.T) {
	api, store, caller, account, sub, plan := personalOrderFixture(t)
	provider := newPersonalProviderEmulator(t, "", nil)
	api.Settings.Payments = provider.provider()
	ctx := context.Background()
	start := time.Now().UTC().Add(48 * time.Hour).Truncate(time.Microsecond)
	if _, err := store.DB.Exec(ctx, "UPDATE subscriptions SET paid_until=$2 WHERE id=$1", sub, start); err != nil {
		t.Fatal(err)
	}
	path := "/api/v1/account/subscriptions/" + sub + "/pay"
	request := personalPayFixture("personal-frozen-key-0001", 3, 113715)
	status, result := caller.do(t, "POST", path, request)
	if status != 200 {
		t.Fatal(status, result)
	}
	id := result["id"].(string)
	api.Settings.Plans = nil
	if status, repeated := caller.do(t, "POST", path, request); status != 200 || repeated["id"] != id || repeated["redirect"] != result["redirect"] {
		t.Fatal("configuration change replaced frozen order", status, repeated)
	}
	for _, update := range []string{
		"UPDATE payments SET amount_kopecks=1 WHERE id=$1", "UPDATE payments SET period_days=1 WHERE id=$1",
		"UPDATE personal_payment_orders SET snapshot='{}' WHERE payment_id=$1", "UPDATE personal_payment_orders SET request_hash=repeat('0',64) WHERE payment_id=$1",
	} {
		if _, err := store.DB.Exec(ctx, update, id); err == nil {
			t.Fatal("frozen financial terms were mutable")
		}
	}
	// CANCELED is not an irrevocable release: the same provider transaction
	// may confirm later and must still credit only the original frozen term.
	if _, extended, err := store.RecordProviderPayment(ctx, "platega", "personal-fixture-tx-1", sub, 113715, "canceled", "fixture:provider", time.Now()); err != nil || extended {
		t.Fatal("cancellation credited or discarded the order", err)
	}
	nextAmount := int64(39900)
	if _, err := store.ReservePersonalOrder(ctx, account, sub, plan, 1, &nextAmount, "canceled-is-not-released-0001", "platega"); err == nil || err.Error() != "PAYMENT_IN_PROGRESS" {
		t.Fatal("canceled provider order released its creation claim", err)
	}
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, _, err := store.RecordProviderPayment(ctx, "platega", "personal-fixture-tx-1", sub, 113715, "succeeded", "fixture:provider", time.Now()); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	var paid time.Time
	var state string
	var credits int
	if err := store.DB.QueryRow(ctx, `SELECT s.paid_until,o.state,(SELECT count(*) FROM audit_log WHERE action='payment.succeeded')
 FROM subscriptions s JOIN payments p ON p.subscription_id=s.id JOIN personal_payment_orders o ON o.payment_id=p.id WHERE p.id=$1`, id).Scan(&paid, &state, &credits); err != nil || !paid.Equal(start.Add(90*24*time.Hour)) || state != "consumed" || credits != 1 {
		t.Fatal("frozen credit duplicated or paid remainder lost", state, credits, err)
	}
	if status, repeated := caller.do(t, "POST", path, request); status != 200 || repeated["id"] != id || repeated["status"] != "succeeded" || repeated["redirect"] != nil || provider.creates.Load() != 1 {
		t.Fatal("paid replay created another charge or exposed stale link", status, repeated)
	}
	if _, _, err := store.RecordPayment(ctx, sub, "platega", "personal-fixture-tx-1", 113715, 1, "succeeded", "fixture", "fixture", time.Now()); err == nil || err.Error() != "PAYMENT_MISMATCH" {
		t.Fatal("legacy writer bypassed frozen period", err)
	}
	if _, err := store.PersonalOrder(ctx, "not-the-owner", id); err != pgx.ErrNoRows {
		t.Fatal("cross-account order disclosed", err)
	}
	api.Settings.Plans = []Plan{plan}
	if status, next := caller.do(t, "POST", path, personalPayFixture("personal-next-renewal-0001", 1, 39900)); status != 200 || next["id"] == id || provider.creates.Load() != 2 {
		t.Fatal("explicit later renewal blocked or reused previous payment", status, next)
	}
	if _, err := store.PersonalOrder(ctx, account.ID, id); err != nil {
		t.Fatal("renewal removed original order", err)
	}
}

func TestPersonalOrderProviderResultWriteFailureNeverReposts(t *testing.T) {
	api, store, caller, _, sub, _ := personalOrderFixture(t)
	provider := newPersonalProviderEmulator(t, "", nil)
	api.Settings.Payments = provider.provider()
	if _, err := store.DB.Exec(context.Background(), `CREATE FUNCTION reject_personal_binding() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'fixture binding failure'; END $$;
 CREATE TRIGGER reject_personal_binding BEFORE UPDATE OF provider_payment_id ON payments FOR EACH ROW EXECUTE FUNCTION reject_personal_binding()`); err != nil {
		t.Fatal(err)
	}
	path := "/api/v1/account/subscriptions/" + sub + "/pay"
	request := personalPayFixture("personal-bind-failure-0001", 1, 39900)
	if status, result := caller.do(t, "POST", path, request); status != 503 || result["error"] != "PAYMENT_RECONCILIATION_REQUIRED" {
		t.Fatal("unknown binding result discarded", status, result)
	}
	for range 2 {
		if status, result := caller.do(t, "POST", path, request); status != 409 || result["error"] != "PAYMENT_RECONCILIATION_REQUIRED" {
			t.Fatal("binding failure restarted provider creation", status, result)
		}
	}
	if provider.creates.Load() != 1 {
		t.Fatal("provider transaction created twice", provider.creates.Load())
	}
}

func TestPersonalOrderMissingKeyOrConfirmationCreatesNothing(t *testing.T) {
	api, store, caller, _, sub, _ := personalOrderFixture(t)
	provider := newPersonalProviderEmulator(t, "", nil)
	api.Settings.Payments = provider.provider()
	for _, fixture := range []struct {
		request map[string]any
		status  int
		code    string
	}{
		{map[string]any{"months": 1, "expected_amount_kopecks": 39900}, 400, "PAYMENT_IDEMPOTENCY_REQUIRED"},
		{map[string]any{"months": 1, "expected_amount_kopecks": 39900, "idempotency_key": "short"}, 400, "PAYMENT_IDEMPOTENCY_REQUIRED"},
		{map[string]any{"months": 1, "idempotency_key": "personal-no-confirmation-0001"}, 409, "PAYMENT_CONFIRMATION_REQUIRED"},
		{personalPayFixture("personal-stale-price-0001", 1, 1), 409, "PAYMENT_PRICE_CHANGED"},
	} {
		if status, result := caller.do(t, "POST", "/api/v1/account/subscriptions/"+sub+"/pay", fixture.request); status != fixture.status || result["error"] != fixture.code {
			t.Fatal("unconfirmed old/stale checkout was accepted", status, result)
		}
	}
	var count int
	if err := store.DB.QueryRow(context.Background(), "SELECT count(*) FROM payments").Scan(&count); err != nil || count != 0 || provider.creates.Load() != 0 {
		t.Fatal("invalid confirmation left financial records or called provider", count, err)
	}
}
