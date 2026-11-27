package controlplane

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/buzzmean/veliq/core/security"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestClubReferralMigration015PreservesSchema13(t *testing.T) {
	base := codeStore(t)
	ctx := context.Background()
	id, err := security.NewID()
	if err != nil {
		t.Fatal(err)
	}
	schema := "referral_schema13_" + id
	if _, err = base.DB.Exec(ctx, "CREATE SCHEMA "+schema); err != nil {
		t.Fatal(err)
	}
	cfg := base.DB.Config()
	cfg.ConnConfig.RuntimeParams["search_path"] = schema
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pool.Close(); base.DB.Exec(context.Background(), "DROP SCHEMA "+schema+" CASCADE") })
	entries, err := migrations.ReadDir("migrations")
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if entry.Name() > "013_persistent_club_health.sql" {
			continue
		}
		raw, err := migrations.ReadFile("migrations/" + entry.Name())
		if err != nil {
			t.Fatal(err)
		}
		if _, err = pool.Exec(ctx, string(raw)); err != nil {
			t.Fatal(entry.Name(), err)
		}
	}
	// Seed the exact historical schema13 shape, independent of current runtime
	// subscription creation (which legitimately expects the latest migration).
	owner, device, sub, code := strings.Repeat("a", 32), strings.Repeat("d", 32), strings.Repeat("b", 32), strings.Repeat("c", 32)
	public, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for _, seed := range []struct {
		sql  string
		args []any
	}{
		{"INSERT INTO accounts(id,email) VALUES($1,'schema13-owner@example.test')", []any{owner}},
		{"INSERT INTO subscriptions(id,account_id,plan_id,kind,seats) VALUES($1,$2,'player','player',1)", []any{sub, owner}},
		{"INSERT INTO activation_codes(id,code_hash,kind,seat_limit,name,expires_at,subscription_id) VALUES($1,decode(repeat('11',32),'hex'),'personal',1,'Schema13 fixture',now()+interval '20 years',$2)", []any{code, sub}},
		{"INSERT INTO devices(id,user_id,name,public_key) VALUES($1,'owner','PC13',$2)", []any{device, base64.RawURLEncoding.EncodeToString(public)}},
		{"INSERT INTO account_device_bindings(device_id,subscription_id) VALUES($1,$2)", []any{device, sub}},
		{"INSERT INTO activation_slots(code_id,machine_hash,device_id) VALUES($1,repeat('a',64),$2)", []any{code, device}},
	} {
		if _, err = pool.Exec(ctx, seed.sql, seed.args...); err != nil {
			t.Fatal("historical schema13 seed", err)
		}
	}
	for _, statement := range []struct {
		sql  string
		args []any
	}{
		{`INSERT INTO device_details(device_id,computer_name,software_version) VALUES($1,'PC13','0.3.792')`, []any{device}},
		{`INSERT INTO account_device_labels(account_id,machine_hash,label) VALUES($1,repeat('a',64),'Fixture PC')`, []any{owner}},
		{`INSERT INTO club_health_persistent_devices(device_id,account_id,pc,software_version) VALUES($1,$2,'PC13','0.3.792')`, []any{device, owner}},
		{`INSERT INTO club_health_persistent_events(device_id,event_id,account_id,observed_at,summary)
		VALUES($1,repeat('f',32),$2,now(),'{"component":"LANGAME","code":"SCM_NOT_RUNNING"}')`, []any{device, owner}},
	} {
		if _, err = pool.Exec(ctx, statement.sql, statement.args...); err != nil {
			t.Fatal(err)
		}
	}
	for i, status := range []string{"succeeded", "pending"} {
		if _, err = pool.Exec(ctx, `INSERT INTO payments(id,subscription_id,provider,provider_payment_id,amount_kopecks,period_days,status)
			SELECT $1,subscription_id,'fixture',$1,39900,30,$2 FROM account_device_bindings WHERE device_id=$3`,
			fmt.Sprintf("fixture-payment-%d", i), status, device); err != nil {
			t.Fatal(err)
		}
	}
	if _, err = pool.Exec(ctx, `UPDATE subscriptions SET paid_until=now()+interval '30 days',lifetime=true WHERE account_id=$1`, owner); err != nil {
		t.Fatal(err)
	}
	snapshot := func() string {
		t.Helper()
		var result string
		if err := pool.QueryRow(ctx, `SELECT jsonb_build_object(
			'accounts',(SELECT jsonb_agg(to_jsonb(a) ORDER BY id) FROM accounts a),
			'subscriptions',(SELECT jsonb_agg(to_jsonb(s) ORDER BY id) FROM subscriptions s),
			'payments',(SELECT jsonb_agg(to_jsonb(p) ORDER BY id) FROM payments p),
			'devices',(SELECT jsonb_agg(to_jsonb(d) ORDER BY id) FROM devices d),
			'activation_codes',(SELECT jsonb_agg(to_jsonb(c) ORDER BY id) FROM activation_codes c),
			'activation_slots',(SELECT jsonb_agg(to_jsonb(s) ORDER BY code_id,machine_hash) FROM activation_slots s),
			'bindings',(SELECT jsonb_agg(to_jsonb(b) ORDER BY device_id) FROM account_device_bindings b),
			'details',(SELECT jsonb_agg(to_jsonb(d) ORDER BY device_id) FROM device_details d),
			'labels',(SELECT jsonb_agg(to_jsonb(l) ORDER BY account_id,machine_hash) FROM account_device_labels l),
			'health',(SELECT jsonb_agg(to_jsonb(d) ORDER BY device_id) FROM club_health_persistent_devices d),
			'events',(SELECT jsonb_agg(to_jsonb(e) ORDER BY device_id,event_id) FROM club_health_persistent_events e),
			'prior_migrations',(SELECT jsonb_agg(to_jsonb(m) ORDER BY version) FROM schema_migrations m WHERE version<15)
		)::text`).Scan(&result); err != nil {
			t.Fatal(err)
		}
		return result
	}
	before := snapshot()
	raw, err := migrations.ReadFile("migrations/015_club_referrals.sql")
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if _, err = pool.Exec(ctx, string(raw)); err != nil {
			t.Fatal("015 / повторная миграция", err)
		}
		if snapshot() != before {
			t.Fatal("Миграция изменила существующие права, платежи, устройства или диагностику")
		}
	}
	var version, rows int
	if err = pool.QueryRow(ctx, "SELECT max(version) FROM schema_migrations").Scan(&version); err != nil || version != 15 {
		t.Fatal("Миграция015 не применена", version, err)
	}
	if err = pool.QueryRow(ctx, `SELECT (SELECT count(*) FROM club_referral_links)+(SELECT count(*) FROM club_referral_claims)+(SELECT count(*) FROM club_referral_credits)`).Scan(&rows); err != nil || rows != 0 {
		t.Fatal("Миграция создала исторические приглашения или награды", rows, err)
	}
}

func TestClubReferralCreditConcurrentReservation(t *testing.T) {
	store := codeStore(t)
	ctx := context.Background()
	owner, ownerSub, plan := promoAccount(t, store, "club", 1)
	confirmFixture(t, store, reserveFixture(t, store, owner, ownerSub, plan, 1, "", time.Now()), time.Now())
	approve(t, store, owner)
	link, err := store.createClubInvitation(ctx, owner.ID)
	if err != nil {
		t.Fatal(err)
	}
	invitee, inviteeSub, _ := promoAccount(t, store, "club", 2)
	if err = store.claimClubInvitation(ctx, invitee.ID, link); err != nil {
		t.Fatal(err)
	}
	confirmFixture(t, store, reserveFixture(t, store, invitee, inviteeSub, plan, 1, "", time.Now()), time.Now())
	tx, err := store.DB.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	if err = lockClubAccount(ctx, tx, invitee.ID); err != nil {
		t.Fatal(err)
	}
	if err = awardClubReferral(ctx, tx, invitee.ID, inviteeSub.ID); err != nil {
		t.Fatal(err)
	}
	if err = tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	view, err := store.clubReferrals(ctx, owner.ID)
	if err != nil || len(view.Credits) != 1 {
		t.Fatal("Награда пригласившему не начислена", err)
	}
	credit := view.Credits[0].Code
	now := time.Now()
	quote, err := store.QuoteClubOrder(ctx, owner, ownerSub, plan, 1, credit, now)
	if err != nil {
		t.Fatal(err)
	}
	var before int
	if err = store.DB.QueryRow(ctx, "SELECT count(*) FROM payments").Scan(&before); err != nil {
		t.Fatal(err)
	}
	start := make(chan struct{})
	var wg sync.WaitGroup
	orders := make([]ClubOrder, 2)
	errors := make([]error, 2)
	for i := range orders {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			orders[i], errors[i] = store.ReserveClubOrder(ctx, owner, ownerSub, plan, 1, credit, &quote.Amount, quote.Version,
				fmt.Sprintf("concurrent-referral-%016d", i), "fixture", now)
		}(i)
	}
	close(start)
	wg.Wait()
	succeeded := 0
	for _, err := range errors {
		if err == nil {
			succeeded++
		} else if err.Error() != "PROMO_RECONCILIATION_REQUIRED" {
			t.Fatal("Непредвиденный отказ второго заказа", err)
		}
	}
	var after, reserved int
	if err = store.DB.QueryRow(ctx, "SELECT count(*) FROM payments").Scan(&after); err != nil {
		t.Fatal(err)
	}
	if err = store.DB.QueryRow(ctx, "SELECT count(*) FROM club_referral_credits WHERE code=$1 AND reserved_payment_id IS NOT NULL", credit).Scan(&reserved); err != nil {
		t.Fatal(err)
	}
	if succeeded != 1 || after != before+1 || reserved != 1 {
		t.Fatal("Один кредит зарезервирован более чем одним заказом", succeeded, after-before, reserved)
	}
}

func TestClubReferralCheckoutAndReview(t *testing.T) {
	api, store, mailer := accountAPI(t, false)
	api.Settings.ClubVerificationToken = strings.Repeat("v", 32)
	api.Settings.Plans[1].PricePerSeatRub = 299
	mock := newMockPlatega(t)
	api.Settings.Payments = mock.provider()
	const invitations = "/api/v1/account/club-invitations/"
	const subscriptions = "/api/v1/account/subscriptions/"
	ctx := context.Background()

	request := func(c *call, method, path string, payload any, want int, headers ...func(*http.Request)) map[string]any {
		t.Helper()
		status, out := c.do(t, method, path, payload, headers...)
		if status != want {
			t.Fatalf("%s %s: got %d, want %d (%v)", method, path, status, want, out["error"])
		}
		return out
	}
	newClub := func(n int) (*call, string) {
		t.Helper()
		c := &call{api: api, ip: fmt.Sprintf("198.51.100.%d", n)}
		login(t, c, mailer, fmt.Sprintf("referral-%d@example.test", n))
		request(c, "POST", "/api/v1/account/profile", map[string]string{"kind": "club", "name": "Referral fixture"}, 200)
		out := request(c, "POST", strings.TrimSuffix(subscriptions, "/"), map[string]any{"plan_id": "club-month", "seats": 2}, 201)
		return c, out["id"].(string)
	}
	view := func(c *call) map[string]any {
		t.Helper()
		return request(c, "GET", "/api/v1/account", nil, 200)["club_referrals"].(map[string]any)
	}
	credits := func(c *call, want int) map[string]string {
		t.Helper()
		rows := view(c)["credits"].([]any)
		if len(rows) != want {
			t.Fatalf("got %d credits, want %d", len(rows), want)
		}
		byCode := make(map[string]string, want)
		for _, row := range rows {
			credit := row.(map[string]any)
			byCode[credit["code"].(string)] = credit["state"].(string)
		}
		return byCode
	}
	start := func(c *call, sub string, params map[string]any) (map[string]any, string, map[string]any) {
		t.Helper()
		payment := confirmedPayRequest(t, c, sub, params)
		txID := fmt.Sprintf("11111111-1111-4111-8111-%012d", mock.requests.Load()+1)
		mock.nextTx.Store(txID)
		out := request(c, "POST", subscriptions+sub+"/pay", payment, 200)
		return payment, txID, out
	}
	confirm := func(c *call, sub, txID string, amount int64) {
		t.Helper()
		request(c, "POST", "/api/v1/payments/webhook", map[string]any{"id": txID, "amount": float64(amount) / 100,
			"currency": "RUB", "status": "CONFIRMED", "paymentMethod": 2, "payload": "veliq:sub:" + sub}, 200,
			func(r *http.Request) {
				r.Header.Set("X-MerchantId", "merchant-1")
				r.Header.Set("X-Secret", "test-secret")
			})
	}
	verify := func(c *call, sub string) {
		t.Helper()
		request(c, "POST", "/api/v1/club-verifications/"+sub+"/approve", map[string]int{"operator_id": 42}, 200,
			func(r *http.Request) { r.Header.Set("Authorization", "Bearer "+api.Settings.ClubVerificationToken) })
	}

	owner, ownerSub := newClub(11)
	first, firstSub := newClub(12)
	second, secondSub := newClub(13)
	late, lateSub := newClub(14)
	request(&call{api: api}, "POST", invitations+"link", nil, 401)
	request(owner, "POST", invitations+"link", nil, 409)
	_, ownerPayment, _ := start(owner, ownerSub, map[string]any{})
	confirm(owner, ownerSub, ownerPayment, 59800)
	request(owner, "POST", invitations+"link", nil, 409)
	verify(owner, ownerSub)
	link := request(owner, "POST", invitations+"link", nil, 200)["invitation_code"].(string)
	if request(owner, "POST", invitations+"link", nil, 200)["invitation_code"] != link {
		t.Fatal("invitation link changed on retry")
	}
	invite := map[string]string{"code": link}
	if request(owner, "POST", invitations+"claim", invite, 409)["error"] != "CLUB_INVITE_INVALID" {
		t.Fatal("self invitation accepted")
	}
	start(late, lateSub, map[string]any{})
	if request(late, "POST", invitations+"claim", invite, 409)["error"] != "CLUB_INVITE_TOO_LATE" {
		t.Fatal("invitation accepted after checkout started")
	}
	request(first, "POST", invitations+"claim", invite, 200)
	request(first, "POST", invitations+"claim", invite, 200)
	_, firstPayment, _ := start(first, firstSub, map[string]any{})
	confirm(first, firstSub, firstPayment, 59800)
	credits(owner, 0)
	credits(first, 0)
	verify(first, firstSub)
	verify(first, firstSub)
	var earned string
	for code, state := range credits(owner, 1) {
		if state != "available" {
			t.Fatal("credit not available after verification")
		}
		earned = code
	}
	credits(first, 1)
	if request(first, "POST", subscriptions+firstSub+"/quote", map[string]any{"promo_code": earned}, 409)["error"] != "PROMO_INVALID" {
		t.Fatal("another club's credit accepted")
	}
	if request(owner, "POST", subscriptions+ownerSub+"/quote", map[string]any{"promo_code": earned, "months": 3}, 409)["error"] != "CLUB_REFERRAL_MONTH_ONLY" {
		t.Fatal("referral accepted for multiple months")
	}
	request(second, "POST", invitations+"claim", invite, 200)
	var secondAccount string
	if err := store.DB.QueryRow(ctx, "SELECT account_id FROM subscriptions WHERE id=$1", secondSub).Scan(&secondAccount); err != nil {
		t.Fatal(err)
	}
	approve(t, store, Account{ID: secondAccount})
	_, launch := campaign(t, store, "club-launch")
	_, secondPayment, _ := start(second, secondSub, map[string]any{"promo_code": launch})
	confirm(second, secondSub, secondPayment, 41860)
	verify(second, secondSub)
	for code := range credits(second, 1) {
		if request(second, "POST", subscriptions+secondSub+"/quote", map[string]any{"promo_code": code}, 409)["error"] != "CLUB_REFERRAL_PROMO_CONFLICT" {
			t.Fatal("two discounts combined on one bill")
		}
	}
	ownerCredits := credits(owner, 2)
	if ownerCredits[earned] != "available" {
		t.Fatal("second referral overwrote first credit")
	}

	pay, renewal, order := start(owner, ownerSub, map[string]any{"promo_code": earned})
	q := order["quote"].(map[string]any)
	if q["amount_kopecks"] != float64(41860) || q["days"] != float64(30) || q["referral_discount"] != true {
		t.Fatal("wrong one-month quote")
	}
	if replay := request(owner, "POST", subscriptions+ownerSub+"/pay", pay, 200); replay["id"] != order["id"] {
		t.Fatal("replayed request created a second order")
	}
	fullPrice := confirmedPayRequest(t, owner, ownerSub, map[string]any{})
	request(owner, "POST", subscriptions+ownerSub+"/pay", fullPrice, 409)
	if credits(owner, 2)[earned] != "reserved" {
		t.Fatal("credit not reserved")
	}
	if _, _, err := store.RecordProviderPayment(ctx, "platega", renewal, ownerSub, 41860, "canceled", "fixture", time.Now()); err != nil {
		t.Fatal(err)
	}
	confirm(owner, ownerSub, renewal, 41860)
	confirm(owner, ownerSub, renewal, 41860)
	if credits(owner, 2)[earned] != "redeemed" {
		t.Fatal("credit not redeemed after late confirmation")
	}
	if request(owner, "POST", subscriptions+ownerSub+"/quote", map[string]any{"promo_code": earned}, 409)["error"] != "PROMO_USED" {
		t.Fatal("redeemed credit accepted twice")
	}
	if _, _, err := store.RecordProviderPayment(ctx, "platega", secondPayment, secondSub, 41860, "review", "fixture", time.Now(), PaymentEvent{ProviderStatus: "CHARGEBACKED"}); err != nil {
		t.Fatal(err)
	}
	for code, state := range credits(owner, 2) {
		if code != earned && (state != "held" || request(owner, "POST", subscriptions+ownerSub+"/quote", map[string]any{"promo_code": code}, 409)["error"] != "PROMO_INVALID") {
			t.Fatal("disputed source payment still qualifies for a discount")
		}
	}
	var fullAmount, reducedAmount int64
	err := store.DB.QueryRow(ctx, `SELECT
 (SELECT amount_kopecks FROM payments WHERE provider_payment_id=$1),
 (SELECT amount_kopecks FROM payments WHERE provider_payment_id=$2)`, ownerPayment, renewal).Scan(&fullAmount, &reducedAmount)
	if err != nil || fullAmount != 59800 || reducedAmount != 41860 || mock.requests.Load() != 5 {
		t.Fatal("original billing terms or external request count changed", err, mock.requests.Load())
	}
}
