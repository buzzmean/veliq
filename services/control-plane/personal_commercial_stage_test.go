package controlplane

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"github.com/buzzmean/veliq/core/controlclient"
	"github.com/buzzmean/veliq/core/enrollment"
	"github.com/buzzmean/veliq/core/security"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

func stagePersonal(t *testing.T) (*API, *Store, *call, Account, string, Plan) {
	t.Helper()
	a, s, c, acc, sub, p := personalOrderFixture(t)
	if status, out := c.do(t, "POST", "/api/v1/account/profile", map[string]string{"kind": "player", "name": "Stage fixture"}); status != 200 {
		t.Fatal(status, out)
	}
	a.Settings.PersonalFirstPurchase = true
	a.Settings.Payments = newPersonalProviderEmulator(t, "", nil).provider()
	return a, s, c, acc, sub, p
}
func stageQuote(t *testing.T, c *call, sub string, months int) map[string]any {
	t.Helper()
	st, out := c.do(t, "POST", "/api/v1/account/subscriptions/"+sub+"/quote", map[string]any{"months": months})
	if st != 200 {
		t.Fatal(st, out)
	}
	return out
}
func TestPersonalStageFirstConfirmedPurchasePricesAndEligibility(t *testing.T) {
	a, s, c, acc, sub, _ := stagePersonal(t)
	ctx := context.Background()
	for _, tc := range []struct {
		m      int
		amount int64
	}{{1, 39900}, {3, 83790}, {6, 167580}, {12, 335160}} {
		for range 2 {
			q := stageQuote(t, c, sub, tc.m)
			if q["amount_kopecks"] != float64(tc.amount) || q["first_purchase_eligible"] != true || q["first_month_consumes_offer"] != (tc.m == 1) {
				t.Fatal(tc, q)
			}
			if tc.m != 1 && q["discount"] != float64(30) {
				t.Fatal("stacked discount", q)
			}
		}
	}
	if _, _, e := s.RecordPayment(ctx, sub, "fixture", "first-confirmed-month", 39900, 30, "succeeded", "stage", "fixture", time.Now()); e != nil {
		t.Fatal(e)
	}
	for _, tc := range []struct {
		m      int
		amount int64
	}{{3, 113715}, {6, 215460}, {12, 383040}} {
		q := stageQuote(t, c, sub, tc.m)
		if q["amount_kopecks"] != float64(tc.amount) || q["first_purchase_eligible"] != false || q["promotion"] != nil {
			t.Fatal("confirmed month did not consume once", q)
		}
	}
	if eligible, e := firstPurchaseEligible(ctx, s.DB, acc.ID); e != nil || eligible {
		t.Fatal(eligible, e)
	}
	a.Settings.PersonalFirstPurchase = false
	if st, out := c.do(t, "GET", "/api/v1/offers", nil); st != 200 || out["personal_first_purchase"].(map[string]any)["enabled"] != false {
		t.Fatal(st, out)
	}
}
func TestPersonalStagePendingDifferentTermsAndLateCallbackSerialize(t *testing.T) {
	_, s, c, acc, sub, p := stagePersonal(t)
	ctx := context.Background()
	start := time.Now().UTC().Truncate(time.Microsecond)
	if _, e := s.DB.Exec(ctx, "UPDATE subscriptions SET trial_until=$2 WHERE id=$1", sub, start.Add(time.Hour)); e != nil {
		t.Fatal(e)
	}
	type result struct {
		o PersonalOrder
		e error
		m int
	}
	ch := make(chan result, 2)
	var wg sync.WaitGroup
	for _, m := range []int{1, 3} {
		wg.Add(1)
		go func(m int) {
			defer wg.Done()
			v := int64(39900)
			if m == 3 {
				v = 83790
			}
			o, e := s.ReservePersonalOrder(ctx, acc, sub, p, m, &v, fmt.Sprintf("stage-competing-term-%04d", m), "platega", true)
			ch <- result{o, e, m}
		}(m)
	}
	wg.Wait()
	close(ch)
	var winner result
	wins := 0
	for r := range ch {
		if r.e == nil {
			winner = r
			wins++
		} else if r.e.Error() != "PAYMENT_IN_PROGRESS" {
			t.Fatal(r.e)
		}
	}
	if wins != 1 {
		t.Fatal("more than one first purchase reserved", wins)
	}
	if eligible, e := firstPurchaseEligible(ctx, s.DB, acc.ID); e != nil || !eligible {
		t.Fatal("pending/trial consumed eligibility", eligible, e)
	}
	if _, _, e := s.RecordPayment(ctx, sub, "manual", "competing-untracked-month", 39900, 30, "succeeded", "stage", "fixture", time.Now()); e == nil || e.Error() != "PROMO_RECONCILIATION_REQUIRED" {
		t.Fatal("manual payment raced reservation", e)
	}
	// Attach the durable frozen order to a synthetic provider transaction.
	if e := s.AttachPersonalPayment(ctx, winner.o.ID, "platega", "late-stage-provider", "https://pay.example.test/stage"); e != nil {
		t.Fatal(e)
	}
	amount := int64(39900)
	if winner.m == 3 {
		amount = 83790
	}
	if _, extended, e := s.RecordProviderPayment(ctx, "platega", "late-stage-provider", sub, amount, "canceled", "fixture", start); e != nil || extended {
		t.Fatal(e, extended)
	}
	expected := int64(83790)
	if _, e := s.ReservePersonalOrder(ctx, acc, sub, p, 3, &expected, "stage-after-cancel-blocked", "platega", true); e == nil || e.Error() != "PAYMENT_IN_PROGRESS" {
		t.Fatal("canceled pending claim released", e)
	}
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, _, e := s.RecordProviderPayment(ctx, "platega", "late-stage-provider", sub, amount, "succeeded", "fixture", start); e != nil {
				t.Error(e)
			}
		}()
	}
	wg.Wait()
	var paid time.Time
	var credits int
	if e := s.DB.QueryRow(ctx, "SELECT paid_until,(SELECT count(*) FROM audit_log WHERE action='payment.succeeded') FROM subscriptions WHERE id=$1", sub).Scan(&paid, &credits); e != nil || credits != 1 || !paid.Equal(start.Add(time.Duration(30*winner.m)*24*time.Hour)) {
		t.Fatal("late callback double credit", paid, credits, e)
	}
	if q := stageQuote(t, c, sub, 3); q["amount_kopecks"] != float64(113715) || q["first_purchase_eligible"] != false {
		t.Fatal(q)
	}
}
func TestPersonalStageManualTrialAndServerOffers(t *testing.T) {
	a, s, mail := accountAPI(t, false)
	a.Settings.Plans[0].PricePerSeatRub = 399
	a.Settings.PersonalTrials = true
	a.Settings.PersonalFirstPurchase = true
	a.Settings.Payments = newPersonalProviderEmulator(t, "", nil).provider()
	c := trialProfile(t, a, mail, "manual-offer@example.test", "player")
	ctx := context.Background()
	for range 3 {
		st, o := c.do(t, "GET", "/api/v1/account/offers", nil)
		if st != 200 {
			t.Fatal(st, o)
		}
		tr := o["trial"].(map[string]any)
		if tr["active"] != false || tr["eligible"] != true {
			t.Fatal("view started trial", tr)
		}
	}
	var active int
	if e := s.DB.QueryRow(ctx, "SELECT count(*) FROM subscriptions WHERE trial_until IS NOT NULL").Scan(&active); e != nil || active != 0 {
		t.Fatal(active, e)
	}
	_, o := c.do(t, "GET", "/api/v1/account/offers", nil)
	code := o["trial"].(map[string]any)["code"].(string)
	st, activated := c.do(t, "POST", trialActivationPath, map[string]string{"code": code})
	if st != 200 {
		t.Fatal(st, activated)
	}
	_, o = c.do(t, "GET", "/api/v1/account/offers", nil)
	if o["trial"].(map[string]any)["active"] != true || o["personal_first_purchase"].(map[string]any)["eligible"] != true {
		t.Fatal("trial consumed purchase or inactive", o)
	}
	a.Settings.PersonalTrials = false
	if st, o = c.do(t, "GET", "/api/v1/offers", nil); st != 200 || o["trial"].(map[string]any)["enabled"] != false {
		t.Fatal(st, o)
	}
	_, campaignCode := campaign(t, s, "club-launch")
	_, o = c.do(t, "GET", "/api/v1/offers", nil)
	if o["club_first20"].(map[string]any)["enabled"] != false {
		t.Fatal("unverified operator advertised", o)
	}
	a.Settings.ClubVerificationToken = strings.Repeat("t", 32)
	_, o = c.do(t, "GET", "/api/v1/offers", nil)
	if o["club_first20"].(map[string]any)["enabled"] != true {
		t.Fatal(o)
	}
	savedOrigin, savedMailer := a.Settings.AccountOrigin, a.Settings.Mailer
	for _, missing := range []string{"origin", "mailer"} {
		if missing == "origin" {
			a.Settings.AccountOrigin = ""
		} else {
			a.Settings.Mailer = nil
		}
		st, o := c.do(t, "GET", "/api/v1/offers", nil)
		if st != 200 || o["personal_first_purchase"].(map[string]any)["enabled"] != false || o["club_first20"].(map[string]any)["enabled"] != false {
			t.Fatal("unavailable account advertised", st, o)
		}
		a.Settings.AccountOrigin, a.Settings.Mailer = savedOrigin, savedMailer
	}
	// Capacity query includes reserved and redeemed, rather than presenting full offers.
	for i := 0; i < 20; i++ {
		account, sub, plan := promoAccount(t, s, "club", 200+i)
		approve(t, s, account)
		if _, _, e := s.ReservePromotion(ctx, account, sub, plan, 1, campaignCode, nil, "platega"); e != nil {
			t.Fatal(e)
		}
	}
	_, o = c.do(t, "GET", "/api/v1/offers", nil)
	if o["club_first20"].(map[string]any)["enabled"] != false {
		t.Fatal("full campaign advertised", o)
	}
}

func stageDevice(t *testing.T, a *API, c *call, sub string, n int) (string, ed25519.PrivateKey) {
	t.Helper()
	l, q, key := newLinkRequest(t, "device", fmt.Sprintf("%064x", n))
	l.PersonalOptimizationLeaseV1 = true
	q, e := l.Request("Stage PC", q.Device, key, time.Now())
	if e != nil {
		t.Fatal(e)
	}
	if st, o := c.do(t, "POST", "/api/v1/enroll/device/start", q); st != 201 {
		t.Fatal("start", st, o)
	}
	if st, o := c.do(t, "POST", "/api/v1/account/device-links/"+l.ID+"/approve", map[string]string{"subscription_id": sub}); st != 200 {
		t.Fatal("approve", st, o)
	}
	if st, o := c.do(t, "POST", "/api/v1/enroll/device/poll", enrollment.DeviceLinkPoll{ID: l.ID, Secret: l.Secret, PersonalOptimizationLeaseV1: true}); st != 200 {
		t.Fatal("poll", st, o)
	}
	return q.Device.DeviceID, key
}
func stageLease(t *testing.T, c *call, device string, key ed25519.PrivateKey, action, id string) (int, map[string]any) {
	t.Helper()
	aud, e := security.PersonalOptimizationLeaseProofAudience(action, id)
	if e != nil {
		t.Fatal(e)
	}
	proof, e := security.NewProof(device, aud, key, time.Now())
	if e != nil {
		t.Fatal(e)
	}
	return c.do(t, "POST", "/api/v1/subscription/optimization-lease", map[string]any{"proof": proof, "action": action, "lease_id": id})
}
func TestPersonalStageUnlimitedSequentialEnrollmentOneOptimizationLease(t *testing.T) {
	a, s, c, _, sub, _ := stagePersonal(t)
	a.Settings.PersonalOptimizationLeases = true
	if _, e := s.DB.Exec(context.Background(), "UPDATE subscriptions SET personal_optimization_lease_stage=true WHERE id=$1", sub); e != nil {
		t.Fatal(e)
	}
	if _, e := s.DB.Exec(context.Background(), "UPDATE subscriptions SET paid_until=now()+interval '30 days' WHERE id=$1", sub); e != nil {
		t.Fatal(e)
	}
	devices := []string{}
	keys := []ed25519.PrivateKey{}
	for i := 1; i <= 3; i++ {
		d, k := stageDevice(t, a, c, sub, i)
		devices = append(devices, d)
		keys = append(keys, k)
	}
	accountStatus, accountView := c.do(t, "GET", "/api/v1/account", nil)
	if accountStatus != 200 {
		t.Fatal(accountStatus, accountView)
	}
	subscriptions := accountView["subscriptions"].([]any)
	if len(subscriptions) != 1 {
		t.Fatal("stage duplicated subscription")
	}
	shown := subscriptions[0].(map[string]any)
	if shown["personal_optimization_lease_stage"] != true || shown["used_seats"] != float64(3) || shown["seats"] != float64(1) || len(shown["devices"].([]any)) != 3 {
		t.Fatal("stage account presentation missing marker", shown)
	}
	st, o := stageLease(t, c, devices[0], keys[0], "acquire", "")
	if st != 200 || o["granted"] != true {
		t.Fatal(st, o)
	}
	id := o["lease_id"].(string)
	expires, _ := time.Parse(time.RFC3339Nano, o["expires_at"].(string))
	now, _ := time.Parse(time.RFC3339Nano, o["server_time"].(string))
	if expires.Sub(now) > 60*time.Second {
		t.Fatal("unbounded lease")
	}
	if st, o := stageLease(t, c, devices[1], keys[1], "acquire", ""); st != 409 || o["reason"] != "ACTIVE_ON_OTHER_DEVICE" {
		t.Fatal(st, o)
	}
	if st, o := stageLease(t, c, devices[0], keys[0], "acquire", ""); st != 200 || o["lease_id"] != id {
		t.Fatal("not idempotent", st, o)
	}
	if st, o := stageLease(t, c, devices[0], keys[0], "release", id); st != 200 {
		t.Fatal(st, o)
	}
	st, o = stageLease(t, c, devices[1], keys[1], "acquire", "")
	if st != 200 {
		t.Fatal(st, o)
	}
	next := o["lease_id"].(string)
	if st, o := stageLease(t, c, devices[0], keys[0], "release", id); st != 409 {
		t.Fatal("stale release took successor", st, o)
	}
	if st, o := stageLease(t, c, devices[1], keys[1], "renew", next); st != 200 {
		t.Fatal(st, o)
	}
	if _, e := s.DB.Exec(context.Background(), "UPDATE personal_optimization_leases SET expires_at=now()-interval '1 second'"); e != nil {
		t.Fatal(e)
	}
	if st, o := stageLease(t, c, devices[1], keys[1], "renew", next); st != 409 || o["reason"] != "LEASE_EXPIRED" {
		t.Fatal(st, o)
	}
	if st, o := stageLease(t, c, devices[2], keys[2], "acquire", ""); st != 200 || o["lease_id"] == next {
		t.Fatal(st, o)
	}
	// Signed acquire cannot be reinterpreted as release/renew, including valid IDs.
	aud, _ := security.PersonalOptimizationLeaseProofAudience("acquire", "")
	proof, _ := security.NewProof(devices[2], aud, keys[2], time.Now())
	for _, action := range []string{"release", "renew"} {
		if st, o := c.do(t, "POST", "/api/v1/subscription/optimization-lease", map[string]any{"proof": proof, "action": action, "lease_id": next}); st != 400 {
			t.Fatal("unsigned action mutation", st, o)
		}
	}
	if st, _ := c.do(t, "POST", "/api/v1/subscription/optimization-lease", map[string]any{"proof": proof, "action": "acquire"}); st != 200 {
		t.Fatal(st)
	}
	if st, _ := c.do(t, "POST", "/api/v1/subscription/optimization-lease", map[string]any{"proof": proof, "action": "acquire"}); st != 401 {
		t.Fatal("proof replay", st)
	}
}

func TestPersonalStageRealHTTPSClientLeaseWire(t *testing.T) {
	a, s, c, _, sub, _ := stagePersonal(t)
	a.Settings.PersonalOptimizationLeases = true
	if _, e := s.DB.Exec(context.Background(), "UPDATE subscriptions SET personal_optimization_lease_stage=true WHERE id=$1", sub); e != nil {
		t.Fatal(e)
	}
	if _, e := s.DB.Exec(context.Background(), "UPDATE subscriptions SET trial_until=now()+interval '12 seconds' WHERE id=$1", sub); e != nil {
		t.Fatal(e)
	}
	d1, k1 := stageDevice(t, a, c, sub, 101)
	d2, k2 := stageDevice(t, a, c, sub, 102)
	server := httptest.NewTLSServer(a.Handler())
	defer server.Close()
	client := func(d string, k ed25519.PrivateKey) *controlclient.Client {
		return &controlclient.Client{BaseURL: server.URL, HTTP: server.Client(), DeviceID: d, DeviceKey: k, PersonalOptimizationLeaseStage: true}
	}
	one, two := client(d1, k1), client(d2, k2)
	ctx := context.Background()
	status, e := one.SubscriptionStatus(ctx)
	if e != nil || !status.OptimizationLease.Supported || !status.OptimizationLease.Required {
		t.Fatal("subscription policy wire", status, e)
	}
	lease, e := one.OptimizationLease(ctx, "acquire", "")
	if e != nil || !lease.Granted || lease.TTLSeconds != 60 || lease.RenewAfterSeconds != 20 || lease.ExpiresAt == nil || lease.ExpiresAt.Sub(lease.ServerTime) > 12*time.Second {
		t.Fatal("grant/clamp wire", lease, e)
	}
	busy, e := two.OptimizationLease(ctx, "acquire", "")
	if e != nil || busy.Granted || busy.Reason != "ACTIVE_ON_OTHER_DEVICE" {
		t.Fatal("conflict wire", busy, e)
	}
	renewed, e := one.OptimizationLease(ctx, "renew", lease.LeaseID)
	if e != nil || !renewed.Granted || renewed.LeaseID != lease.LeaseID {
		t.Fatal(renewed, e)
	}
	released, e := one.OptimizationLease(ctx, "release", lease.LeaseID)
	if e != nil || !released.Granted {
		t.Fatal(released, e)
	}
	next, e := two.OptimizationLease(ctx, "acquire", "")
	if e != nil || !next.Granted || next.LeaseID == lease.LeaseID {
		t.Fatal("sequential wire", next, e)
	}
}

func TestPersonalStageNewEntitlementRejectsLegacyAndCannotDowngrade(t *testing.T) {
	a, s, mail := accountAPI(t, false)
	a.Settings.PersonalOptimizationLeases = true
	a.Settings.PersonalTrials = true
	c := trialProfile(t, a, mail, "stage-boundary@example.test", "player")
	_, o := c.do(t, "GET", "/api/v1/account/offers", nil)
	code := o["trial"].(map[string]any)["code"].(string)
	if st, o := c.do(t, "POST", trialActivationPath, map[string]string{"code": code}); st != 200 {
		t.Fatal(st, o)
	}
	_, view := c.do(t, "GET", "/api/v1/account", nil)
	sub := view["subscriptions"].([]any)[0].(map[string]any)["id"].(string)
	var staged bool
	if e := s.DB.QueryRow(context.Background(), "SELECT personal_optimization_lease_stage FROM subscriptions WHERE id=$1", sub).Scan(&staged); e != nil || !staged {
		t.Fatal("trial not stage bound", e)
	}
	legacy, q, _ := newLinkRequest(t, "device", strings.Repeat("e", 64))
	if st, o := c.do(t, "POST", "/api/v1/enroll/device/start", q); st != 201 {
		t.Fatal(st, o)
	}
	if st, o := c.do(t, "POST", "/api/v1/account/device-links/"+legacy.ID+"/approve", map[string]string{"subscription_id": sub}); st != 403 || o["error"] != "LEASE_UNSUPPORTED" {
		t.Fatal("legacy first bypass", st, o)
	}
	d, k := stageDevice(t, a, c, sub, 201)
	stageDevice(t, a, c, sub, 202)
	if _, e := s.IssueSubscriptionCode(context.Background(), Account{ID: func() string {
		var id string
		s.DB.QueryRow(context.Background(), "SELECT account_id FROM subscriptions WHERE id=$1", sub).Scan(&id)
		return id
	}()}, sub); e == nil {
		t.Fatal("stage raw code issued")
	}
	a.Settings.PersonalOptimizationLeases = false
	if st, o := deviceCall(t, a, "/api/v1/auth", d, "R1", k); st != 409 || o["error"] != "OPTIMIZATION_LEASE_REQUIRED" {
		t.Fatal("flagoff granted auth", st, o)
	}
	policy, e := a.optimizationLeasePolicy(context.Background(), d)
	if e != nil || policy.Supported || !policy.Required {
		t.Fatal("flagoff downgraded", policy, e)
	}
	if _, e := a.currentOptimizationLease(context.Background(), d); e == nil {
		t.Fatal("flagoff lease became optional")
	}
	if st, o := stageLease(t, c, d, k, "acquire", ""); st != 409 || o["reason"] != "LEASE_UNSUPPORTED" {
		t.Fatal(st, o)
	}
	if st, o := c.do(t, "POST", "/api/v1/account/device-links/"+legacy.ID+"/approve", map[string]string{"subscription_id": sub}); st != 403 {
		t.Fatal("legacy after modern bypass", st, o)
	}
}

func TestPersonalStageDiscountedProviderAmountAndSingleLateGrant(t *testing.T) {
	a, s, c, acc, sub, _ := stagePersonal(t)
	ctx := context.Background()
	provider := newPersonalProviderEmulator(t, "", nil)
	a.Settings.Payments = provider.provider()
	path := "/api/v1/account/subscriptions/" + sub + "/pay"
	st, out := c.do(t, "POST", path, personalPayFixture("first-three-month-provider", 3, 83790))
	if st != 200 {
		t.Fatal(st, out)
	}
	provider.mu.Lock()
	record := provider.records["personal-fixture-tx-1"]
	provider.mu.Unlock()
	if record.Amount.String() != "837.90" && record.Amount.String() != "837.9" {
		t.Fatal("provider did not receive frozen discount", record.Amount)
	}
	if eligible, e := firstPurchaseEligible(ctx, s.DB, acc.ID); e != nil || !eligible {
		t.Fatal("pending consumed", e)
	}
	if _, _, e := s.RecordProviderPayment(ctx, "platega", "personal-fixture-tx-1", sub, 83790, "canceled", "fixture", time.Now()); e != nil {
		t.Fatal(e)
	}
	if st, o := c.do(t, "POST", path, personalPayFixture("first-one-month-competing", 1, 39900)); st != 409 || o["error"] != "PAYMENT_IN_PROGRESS" {
		t.Fatal(st, o)
	}
	var wg sync.WaitGroup
	for range 6 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, _, e := s.RecordProviderPayment(ctx, "platega", "personal-fixture-tx-1", sub, 83790, "succeeded", "fixture", time.Now()); e != nil {
				t.Error(e)
			}
		}()
	}
	wg.Wait()
	var credits int
	if e := s.DB.QueryRow(ctx, "SELECT count(*) FROM audit_log WHERE action='payment.succeeded'").Scan(&credits); e != nil || credits != 1 {
		t.Fatal(credits, e)
	}
	q := stageQuote(t, c, sub, 3)
	if q["amount_kopecks"] != float64(113715) || q["first_purchase_eligible"] != false {
		t.Fatal(q)
	}
	if provider.creates.Load() != 1 {
		t.Fatal("duplicate checkout")
	}
}

func TestPersonalStageConcurrentLeaseAcquisitionHasSingleHolder(t *testing.T) {
	a, s, c, _, sub, _ := stagePersonal(t)
	a.Settings.PersonalOptimizationLeases = true
	if _, e := s.DB.Exec(context.Background(), "UPDATE subscriptions SET personal_optimization_lease_stage=true,paid_until=now()+interval '30 days' WHERE id=$1", sub); e != nil {
		t.Fatal(e)
	}
	ids := []string{}
	keys := []ed25519.PrivateKey{}
	for i := 301; i < 304; i++ {
		id, key := stageDevice(t, a, c, sub, i)
		ids = append(ids, id)
		keys = append(keys, key)
	}
	start := make(chan struct{})
	result := make(chan int, 3)
	var wg sync.WaitGroup
	for i := range ids {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			other := &call{api: a}
			st, o := stageLease(t, other, ids[i], keys[i], "acquire", "")
			if st != 200 && (st != 409 || o["reason"] != "ACTIVE_ON_OTHER_DEVICE") {
				t.Error(st, o)
			}
			result <- st
		}(i)
	}
	close(start)
	wg.Wait()
	close(result)
	granted := 0
	for st := range result {
		if st == 200 {
			granted++
		}
	}
	if granted != 1 {
		t.Fatal("concurrent holders", granted)
	}
	var count int
	if e := s.DB.QueryRow(context.Background(), "SELECT count(*) FROM personal_optimization_leases WHERE expires_at>clock_timestamp()").Scan(&count); e != nil || count != 1 {
		t.Fatal(count, e)
	}
}

func TestPersonalStageOldStrictSubscriptionStatusWireUnchanged(t *testing.T) {
	a, s, c, _, sub, _ := stagePersonal(t)
	a.Settings.PersonalOptimizationLeases = true
	if _, e := s.DB.Exec(context.Background(), "UPDATE subscriptions SET personal_optimization_lease_stage=true,paid_until=now()+interval '30 days' WHERE id=$1", sub); e != nil {
		t.Fatal(e)
	}
	d, k := stageDevice(t, a, c, sub, 401)
	for _, enabled := range []bool{false, true} {
		a.Settings.PersonalOptimizationLeases = enabled
		proof, e := security.NewProof(d, security.SubscriptionAudience, k, time.Now())
		if e != nil {
			t.Fatal(e)
		}
		st, o := c.do(t, "POST", "/api/v1/subscription/status", proof)
		if st != 200 {
			t.Fatal(st, o)
		}
		if _, extra := o["optimization_lease"]; extra {
			t.Fatal("newfield leaked to oldcodec", o)
		}
		// Exact812/813 fields and strict security.Parse behavior, rather than a tolerant map.
		var old struct {
			Managed    bool       `json:"managed"`
			Enforced   bool       `json:"enforced"`
			Active     bool       `json:"active"`
			PaidUntil  *time.Time `json:"paid_until,omitempty"`
			GraceUntil *time.Time `json:"grace_until,omitempty"`
		}
		raw, _ := json.Marshal(o)
		if e = security.Parse(raw, &old); e != nil || !old.Active {
			t.Fatal("old strictcodec failed", e)
		}
	}
}

func TestPersonalStageFirstPurchaseDoesNotDiscountOtherContracts(t *testing.T) {
	_, s, _, acc, id, p := stagePersonal(t)
	sub := Subscription{ID: id, PlanID: p.ID, Kind: "player", Seats: 1}
	for _, which := range []string{"custom-period", "other-price", "lifetime", "club", "multi-seat", "disabled-flag"} {
		plan, right := p, sub
		enabled := true
		switch which {
		case "custom-period":
			plan.PeriodDays = 60
		case "other-price":
			plan.PricePerSeatRub = 400
		case "lifetime":
			right.Lifetime = true
		case "club":
			right.Kind = "club"
			plan.Kind = "club"
		case "multi-seat":
			right.Seats = 2
			plan.MaxSeats = 2
		case "disabled-flag":
			enabled = false
		}
		q, e := s.QuotePersonal(context.Background(), acc, right, plan, 3, enabled)
		if e == nil && (q.Promotion != "" || q.Discount == 30 || q.FirstPurchaseEligible) {
			t.Fatal("discount escaped approved contract", which, q)
		}
	}
}

func TestPersonalStageNewMultiSeatRejectedExistingHistoricalPreserved(t *testing.T) {
	a, s, mail := accountAPI(t, false)
	a.Settings.Plans[0].MaxSeats = 3
	old := trialProfile(t, a, mail, "old-three-seat@example.test", "player")
	historical := linkedPlan(t, old, "player", 3)
	beforeStatus, beforeView := old.do(t, "GET", "/api/v1/account", nil)
	if beforeStatus != 200 {
		t.Fatal(beforeStatus, beforeView)
	}
	beforeRaw, _ := json.Marshal(beforeView["subscriptions"])
	a.Settings.PersonalOptimizationLeases = true
	for _, seats := range []int{2, 3} {
		fresh := trialProfile(t, a, mail, fmt.Sprintf("stage-new-seats%d@example.test", seats), "player")
		if st, o := fresh.do(t, "POST", "/api/v1/account/subscriptions", map[string]any{"plan_id": "player-month", "seats": seats}); st != 400 || o["error"] != "SUBSCRIPTION_INVALID" {
			t.Fatal("newstage multi-seat bypass", st, o)
		}
	}
	if st, o := old.do(t, "POST", "/api/v1/account/subscriptions", map[string]any{"plan_id": "player-month", "seats": 3}); st != 201 || o["id"] != historical {
		t.Fatal("oldright changed", st, o)
	}
	var stage bool
	var seats int
	if e := s.DB.QueryRow(context.Background(), "SELECT seats,personal_optimization_lease_stage FROM subscriptions WHERE id=$1", historical).Scan(&seats, &stage); e != nil || stage || seats != 3 {
		t.Fatal("oldright reclassified", stage, seats, e)
	}
	afterStatus, afterView := old.do(t, "GET", "/api/v1/account", nil)
	if afterStatus != 200 {
		t.Fatal(afterStatus, afterView)
	}
	afterRaw, _ := json.Marshal(afterView["subscriptions"])
	if string(beforeRaw) != string(afterRaw) {
		t.Fatal("historical account subscription JSON changed under stage flag")
	}
	shown := afterView["subscriptions"].([]any)[0].(map[string]any)
	if _, present := shown["personal_optimization_lease_stage"]; present {
		t.Fatal("oldfalse marker serialized")
	}
}

func TestPersonalStageFullManualTrialFirstPurchaseAndSequentialLeaseLifecycle(t *testing.T) {
	a, s, mail := accountAPI(t, false)
	a.Settings.Plans[0].PricePerSeatRub = 399
	a.Settings.PersonalTrials = true
	a.Settings.PersonalFirstPurchase = true
	a.Settings.PersonalOptimizationLeases = true
	provider := newPersonalProviderEmulator(t, "", nil)
	a.Settings.Payments = provider.provider()
	ctx := context.Background()
	c := trialProfile(t, a, mail, "full-stage-lifecycle@example.test", "player")
	for range 2 {
		if st, o := c.do(t, "GET", "/api/v1/account/offers", nil); st != 200 || o["trial"].(map[string]any)["active"] != false {
			t.Fatal(st, o)
		}
	}
	var trials int
	if e := s.DB.QueryRow(ctx, "SELECT count(*) FROM subscriptions WHERE trial_until IS NOT NULL").Scan(&trials); e != nil || trials != 0 {
		t.Fatal("view started trial", trials, e)
	}
	_, offers := c.do(t, "GET", "/api/v1/account/offers", nil)
	trialCode := offers["trial"].(map[string]any)["code"].(string)
	st, activation := c.do(t, "POST", trialActivationPath, map[string]string{"code": trialCode})
	if st != 200 {
		t.Fatal(st, activation)
	}
	trialDeadline := activation["trial_until"].(string)
	_, account := c.do(t, "GET", "/api/v1/account", nil)
	sub := account["subscriptions"].([]any)[0].(map[string]any)["id"].(string)
	if q := stageQuote(t, c, sub, 3); q["amount_kopecks"] != float64(83790) || q["discount"] != float64(30) {
		t.Fatal(q)
	}
	if st, o := c.do(t, "POST", "/api/v1/account/subscriptions/"+sub+"/pay", personalPayFixture("full-lifecycle-first-checkout", 3, 83790)); st != 200 {
		t.Fatal(st, o)
	}
	provider.mu.Lock()
	record := provider.records["personal-fixture-tx-1"]
	provider.mu.Unlock()
	raw, e := json.Marshal(map[string]any{"id": "personal-fixture-tx-1", "amount": record.Amount, "currency": "RUB", "status": "CONFIRMED", "payload": record.Payload})
	if e != nil {
		t.Fatal(e)
	}
	before := time.Now()
	for range 2 {
		w := httptest.NewRecorder()
		a.Handler().ServeHTTP(w, plategaWebhookRequest(provider.provider(), string(raw)))
		if w.Code != 200 {
			t.Fatal("actual signed webhook path", w.Code, w.Body.String())
		}
	}
	_, account = c.do(t, "GET", "/api/v1/account", nil)
	rights := account["subscriptions"].([]any)
	if len(rights) != 1 {
		t.Fatal("purchase duplicated trial right")
	}
	right := rights[0].(map[string]any)
	originalDeadline, parseOriginal := time.Parse(time.RFC3339Nano, trialDeadline)
	persistedDeadline, parsePersisted := time.Parse(time.RFC3339Nano, right["trial_until"].(string))
	if parseOriginal != nil || parsePersisted != nil || right["id"] != sub || !persistedDeadline.Equal(originalDeadline) || right["personal_optimization_lease_stage"] != true {
		t.Fatal("trial lineage lost", right)
	}
	paid, e := time.Parse(time.RFC3339Nano, right["paid_until"].(string))
	if e != nil || paid.Before(before.Add(90*24*time.Hour)) || paid.After(time.Now().Add(90*24*time.Hour)) {
		t.Fatal("paid duration", paid, e)
	}
	ids := []string{}
	keys := []ed25519.PrivateKey{}
	for i := 501; i < 504; i++ {
		id, key := stageDevice(t, a, c, sub, i)
		ids = append(ids, id)
		keys = append(keys, key)
	}
	_, account = c.do(t, "GET", "/api/v1/account", nil)
	right = account["subscriptions"].([]any)[0].(map[string]any)
	if right["personal_optimization_lease_stage"] != true || right["used_seats"] != float64(3) || right["seats"] != float64(1) {
		t.Fatal("missing account stage presentation", right)
	}
	st, lease := stageLease(t, c, ids[0], keys[0], "acquire", "")
	if st != 200 {
		t.Fatal(st, lease)
	}
	if st, o := stageLease(t, c, ids[1], keys[1], "acquire", ""); st != 409 || o["reason"] != "ACTIVE_ON_OTHER_DEVICE" {
		t.Fatal(st, o)
	}
	if st, o := stageLease(t, c, ids[0], keys[0], "release", lease["lease_id"].(string)); st != 200 {
		t.Fatal(st, o)
	}
	if st, o := stageLease(t, c, ids[2], keys[2], "acquire", ""); st != 200 {
		t.Fatal(st, o)
	}
	if st, o := c.do(t, "POST", "/api/v1/account/subscriptions/"+sub+"/code", nil); st != 404 {
		t.Fatal("raw code exposed", st, o)
	}
	legacy, q, _ := newLinkRequest(t, "device", strings.Repeat("9", 64))
	if st, o := c.do(t, "POST", "/api/v1/enroll/device/start", q); st != 201 {
		t.Fatal(st, o)
	}
	if st, o := c.do(t, "POST", "/api/v1/account/device-links/"+legacy.ID+"/approve", map[string]string{"subscription_id": sub}); st != 403 || o["error"] != "LEASE_UNSUPPORTED" {
		t.Fatal(st, o)
	}
	var credits int
	if e := s.DB.QueryRow(ctx, "SELECT count(*) FROM audit_log WHERE action='payment.succeeded'").Scan(&credits); e != nil || credits != 1 || provider.creates.Load() != 1 {
		t.Fatal("duplicate payment grant", credits, e)
	}
}
