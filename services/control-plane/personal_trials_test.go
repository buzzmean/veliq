package controlplane

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/buzzmean/veliq/core/enrollment"
	"github.com/buzzmean/veliq/core/optimizer"
	"github.com/buzzmean/veliq/core/security"
)

const trialActivationPath = "/api/v1/account/trial/activate"

func trialProfile(t *testing.T, api *API, m *fakeMailer, email, kind string) *call {
	t.Helper()
	c := &call{api: api}
	login(t, c, m, email)
	if status, _ := c.do(t, "POST", "/api/v1/account/profile", map[string]string{"kind": kind, "name": "Trial fixture"}); status != 200 {
		t.Fatal("profile", status)
	}
	return c
}

func TestPersonalTrialConcurrentActivationExpiryAndPurchase(t *testing.T) {
	api, store, mail := accountAPI(t, false)
	api.Settings.PersonalTrials = true
	ctx := context.Background()
	owner := trialProfile(t, api, mail, "trial-owner@example.test", "player")
	if status, out := owner.do(t, "GET", "/api/v1/account/trial", nil); status != 200 || out["available"] != true {
		t.Fatal("availability endpoint", status)
	}
	_, view := owner.do(t, "GET", "/api/v1/account", nil)
	voucher, ok := view["trial_code"].(string)
	if !ok || !enrollment.AccountLinkID(voucher) {
		t.Fatal("offer missing")
	}
	q := map[string]string{"code": voucher}
	stranger := trialProfile(t, api, mail, "trial-stranger@example.test", "player")
	club := trialProfile(t, api, mail, "trial-club@example.test", "club")
	for _, caller := range []*call{stranger, club, {api: api}} {
		if status, _ := caller.do(t, "POST", trialActivationPath, q); status != 409 && status != 401 {
			t.Fatal("foreign or anonymous activation succeeded", status)
		}
	}
	_, clubView := club.do(t, "GET", "/api/v1/account", nil)
	if clubView["trial_code"] != nil {
		t.Fatal("offered trial to club")
	}

	var before time.Time
	if err := store.DB.QueryRow(ctx, "SELECT clock_timestamp()").Scan(&before); err != nil {
		t.Fatal(err)
	}
	raw := make(chan string, 4)
	for i := range 4 {
		go func() {
			otherTab := &call{api: api, cookie: owner.cookie, ip: fmt.Sprintf("192.0.2.%d", i+1)}
			status, out := otherTab.do(t, "POST", trialActivationPath, q)
			s, _ := out["trial_until"].(string)
			if status != 200 {
				s = ""
			}
			raw <- s
		}()
	}
	var until time.Time
	for range 4 {
		deadline, err := time.Parse(time.RFC3339Nano, <-raw)
		if err != nil || (!until.IsZero() && !deadline.Equal(until)) {
			t.Fatal("concurrent activation failed or extended the trial")
		}
		until = deadline
	}
	var after time.Time
	if err := store.DB.QueryRow(ctx, "SELECT clock_timestamp()").Scan(&after); err != nil {
		t.Fatal(err)
	}
	activated := until.Add(-24 * time.Hour)
	if activated.Before(before) || activated.After(after) {
		t.Fatal("deadline is not 24 hours after activation")
	}
	_, view = owner.do(t, "GET", "/api/v1/account", nil)
	subs := view["subscriptions"].([]any)
	if view["trial_code"] != nil || len(subs) != 1 || len(view["payments"].([]any)) != 0 {
		t.Fatal("second subscription, stale promotion or payment created")
	}
	sub := subs[0].(map[string]any)
	id := sub["id"].(string)
	if sub["seats"] != float64(1) || sub["active"] != true || sub["can_connect"] != true || sub["paid_until"] != nil {
		t.Fatal("invalid trial subscription")
	}
	if status, _ := owner.do(t, "POST", "/api/v1/account/subscriptions/"+id+"/code", nil); status != 404 {
		t.Fatal("issued a raw legacy code for trial-only access", status)
	}
	if status, out := owner.do(t, "POST", "/api/v1/account/subscriptions", map[string]any{"plan_id": "player-month", "seats": 1}); status != 201 || out["id"] != id {
		t.Fatal("purchase path created a second subscription", status)
	}

	connect := func(machine string) enrollment.DeviceLink {
		t.Helper()
		l, req, _ := newLinkRequest(t, "device", machine)
		if status, _ := owner.do(t, "POST", "/api/v1/enroll/device/start", req); status != 201 {
			t.Fatal("device start", status)
		}
		if status, _ := owner.do(t, "POST", "/api/v1/account/device-links/"+l.ID+"/approve", map[string]string{"subscription_id": id}); status != 200 {
			t.Fatal("device approval", status)
		}
		return l
	}
	l, device, key := newLinkRequest(t, "device", strings.Repeat("a", 64))
	if status, _ := owner.do(t, "POST", "/api/v1/enroll/device/start", device); status != 201 {
		t.Fatal("first start", status)
	}
	if status, _ := owner.do(t, "POST", "/api/v1/account/device-links/"+l.ID+"/approve", map[string]string{"subscription_id": id}); status != 200 {
		t.Fatal("first approval", status)
	}
	status, response := owner.do(t, "POST", "/api/v1/enroll/device/poll", enrollment.DeviceLinkPoll{ID: l.ID, Secret: l.Secret})
	binding := decodeLinkStatus(t, response).Account
	if status != 200 || binding.TrialUntil == nil || !binding.TrialUntil.Equal(until) {
		t.Fatal("client did not receive the binding deadline", status)
	}
	second := connect(strings.Repeat("b", 64))
	if status, out := owner.do(t, "POST", "/api/v1/enroll/device/poll", enrollment.DeviceLinkPoll{ID: second.ID, Secret: second.Secret}); status != 403 || out["error"] != "ACTIVATION_LIMIT" {
		t.Fatal("second seat admitted", status)
	}
	if err := store.PutRelay(ctx, optimizer.RelayCandidate{ID: "R1", Address: "192.0.2.1:4433"}); err != nil {
		t.Fatal(err)
	}
	var shortDeadline time.Time
	if err := store.DB.QueryRow(ctx, "UPDATE subscriptions SET trial_until=now()+interval '30 seconds' WHERE id=$1 RETURNING trial_until", id).Scan(&shortDeadline); err != nil {
		t.Fatal(err)
	}
	deviceID := device.Device.DeviceID
	proof, err := security.NewProof(deviceID, "R1", key, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	request, _ := json.Marshal(proof)
	w := httptest.NewRecorder()
	api.Handler().ServeHTTP(w, httptest.NewRequest("POST", "/api/v1/auth", bytes.NewReader(request)))
	var ticket security.Ticket
	trust := map[string]ed25519.PublicKey{api.Settings.KeyID: api.Settings.SigningKey.Public().(ed25519.PublicKey)}
	if err = security.Verify("ticket", trust, w.Body.Bytes(), &ticket); w.Code != 200 || err != nil ||
		ticket.TrialUntil == nil || !ticket.TrialUntil.Equal(shortDeadline) || !ticket.ExpiresAt.Equal(shortDeadline) {
		t.Fatal("trial ticket missing hard deadline", w.Code, err)
	}
	ent, err := store.DeviceEntitlement(ctx, deviceID)
	if err != nil || !ent.Active(shortDeadline.Add(-time.Nanosecond)) || ent.Active(shortDeadline) {
		t.Fatal("trial access violated the exact boundary", err)
	}
	viewBefore := statusFor(ent, true, shortDeadline.Add(-time.Nanosecond))
	viewAt := statusFor(ent, true, shortDeadline)
	if !viewBefore.Active || viewAt.Active || viewAt.PaidUntil != nil || viewAt.GraceUntil == nil || !viewAt.GraceUntil.Equal(shortDeadline) {
		t.Fatal("device status granted grace to trial access")
	}
	if _, err = store.DB.Exec(ctx, "UPDATE subscriptions SET trial_until=now() WHERE id=$1", id); err != nil {
		t.Fatal(err)
	}
	api.Settings.PersonalTrials = false
	if status, out := deviceCall(t, api, "/api/v1/auth", deviceID, "R1", key); status != 402 || out["error"] != "SUBSCRIPTION_EXPIRED" {
		t.Fatal("expired trial authorized after the flag was disabled", status)
	}
	if status, out := owner.do(t, "POST", "/api/v1/enroll/device/poll", enrollment.DeviceLinkPoll{ID: l.ID, Secret: l.Secret}); status != 403 || out["error"] != "SUBSCRIPTION_EXPIRED" {
		t.Fatal("expired binding approved", status)
	}
	paidAt := time.Now().UTC().Truncate(time.Microsecond)
	paid, extended, err := store.RecordPayment(ctx, id, "manual", "trial-upgrade", 39900, 30, "succeeded", "fixture", "admin", paidAt)
	if err != nil || !extended || !paid.Equal(paidAt.Add(30*24*time.Hour)) {
		t.Fatal("paid access did not start on the same subscription", err)
	}
	if status, _ := deviceCall(t, api, "/api/v1/auth", deviceID, "R1", key); status != 200 {
		t.Fatal("payment did not restore access", status)
	}
	_, view = owner.do(t, "GET", "/api/v1/account", nil)
	subs = view["subscriptions"].([]any)
	if len(subs) != 1 || subs[0].(map[string]any)["id"] != id || len(view["payments"].([]any)) != 1 {
		t.Fatal("payment or subscription history changed")
	}
}

func TestPersonalTrialMigrationPreservesExistingAccounts(t *testing.T) {
	api, store, mail := accountAPI(t, false)
	ctx := context.Background()
	if _, err := store.DB.Exec(ctx, "DROP TABLE account_trial_offers; ALTER TABLE subscriptions DROP COLUMN trial_until; DELETE FROM schema_migrations WHERE version=10"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.DB.Exec(ctx, `
		INSERT INTO accounts(id,email,account_type) VALUES('historical','historical@example.test','player');
		INSERT INTO subscriptions(id,account_id,plan_id,kind,seats,paid_until,lifetime)
		VALUES ('legacy-lifetime','historical','player-month','player',1,NULL,true),
		       ('legacy-paid','historical','player-month','player',1,now()+interval '30 days',false);
		INSERT INTO payments(id,subscription_id,provider,provider_payment_id,amount_kopecks,period_days,status)
		VALUES ('historical-payment','legacy-paid','manual','fixture-old',39900,30,'succeeded');`); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err := store.Migrate(ctx); err != nil {
			t.Fatal("schema 9 to 10 or repeat", err)
		}
	}
	api.Settings.PersonalTrials = true
	c := &call{api: api}
	login(t, c, mail, "historical@example.test")
	status, out := c.do(t, "GET", "/api/v1/account", nil)
	if status != 200 || out["trial_code"] != nil || len(out["subscriptions"].([]any)) != 2 || len(out["payments"].([]any)) != 1 {
		t.Fatal("migration changed historical rights or trial eligibility", status)
	}
	for _, value := range out["subscriptions"].([]any) {
		sub := value.(map[string]any)
		if sub["trial_until"] != nil || sub["active"] != true || sub["can_connect"] != true {
			t.Fatal("migration changed historical access")
		}
	}
}
