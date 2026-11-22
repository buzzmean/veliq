package controlplane

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"net/http"
	"strings"
	"testing"

	"github.com/buzzmean/neexitlag/core/enrollment"
	"github.com/buzzmean/neexitlag/core/security"
)

func TestClubVerificationCheckoutRequiresPaidOrderAndOperator(t *testing.T) {
	api, store, mailer := accountAPI(t, false)
	api.Settings.ClubVerificationToken = strings.Repeat("v", 32)
	api.Settings.Plans[1].PricePerSeatRub = 299
	mock := newMockPlatega(t)
	api.Settings.Payments = mock.provider()
	c := &call{api: api}
	login(t, c, mailer, "club@example.test")
	if code, _ := c.do(t, "POST", "/api/v1/account/profile", map[string]string{"kind": "club", "name": "Club fixture"}); code != 200 {
		t.Fatal("profile", code)
	}
	st, response := c.do(t, "POST", "/api/v1/account/subscriptions", map[string]any{"plan_id": "club-month", "seats": 2})
	if st != 201 {
		t.Fatal("create", st, response)
	}
	sub := response["id"].(string)
	codePath := "/api/v1/account/subscriptions/" + sub + "/code"
	const queuePath = "/api/v1/club-verifications"
	verifyPath := queuePath + "/" + sub + "/approve"
	operator := map[string]any{"operator_id": 42}
	bot := func(r *http.Request) {
		r.Header.Set("Authorization", "Bearer "+api.Settings.ClubVerificationToken)
	}
	checkCode := func(status int, want string) {
		t.Helper()
		if got, out := c.do(t, "POST", codePath, nil); got != status || out["error"] != want || out["code"] != nil {
			t.Fatal("code gate", got, out)
		}
	}
	checkQueue := func(n int) {
		t.Helper()
		got, out := c.do(t, "GET", queuePath, nil, bot)
		if got != 200 || len(out["requests"].([]any)) != n {
			t.Fatal("verification queue", got, out)
		}
		if n == 1 {
			row := out["requests"].([]any)[0].(map[string]any)
			if len(row) != 2 || row["subscription_id"] != sub || row["seats"] != float64(2) {
				t.Fatal("unexpected verification metadata", row)
			}
		}
	}
	checkCode(409, "CLUB_PAYMENT_REQUIRED")
	checkQueue(0)
	if st, _ = c.do(t, "POST", verifyPath, operator, bot); st != 409 {
		t.Fatal("operator approved an unpaid club", st)
	}
	payRequest := confirmedPayRequest(t, c, sub, map[string]any{})
	if st, _ = c.do(t, "POST", "/api/v1/account/subscriptions/"+sub+"/pay", payRequest); st != 200 {
		t.Fatal("checkout", st)
	}
	checkQueue(0)
	checkCode(409, "CLUB_PAYMENT_REQUIRED")
	webhook := map[string]any{"id": mock.nextTx.Load().(string), "amount": 598, "currency": "RUB", "status": "CONFIRMED", "paymentMethod": 2, "payload": "veliq:sub:" + sub}
	if st, response = c.do(t, "POST", "/api/v1/payments/webhook", webhook, func(r *http.Request) {
		r.Header.Set("X-MerchantId", "merchant-1")
		r.Header.Set("X-Secret", "test-secret")
	}); st != 200 {
		t.Fatal("confirmed webhook", st, response)
	}
	checkQueue(1)
	checkCode(409, "CLUB_VERIFICATION_PENDING")
	if st, response = c.do(t, "GET", "/api/v1/account", nil); st != 200 {
		t.Fatal("cabinet state", st, response)
	}
	paid := response["subscriptions"].([]any)[0].(map[string]any)
	if paid["club_verification"] != "pending" || paid["can_connect"] != false {
		t.Fatal("cabinet claimed access during verification", paid)
	}
	link, request, _ := newLinkRequest(t, "image", "")
	if st, response = c.do(t, "POST", "/api/v1/enroll/device/start", request); st != 201 {
		t.Fatal("image request", st, response)
	}
	if st, response = c.do(t, "POST", "/api/v1/account/device-links/"+link.ID+"/approve", map[string]string{"subscription_id": sub}); st != 403 || response["error"] != "CLUB_VERIFICATION_PENDING" {
		t.Fatal("browser link bypassed review", st, response)
	}
	if st, _ = c.do(t, "POST", verifyPath, operator); st != 401 {
		t.Fatal("account holder approved own club", st)
	}
	if st, _ = c.do(t, "POST", verifyPath, operator, func(r *http.Request) {
		r.Header.Set("Authorization", "Bearer "+api.Settings.AdminToken)
	}); st != 401 {
		t.Fatal("unscoped operator token accepted by bot endpoint", st)
	}
	if st, _ = c.do(t, "POST", queuePath+"/"+sub+"/notified", nil, bot); st != 200 {
		t.Fatal("queue acknowledgement", st)
	}
	checkQueue(0)
	checkCode(409, "CLUB_VERIFICATION_PENDING")
	for range 2 {
		if st, response = c.do(t, "POST", verifyPath, operator, bot); st != 200 || response["verified"] != true {
			t.Fatal("verification", st, response)
		}
	}
	var audits int
	if err := store.DB.QueryRow(context.Background(), "SELECT count(*) FROM audit_log WHERE action='subscription.club_verified' AND entity_id=$1", sub).Scan(&audits); err != nil || audits != 1 {
		t.Fatal("duplicated operator action", audits, err)
	}
	st, response = c.do(t, "POST", codePath, nil)
	if st != 200 {
		t.Fatal("issue after verification", st, response)
	}
	rawCode := response["code"].(string)
	dev, _ := enrollWith(t, api, store, rawCode, strings.Repeat("a", 64))
	enrollWith(t, api, store, rawCode, strings.Repeat("b", 64))
	ent, err := store.DeviceEntitlement(context.Background(), dev)
	if err != nil || !ent.Managed || !ent.AccountBound {
		t.Fatal("enrollment bypasses the purchased period", err)
	}
	public, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	id, err := security.NewID()
	if err != nil {
		t.Fatal(err)
	}
	hash, err := enrollment.CodeHash(rawCode)
	if err != nil {
		t.Fatal(err)
	}
	third := Device{ID: id, Name: "Fixture", PublicKey: base64.RawURLEncoding.EncodeToString(public)}
	if err = store.EnrollCode(context.Background(), hash, strings.Repeat("c", 64), third, api.Settings.KeyID, api.Settings.SigningKey, api.trust()); err == nil || err.Error() != "ACTIVATION_LIMIT" {
		t.Fatal("more PCs than paid seats accepted", err)
	}
	if _, err = store.DB.Exec(context.Background(), "UPDATE subscriptions SET paid_until=now()-interval '1 minute' WHERE id=$1", sub); err != nil {
		t.Fatal(err)
	}
	checkCode(409, "SUBSCRIPTION_EXPIRED")
	if err = store.EnrollCode(context.Background(), hash, strings.Repeat("c", 64), third, api.Settings.KeyID, api.Settings.SigningKey, api.trust()); err != errClubVerificationExpired {
		t.Fatal("old activation code bypassed paid-period verification", err)
	}
}
