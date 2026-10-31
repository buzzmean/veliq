package controlplane

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/buzzmean/neexitlag/core/enrollment"
	"github.com/buzzmean/neexitlag/core/optimizer"
	"github.com/buzzmean/neexitlag/core/security"
)

type fakeMailer struct {
	mu   sync.Mutex
	sent map[string]string
}

func (f *fakeMailer) Send(_ context.Context, to, subject, body string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.sent == nil {
		f.sent = map[string]string{}
	}
	f.sent[to] = body[strings.Index(body, ": ")+2 : strings.Index(body, ": ")+8]
	return nil
}

const testOrigin = "https://cabinet.test"

func accountAPI(t *testing.T, enforce bool) (*API, *Store, *fakeMailer) {
	t.Helper()
	s := codeStore(t)
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(48 * time.Hour)}
	der, _ := x509.CreateCertificate(rand.Reader, tpl, tpl, pub, key)
	ca, _ := x509.ParseCertificate(der)
	m := &fakeMailer{}
	plans := []Plan{{ID: "player-month", Kind: "player", Title: "Игрок", PricePerSeatRub: 300, PeriodDays: 30, MaxSeats: 1}, {ID: "club-month", Kind: "club", Title: "Клуб", PricePerSeatRub: 200, PeriodDays: 30, MaxSeats: 500}}
	api, e := New(s, Settings{AdminToken: strings.Repeat("a", 32), EnrollmentProbeToken: strings.Repeat("p", 32), KeyID: "test", SigningKey: key, CA: ca, CAKey: key, AccountOrigin: testOrigin, Mailer: m, Plans: plans, EnforceSubscription: enforce})
	if e != nil {
		t.Fatal(e)
	}
	if e = api.Initialize(context.Background()); e != nil {
		t.Fatal(e)
	}
	return api, s, m
}

type call struct {
	api    *API
	cookie string
	ip     string
}

func (c *call) do(t *testing.T, method, path string, v any, mutate ...func(*http.Request)) (int, map[string]any) {
	t.Helper()
	var raw []byte
	if v != nil {
		raw, _ = json.Marshal(v)
	}
	r := httptest.NewRequest(method, path, bytes.NewReader(raw))
	r.RemoteAddr = c.ip + ":5000"
	if c.ip == "" {
		r.RemoteAddr = "198.51.100.7:5000"
	}
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Origin", testOrigin)
	if c.cookie != "" {
		r.AddCookie(&http.Cookie{Name: sessionCookie, Value: c.cookie})
	}
	for _, f := range mutate {
		f(r)
	}
	w := httptest.NewRecorder()
	c.api.Handler().ServeHTTP(w, r)
	for _, ck := range w.Result().Cookies() {
		if ck.Name == sessionCookie {
			c.cookie = ck.Value
			if !ck.HttpOnly || !ck.Secure || ck.SameSite != http.SameSiteStrictMode {
				t.Fatal("session cookie must be HttpOnly, Secure, SameSite=Strict")
			}
		}
	}
	out := map[string]any{}
	json.Unmarshal(w.Body.Bytes(), &out)
	return w.Code, out
}

func login(t *testing.T, c *call, m *fakeMailer, email string) {
	t.Helper()
	if code, out := c.do(t, "POST", "/api/v1/account/login/start", map[string]string{"email": email}); code != 200 {
		t.Fatal("login start", code, out)
	}
	if code, out := c.do(t, "POST", "/api/v1/account/login/verify", map[string]string{"email": email, "code": m.sent[strings.ToLower(email)]}); code != 200 || c.cookie == "" {
		t.Fatal("login verify", code, out)
	}
}

func TestAccountLoginCodesSessionsAndOriginGuard(t *testing.T) {
	api, s, m := accountAPI(t, false)
	c := &call{api: api}
	if code, _ := c.do(t, "POST", "/api/v1/account/login/start", map[string]string{"email": "not-an-email"}); code != 400 {
		t.Fatal("invalid email accepted", code)
	}
	if code, out := c.do(t, "POST", "/api/v1/account/login/start", map[string]string{"email": "Player@Example.com"}, func(r *http.Request) { r.Header.Set("Origin", "https://evil.test") }); code != 403 {
		t.Fatal("foreign origin accepted", code, out)
	}
	if code, _ := c.do(t, "GET", "/api/v1/account", nil); code != 401 {
		t.Fatal("cabinet without session", code)
	}
	if code, _ := c.do(t, "POST", "/api/v1/account/login/start", map[string]string{"email": "Player@Example.com"}); code != 200 {
		t.Fatal("start", code)
	}
	good := m.sent["player@example.com"]
	if len(good) != 6 {
		t.Fatal("code not mailed", m.sent)
	}
	// A resend inside a minute mails nothing new but answers the same.
	m.sent = nil
	if code, _ := c.do(t, "POST", "/api/v1/account/login/start", map[string]string{"email": "player@example.com"}); code != 200 || m.sent != nil {
		t.Fatal("resend throttle", code, m.sent)
	}
	wrong := "000000"
	if good == wrong {
		wrong = "111111"
	}
	for i := 0; i < LoginCodeAttempts; i++ {
		if code, _ := c.do(t, "POST", "/api/v1/account/login/verify", map[string]string{"email": "player@example.com", "code": wrong}); code != 401 {
			t.Fatal("wrong code accepted", code)
		}
	}
	if code, _ := c.do(t, "POST", "/api/v1/account/login/verify", map[string]string{"email": "player@example.com", "code": good}); code != 401 {
		t.Fatal("code must be burned after too many attempts", code)
	}
	// A fresh code (after the resend interval) logs in and creates the account.
	c.ip = "198.51.100.8" // the guessing address above is rate limited by now
	code, sent, e := s.StartLogin(context.Background(), "player@example.com", time.Now().Add(2*LoginResendInterval))
	if e != nil || !sent {
		t.Fatal(e, sent)
	}
	if st, out := c.do(t, "POST", "/api/v1/account/login/verify", map[string]string{"email": "player@example.com", "code": code}); st != 200 || out["email"] != "player@example.com" {
		t.Fatal("login", st, out)
	}
	if st, out := c.do(t, "GET", "/api/v1/account", nil); st != 200 || out["email"] != "player@example.com" {
		t.Fatal("cabinet", st, out)
	}
	if st, _ := c.do(t, "POST", "/api/v1/account/login/verify", map[string]string{"email": "player@example.com", "code": code}); st != 401 {
		t.Fatal("login code reused", st)
	}
	if st, _ := c.do(t, "POST", "/api/v1/account/logout", map[string]string{}); st != 200 {
		t.Fatal("logout", st)
	}
	stale := &call{api: api, cookie: strings.Repeat("x", 43)}
	if st, _ := stale.do(t, "GET", "/api/v1/account", nil); st != 401 {
		t.Fatal("unknown session accepted", st)
	}
	api.Settings.AccountOrigin = ""
	if st, _ := (&call{api: api}).do(t, "POST", "/api/v1/account/login/start", map[string]string{"email": "a@b.cd"}); st != 503 {
		t.Fatal("cabinet must stay off without origin", st)
	}
}

func enrollWith(t *testing.T, api *API, s *Store, code, machine string) (string, ed25519.PrivateKey) {
	t.Helper()
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	id, _ := security.NewID()
	hash, e := enrollment.CodeHash(code)
	if e != nil {
		t.Fatal(e)
	}
	if e = s.EnrollCode(context.Background(), hash, machine, Device{ID: id, Name: "VELIQ device", PublicKey: base64.RawURLEncoding.EncodeToString(pub)}, api.Settings.KeyID, api.Settings.SigningKey, api.trust()); e != nil {
		t.Fatal("enroll", e)
	}
	return id, key
}

func deviceCall(t *testing.T, api *API, path, device, audience string, key ed25519.PrivateKey) (int, map[string]any) {
	t.Helper()
	p, _ := security.NewProof(device, audience, key, time.Now())
	return (&call{api: api}).do(t, "POST", path, p)
}

func TestSubscriptionLifecyclePaymentSeatsAndEnforcement(t *testing.T) {
	api, s, m := accountAPI(t, true)
	ctx := context.Background()
	if e := s.PutRelay(ctx, optimizer.RelayCandidate{ID: "R1", Address: "192.0.2.1:443"}); e != nil {
		t.Fatal(e)
	}
	c := &call{api: api}
	login(t, c, m, "club@example.com")
	if st, _ := c.do(t, "POST", "/api/v1/account/subscriptions", map[string]any{"plan_id": "player-month", "seats": 2}); st != 400 {
		t.Fatal("player plan allows one seat", st)
	}
	st, out := c.do(t, "POST", "/api/v1/account/subscriptions", map[string]any{"plan_id": "club-month", "seats": 2})
	if st != 201 {
		t.Fatal("create", st, out)
	}
	sub := out["id"].(string)
	st, out = c.do(t, "POST", "/api/v1/account/subscriptions/"+sub+"/code", map[string]any{})
	if st != 200 {
		t.Fatal("code", st, out)
	}
	code := out["code"].(string)
	dev, key := enrollWith(t, api, s, code, strings.Repeat("a", 64))
	// Activated but unpaid: no relay ticket, status says inactive.
	if st, out = deviceCall(t, api, "/api/v1/auth", dev, "R1", key); st != 402 || out["error"] != "SUBSCRIPTION_EXPIRED" {
		t.Fatal("unpaid device got a ticket", st, out)
	}
	if st, out = deviceCall(t, api, "/api/v1/subscription/status", dev, security.SubscriptionAudience, key); st != 200 || out["active"] != false || out["managed"] != true {
		t.Fatal("status unpaid", st, out)
	}
	if st, _ = deviceCall(t, api, "/api/v1/subscription/status", dev, "R1", key); st != 400 {
		t.Fatal("ticket audience accepted for status", st)
	}
	// Club pays an invoice: the operator credits it; the same reference twice extends once.
	admin := func(r *http.Request) { r.Header.Set("Authorization", "Bearer "+strings.Repeat("a", 32)) }
	pay := map[string]any{"subscription_id": sub, "amount_kopecks": 40000, "period_days": 30, "reference": "invoice-1"}
	st, out = c.do(t, "POST", "/api/v1/admin/subscriptions/payments", pay, admin)
	if st != 200 || out["extended"] != true {
		t.Fatal("manual payment", st, out)
	}
	first := out["paid_until"]
	st, out = c.do(t, "POST", "/api/v1/admin/subscriptions/payments", pay, admin)
	if st != 200 || out["extended"] != false || out["paid_until"] != first {
		t.Fatal("repeated payment must not extend twice", st, out)
	}
	if st, _ = c.do(t, "POST", "/api/v1/admin/subscriptions/payments", pay); st != 401 {
		t.Fatal("manual payment without admin", st)
	}
	if st, out = deviceCall(t, api, "/api/v1/auth", dev, "R1", key); st != 200 {
		t.Fatal("paid device refused", st, out)
	}
	// A new code value keeps already activated computers.
	st, out = c.do(t, "POST", "/api/v1/account/subscriptions/"+sub+"/code", map[string]any{})
	if st != 200 || out["code"] == code {
		t.Fatal("rotate", st, out)
	}
	if st, out = deviceCall(t, api, "/api/v1/auth", dev, "R1", key); st != 200 {
		t.Fatal("rotation dropped a seat", st, out)
	}
	st, out = c.do(t, "GET", "/api/v1/account", nil)
	subs := out["subscriptions"].([]any)
	first0 := subs[0].(map[string]any)
	if st != 200 || first0["used_seats"].(float64) != 1 || first0["active"] != true {
		t.Fatal("cabinet view", st, out)
	}
	machine := first0["devices"].([]any)[0].(map[string]any)["machine"].(string)
	// Another account cannot touch this subscription.
	other := &call{api: api, ip: "198.51.100.9"}
	login(t, other, m, "other@example.com")
	if st, _ = other.do(t, "POST", "/api/v1/account/subscriptions/"+sub+"/devices/"+machine+"/release", map[string]any{}); st != 404 {
		t.Fatal("foreign release", st)
	}
	if st, _ = other.do(t, "POST", "/api/v1/account/subscriptions/"+sub+"/code", map[string]any{}); st != 404 {
		t.Fatal("foreign code", st)
	}
	if st, out = c.do(t, "POST", "/api/v1/account/subscriptions/"+sub+"/devices/"+machine+"/release", map[string]any{}); st != 200 {
		t.Fatal("release", st, out)
	}
	if st, _ = deviceCall(t, api, "/api/v1/auth", dev, "R1", key); st != 401 {
		t.Fatal("released device kept access", st)
	}
	st, out = c.do(t, "GET", "/api/v1/account", nil)
	if out["subscriptions"].([]any)[0].(map[string]any)["used_seats"].(float64) != 0 {
		t.Fatal("seat not freed", out)
	}
	if st, _ = c.do(t, "POST", "/api/v1/account/subscriptions/"+sub+"/pay", map[string]any{}); st != 503 {
		t.Fatal("payment provider is not configured yet", st)
	}
}

func TestEnforcementOffKeepsLegacyBehaviourAndCutoffPreview(t *testing.T) {
	api, s, _ := accountAPI(t, false)
	ctx := context.Background()
	if e := s.PutRelay(ctx, optimizer.RelayCandidate{ID: "R1", Address: "192.0.2.1:443"}); e != nil {
		t.Fatal(e)
	}
	c, raw, e := s.CreateCode(ctx, ActivationCode{Kind: "club", Limit: 5, Name: "legacy club", Expires: time.Now().Add(time.Hour)})
	if e != nil {
		t.Fatal(e)
	}
	dev, key := enrollWith(t, api, s, raw, strings.Repeat("b", 64))
	// Make the legacy code period end (past grace).
	if _, e = s.DB.Exec(ctx, "UPDATE activation_codes SET expires_at=now()-interval '5 days' WHERE id=$1", c.ID); e != nil {
		t.Fatal(e)
	}
	if st, out := deviceCall(t, api, "/api/v1/auth", dev, "R1", key); st != 200 {
		t.Fatal("enforcement off must not change auth", st, out)
	}
	st, out := deviceCall(t, api, "/api/v1/subscription/status", dev, security.SubscriptionAudience, key)
	if st != 200 || out["active"] != true || out["enforced"] != false || out["paid_until"] == nil {
		t.Fatal("status with enforcement off", st, out)
	}
	admin := func(r *http.Request) { r.Header.Set("Authorization", "Bearer "+strings.Repeat("a", 32)) }
	st, out = (&call{api: api}).do(t, "GET", "/api/v1/admin/subscriptions/cutoff", nil, admin)
	devices := out["devices"].([]any)
	if st != 200 || len(devices) != 1 || devices[0].(map[string]any)["device_id"] != dev {
		t.Fatal("cutoff preview", st, out)
	}
	// Within grace the device is still active when enforcement is switched on.
	if _, e = s.DB.Exec(ctx, "UPDATE activation_codes SET expires_at=now()-interval '1 day' WHERE id=$1", c.ID); e != nil {
		t.Fatal(e)
	}
	api.Settings.EnforceSubscription = true
	if st, out = deviceCall(t, api, "/api/v1/auth", dev, "R1", key); st != 200 {
		t.Fatal("grace period ignored", st, out)
	}
	// An operator-registered device without a slot is never limited.
	ent, e := s.DeviceEntitlement(ctx, "no-such-device")
	if e != nil || ent.Managed || !ent.Active(time.Now()) {
		t.Fatal("unmanaged device", ent, e)
	}
}

func TestPlansFileAndEmailNormalization(t *testing.T) {
	for in, want := range map[string]string{" User@Mail.RU ": "user@mail.ru", "a@b.cd": "a@b.cd"} {
		if got, ok := normalizeEmail(in); !ok || got != want {
			t.Fatal(in, got, ok)
		}
	}
	for _, bad := range []string{"", "user", "user@localhost", "Name <a@b.cd>", "a@b.cd\r\nBcc: x@y.z"} {
		if _, ok := normalizeEmail(bad); ok {
			t.Fatal("accepted", bad)
		}
	}
	dir := t.TempDir()
	write := func(s string) string {
		p := dir + "/plans.json"
		if e := writeFile(p, s); e != nil {
			t.Fatal(e)
		}
		return p
	}
	if _, e := LoadPlans(write(`[{"id":"club-month","kind":"club","title":"Клуб","price_per_seat_rub":0,"period_days":30,"max_seats":500}]`)); e != nil {
		t.Fatal(e)
	}
	if _, e := LoadPlans(write(`[{"id":"a","kind":"club","title":"x","price_per_seat_rub":1,"period_days":30,"max_seats":5},{"id":"a","kind":"club","title":"x","price_per_seat_rub":1,"period_days":30,"max_seats":5}]`)); e == nil {
		t.Fatal("duplicate plan accepted")
	}
	if _, e := LoadPlans(write(`[{"id":"a","kind":"vip","title":"x","price_per_seat_rub":1,"period_days":30,"max_seats":5}]`)); e == nil {
		t.Fatal("unknown kind accepted")
	}
}

func TestSourceKeyTrustsRealIPOnlyFromLoopback(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "127.0.0.1:1234"
	r.Header.Set("X-Real-IP", "203.0.113.5")
	if sourceKey(r) != "203.0.113.5" {
		t.Fatal("proxy address ignored")
	}
	r.RemoteAddr = "198.51.100.1:1234"
	if sourceKey(r) != "198.51.100.1" {
		t.Fatal("remote client spoofed its address")
	}
}

func writeFile(path, s string) error { return os.WriteFile(path, []byte(s), 0o600) }
