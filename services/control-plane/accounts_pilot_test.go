package controlplane

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/json"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/buzzmean/neexitlag/core/optimizer"
	"github.com/buzzmean/neexitlag/core/security"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestPilotSTARTTLSHTTPSLoginLogout(t *testing.T) {
	a, _, _ := accountAPI(t, false)
	// Ephemeral loopback port: this acceptance must not silently skip because
	// privileged SMTP ports are unavailable or another fixture is using them.
	smtp := startFakeSMTP(t, "0", false, true)
	a.Settings.Mailer = smtp.mailer
	server := httptest.NewTLSServer(a.Handler())
	defer server.Close()
	client := server.Client() // Trust this server's test certificate; no TLS bypass.
	client.Timeout = 10 * time.Second
	var err error
	client.Jar, err = cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	request := func(method, path string, input any, want int) *http.Response {
		t.Helper()
		body, err := json.Marshal(input)
		if err != nil {
			t.Fatal(err)
		}
		r, err := http.NewRequest(method, server.URL+path, bytes.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		r.Header.Set("Origin", testOrigin)
		r.Header.Set("Content-Type", "application/json")
		response, err := client.Do(r)
		if err != nil {
			t.Fatal("isolated HTTPS request failed", err)
		}
		response.Body.Close()
		if response.StatusCode != want {
			t.Fatalf("%s %s: HTTP %d, expected %d (body suppressed)", method, path, response.StatusCode, want)
		}
		return response
	}
	request("POST", "/api/v1/account/login/start", map[string]string{"email": "smtp-pilot@example.com"}, 200)
	var mail string
	select {
	case mail = <-smtp.data:
	case <-time.After(time.Second):
		t.Fatal("SMTP DATA not received")
	}
	if err := <-smtp.err; err != nil {
		t.Fatal("isolated SMTP TLS/authentication failed", err)
	}
	match := regexp.MustCompile(`(?m)^Код для входа в личный кабинет VELIQ: ([0-9]{6})`).FindStringSubmatch(mail)
	if len(match) != 2 {
		t.Fatal("login code absent from SMTP DATA (payload suppressed)")
	}
	verify := map[string]string{"email": "smtp-pilot@example.com", "code": match[1]}
	response := request("POST", "/api/v1/account/login/verify", verify, 200)
	var cookie *http.Cookie
	for _, c := range response.Cookies() {
		if c.Name == sessionCookie {
			cookie = c
		}
	}
	if cookie == nil || !cookie.Secure || !cookie.HttpOnly || cookie.SameSite != http.SameSiteStrictMode || cookie.Path != "/api/v1/account" {
		t.Fatal("session security attributes missing")
	}
	request("GET", "/api/v1/account", nil, 200)
	request("POST", "/api/v1/account/logout", map[string]any{}, 200)
	request("GET", "/api/v1/account", nil, 401)
	request("POST", "/api/v1/account/logout", map[string]any{}, 200)
	request("POST", "/api/v1/account/login/verify", verify, 401)
	// A stolen old cookie is unusable after server-side logout, too.
	r, _ := http.NewRequest("GET", server.URL+"/api/v1/account", nil)
	r.AddCookie(cookie)
	res, err := client.Do(r)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != 401 {
		t.Fatal("logged-out server session survived", res.StatusCode)
	}
}

func TestPilotMigration004PreservesSchema3IdentityAndCertificate(t *testing.T) {
	a, base, _ := accountAPI(t, false)
	ctx := context.Background()
	id, err := security.NewID()
	if err != nil {
		t.Fatal(err)
	}
	schema := "pilot_schema3_" + id
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
	s := &Store{pool}
	a.Store = s
	for _, name := range []string{"001_initial.sql", "002_activation_codes.sql", "003_temporary_test_codes.sql"} {
		sql, err := migrations.ReadFile("migrations/" + name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = pool.Exec(ctx, string(sql)); err != nil {
			t.Fatal(err)
		}
	}
	if _, err = pool.Exec(ctx, "INSERT INTO activation_policy VALUES(true,decode(repeat('01',32),'hex'))"); err != nil {
		t.Fatal(err)
	}
	if err = s.PutRelay(ctx, optimizer.RelayCandidate{ID: "R1", Address: "192.0.2.1:4433"}); err != nil {
		t.Fatal(err)
	}
	legacy, code, err := s.CreateCode(ctx, ActivationCode{Kind: "club", Limit: 2, Name: "isolated schema3", Expires: time.Now().Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	device, key := enrollWith(t, a, s, code, strings.Repeat("c", 64))
	// Preserve real revocation/disabled-slot history, not only active rows.
	enrollWith(t, a, s, code, strings.Repeat("e", 64))
	if err = s.RevokeCode(ctx, legacy.ID, strings.Repeat("e", 64), a.Settings.KeyID, a.Settings.SigningKey, a.trust()); err != nil {
		t.Fatal(err)
	}
	if _, err = pool.Exec(ctx, "INSERT INTO auth_nonces VALUES($1,'preserved-fixture-nonce',now()+interval '1 hour')", device); err != nil {
		t.Fatal(err)
	}
	der, err := issueClientCertificate(a.Settings.CA, a.Settings.CAKey, key.Public().(ed25519.PublicKey), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "client.der")
	if err = os.WriteFile(path, der, 0600); err != nil {
		t.Fatal(err)
	}
	snapshot := func() string {
		t.Helper()
		var out string
		err := pool.QueryRow(ctx, `SELECT jsonb_build_object(
'devices',(SELECT jsonb_agg(to_jsonb(d) ORDER BY id) FROM devices d),
'codes',(SELECT jsonb_agg(to_jsonb(c)-'subscription_id' ORDER BY id) FROM activation_codes c),
'slots',(SELECT jsonb_agg(to_jsonb(s) ORDER BY code_id,machine_hash) FROM activation_slots s),
'nonces',(SELECT jsonb_agg(to_jsonb(n) ORDER BY device_id,nonce) FROM auth_nonces n),
'configs',(SELECT jsonb_agg(to_jsonb(c) ORDER BY version) FROM config_versions c),
'salt',(SELECT jsonb_agg(to_jsonb(p)) FROM activation_policy p))::text`).Scan(&out)
		if err != nil {
			t.Fatal(err)
		}
		return out
	}
	before := snapshot()
	for i := 0; i < 2; i++ {
		if err = s.Migrate(ctx); err != nil {
			t.Fatal("schema3 -> schema4 / repeat", err)
		}
		if snapshot() != before {
			t.Fatal("migration changed existing identity/security state (values suppressed)")
		}
	}
	var version int
	if err = pool.QueryRow(ctx, "SELECT max(version) FROM schema_migrations").Scan(&version); err != nil || version != 4 {
		t.Fatal("schema4 missing", err, version)
	}
	after, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(after, der) {
		t.Fatal("test certificate changed", err)
	}
	leaf, err := x509.ParseCertificate(after)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(a.Settings.CA)
	if _, err = leaf.Verify(x509.VerifyOptions{Roots: roots, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		t.Fatal("old test certificate no longer verifies", err)
	}
	if status, _ := deviceCall(t, a, "/api/v1/auth", device, "R1", key); status != 200 {
		t.Fatal("existing device lost authorization after migration", status)
	}
}

func TestPilotDatabaseUnavailableDoesNotAcknowledgeAndRecovers(t *testing.T) {
	a, s, mailer := accountAPI(t, false)
	c := &call{api: a}
	login(t, c, mailer, "db-pilot@example.com")
	token := c.cookie
	cfg := s.DB.Config()
	s.DB.Close() // Deterministic outage of the entire client pool, not one SQL statement.
	for _, q := range []struct {
		path string
		body map[string]any
	}{
		{"/api/v1/account/login/start", map[string]any{"email": "db-retry@example.com"}},
		{"/api/v1/account/logout", map[string]any{}},
		{"/api/v1/account/subscriptions", map[string]any{"plan_id": "club-month", "seats": 2}},
	} {
		if status, _ := c.do(t, "POST", q.path, q.body); status != 503 {
			t.Fatal("database outage acknowledged", q.path, status)
		}
	}
	if c.cookie != token {
		t.Fatal("database outage lost logout retry cookie")
	}
	pool, err := pgxpool.NewWithConfig(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	a.Store = &Store{pool}
	if status, _ := c.do(t, "GET", "/api/v1/account", nil); status != 200 {
		t.Fatal("session did not survive connection-pool recovery", status)
	}
	if status, _ := c.do(t, "POST", "/api/v1/account/logout", nil); status != 200 {
		t.Fatal("logout retry after recovery", status)
	}
}

func TestPilotSubscriptionExpiryGraceAndRecoveryWithoutEnforcement(t *testing.T) {
	a, s, mailer := accountAPI(t, false)
	c := &call{api: a}
	login(t, c, mailer, "expiry-pilot@example.com")
	status, out := c.do(t, "POST", "/api/v1/account/subscriptions", map[string]any{"plan_id": "club-month", "seats": 2})
	if status != 201 {
		t.Fatal("subscription create", status)
	}
	sub := out["id"].(string)
	status, out = c.do(t, "POST", "/api/v1/account/subscriptions/"+sub+"/code", map[string]any{})
	if status != 200 {
		t.Fatal("subscription code", status)
	}
	device, key := enrollWith(t, a, s, out["code"].(string), strings.Repeat("d", 64))
	before, err := s.Device(context.Background(), device)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	for _, elapsed := range []time.Duration{24 * time.Hour, SubscriptionGrace, 96 * time.Hour} {
		if _, err = s.DB.Exec(context.Background(), "UPDATE subscriptions SET paid_until=$2 WHERE id=$1", sub, now.Add(-elapsed)); err != nil {
			t.Fatal(err)
		}
		ent, err := s.DeviceEntitlement(context.Background(), device)
		if err != nil || !ent.Managed || ent.Active(now) != (elapsed < SubscriptionGrace) {
			t.Fatal("expiry/grace boundary", elapsed, err)
		}
		// Compute the access decision without enabling the service flag. Even an
		// expired entitlement remains non-blocking in the pilot's default mode.
		if view := statusFor(ent, false, now); !view.Active || view.Enforced {
			t.Fatal("default mode unexpectedly enforced expiry")
		}
	}
	until, extended, err := s.RecordPayment(context.Background(), sub, "manual", "isolated-expiry-credit", 40000, 30, "succeeded", "fixture", "test", now)
	if err != nil || !extended || !until.Equal(now.Add(30*24*time.Hour)) {
		t.Fatal("isolated recovery credit", err)
	}
	ent, err := s.DeviceEntitlement(context.Background(), device)
	if err != nil || !ent.Active(now) {
		t.Fatal("paid entitlement did not recover", err)
	}
	after, err := s.Device(context.Background(), device)
	if err != nil || after.Revoked || after.PublicKey != before.PublicKey || !key.Public().(ed25519.PublicKey).Equal(mustPilotPublicKey(t, after.PublicKey)) {
		t.Fatal("recovery changed or revoked the existing identity", err)
	}
}

func mustPilotPublicKey(t *testing.T, encoded string) ed25519.PublicKey {
	t.Helper()
	pub, err := security.DecodePublicKey(encoded)
	if err != nil {
		t.Fatal(err)
	}
	return pub
}

func TestPilotConcurrentPlategaWebhookCreditsOnce(t *testing.T) {
	a, s, mailer := accountAPI(t, false)
	mock := newMockPlatega(t) // BaseURL is loopback; no real provider or credentials.
	a.Settings.Payments = mock.provider()
	c := &call{api: a}
	login(t, c, mailer, "webhook-pilot@example.com")
	status, out := c.do(t, "POST", "/api/v1/account/subscriptions", map[string]any{"plan_id": "club-month", "seats": 2})
	if status != 201 {
		t.Fatal("subscription create", status)
	}
	sub := out["id"].(string)
	if status, _ = c.do(t, "POST", "/api/v1/account/subscriptions/"+sub+"/pay", map[string]any{}); status != 200 {
		t.Fatal("mock payment create", status)
	}
	body, _ := json.Marshal(map[string]any{"id": mock.nextTx.Load().(string), "amount": 400, "currency": "RUB", "status": "CONFIRMED", "payload": plategaPayloadPrefix + sub})
	const parallel = 32
	start, results := make(chan struct{}), make(chan int, parallel)
	for i := 0; i < parallel; i++ {
		go func() {
			<-start
			r := plategaWebhookRequest(mock.provider(), string(body))
			w := httptest.NewRecorder()
			a.Handler().ServeHTTP(w, r)
			results <- w.Code
		}()
	}
	close(start)
	for i := 0; i < parallel; i++ {
		if code := <-results; code != 200 {
			t.Fatal("concurrent mock notification failed", code)
		}
	}
	var credits int
	if err := s.DB.QueryRow(context.Background(), "SELECT count(*) FROM audit_log WHERE action='payment.succeeded' AND entity_id=$1", sub).Scan(&credits); err != nil || credits != 1 {
		t.Fatal("duplicate webhook credit", err, credits)
	}
	var until time.Time
	if err := s.DB.QueryRow(context.Background(), "SELECT paid_until FROM subscriptions WHERE id=$1", sub).Scan(&until); err != nil || until.Before(time.Now().Add(29*24*time.Hour)) || until.After(time.Now().Add(31*24*time.Hour)) {
		t.Fatal("concurrent notifications changed the paid period more than once", err)
	}
}
