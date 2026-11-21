package controlplane

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/buzzmean/neexitlag/core/enrollment"
	"github.com/buzzmean/neexitlag/core/security"
)

func TestTemporaryCodeAdminOnlyHTTPSAndBothRateLimits(t *testing.T) {
	s := codeStore(t)
	ctx := context.Background()
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	now := time.Now()
	template := &x509.Certificate{SerialNumber: big.NewInt(1), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(60 * 24 * time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, template, template, pub, key)
	if err != nil {
		t.Fatal(err)
	}
	ca, _ := x509.ParseCertificate(der)
	api, err := New(s, Settings{EnrollmentProbeToken: strings.Repeat("p", 32), AdminToken: strings.Repeat("x", 32), KeyID: "fixture", SigningKey: key, CA: ca, CAKey: key})
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewTLSServer(api.Handler())
	defer server.Close()
	admin := func(path, body string, authorized bool) int {
		t.Helper()
		req, _ := http.NewRequest(http.MethodPost, server.URL+path, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		if authorized {
			req.Header.Set("Authorization", "Bearer "+api.Settings.AdminToken)
		}
		res, err := server.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer res.Body.Close()
		return res.StatusCode
	}
	for _, path := range []string{"/api/v1/codes/test", "/api/v1/codes/revoke-tests"} {
		if admin(path, `{"value":"test","name":"fixture"}`, false) != 401 {
			t.Fatal("unauthorized test mutation")
		}
	}
	if admin("/api/v1/codes/test", `{"value":"test","name":"fixture","limit":40}`, true) != 400 {
		t.Fatal("test limit override")
	}
	if admin("/api/v1/codes/test", `{"value":"test","name":"fixture"}`, true) != 201 {
		t.Fatal("admin test creation")
	}
	if admin("/api/v1/codes/test", `{"value":"test","name":"duplicate"}`, true) != 409 {
		t.Fatal("duplicate not rejected")
	}
	client := enrollment.Client{URL: server.URL, HTTP: server.Client()}
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	_, deviceKey, _ := ed25519.GenerateKey(rand.Reader)
	id, _ := security.NewID()
	q, err := enrollment.NewRequest(id, strings.Repeat("a", 64), deviceKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = client.Enroll(ctx, "test", q, roots); err != nil {
		t.Fatal("HTTPS test activation", err)
	}
	// The exact short-code request hits the same IP and code buckets before CSR.
	hash, _ := enrollment.CodeHash("test")
	codeKey := hex.EncodeToString(hash)
	api.enrollCode.mu.Lock()
	_, seen := api.enrollCode.perIP[codeKey]
	_, rawSeen := api.enrollCode.perIP["test"]
	api.enrollCode.mu.Unlock()
	if !seen || rawSeen {
		t.Fatal("code throttle not hash scoped")
	}
	for _, byCode := range []bool{false, true} {
		api.enrollIP = newEnrollmentLimiter(time.Now())
		api.enrollCode = newEnrollmentLimiter(time.Now())
		limiter, key := api.enrollIP, "192.0.2.4"
		if byCode {
			limiter, key = api.enrollCode, codeKey
		}
		limiter.ipRate = 0
		limiter.perIP[key] = &bucket{tokens: 0, last: time.Now()}
		payload, _ := json.Marshal(enrollment.Request{Code: "test", Device: q})
		req := httptest.NewRequest(http.MethodPost, "/api/v1/enroll", bytes.NewReader(payload))
		req.RemoteAddr = "192.0.2.4:1234"
		w := httptest.NewRecorder()
		api.enroll(w, req)
		if w.Code != 429 || !strings.Contains(w.Body.String(), "ACTIVATION_RATE_LIMIT") {
			t.Fatal("short code bypasses throttle", byCode, w.Code)
		}
	}
	api.enrollIP = newEnrollmentLimiter(time.Now())
	api.enrollCode = newEnrollmentLimiter(time.Now())
	if admin("/api/v1/codes/revoke-tests", `{}`, true) != 200 {
		t.Fatal("admin bulk revoke")
	}
	if _, err = client.Enroll(ctx, "test", q, roots); err == nil || err.Error() != "ACTIVATION_REVOKED" {
		t.Fatal("test reenrolled after revoke", err)
	}
}
