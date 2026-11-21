package controlplane

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"github.com/buzzmean/neexitlag/core/enrollment"
	"github.com/buzzmean/neexitlag/core/security"
	"math/big"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestPublicCodeCSRHTTPSNoAdminAndSafeFailures(t *testing.T) {
	s := codeStore(t)
	ctx := context.Background()
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	now := time.Now()
	template := &x509.Certificate{SerialNumber: big.NewInt(1), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(60 * 24 * time.Hour)}
	der, e := x509.CreateCertificate(rand.Reader, template, template, pub, key)
	if e != nil {
		t.Fatal(e)
	}
	ca, _ := x509.ParseCertificate(der)
	api, e := New(s, Settings{EnrollmentProbeToken: strings.Repeat("p", 32), AdminToken: strings.Repeat("x", 32), KeyID: "test", SigningKey: key, CA: ca, CAKey: key})
	if e != nil {
		t.Fatal(e)
	}
	server := httptest.NewTLSServer(api.Handler())
	defer server.Close()
	client := enrollment.Client{URL: server.URL, HTTP: server.Client()}
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	code, raw, e := s.CreateCode(ctx, ActivationCode{Kind: "personal", Limit: 2, Name: "fixture", Expires: now.Add(time.Hour)})
	if e != nil {
		t.Fatal(e)
	}
	_, deviceKey, _ := ed25519.GenerateKey(rand.Reader)
	id, _ := security.NewID()
	q, e := enrollment.NewRequest(id, strings.Repeat("a", 64), deviceKey)
	if e != nil {
		t.Fatal(e)
	}
	policy, e := client.Policy(ctx)
	if e != nil || len(policy.HardwareSalt) != 64 || policy.CANotAfter == "" {
		t.Fatal("policy unavailable", e)
	}
	response, e := client.Enroll(ctx, raw, q, roots)
	if e != nil || response.DeviceID != id {
		t.Fatal("public CSR enrollment failed", e)
	}
	if _, e = client.Enroll(ctx, raw, q, roots); e != nil {
		t.Fatal("idempotent CSR retry", e)
	}
	if _, e = client.Enroll(ctx, strings.Repeat("s", 32), q, roots); e == nil || e.Error() != "ACTIVATION_INVALID" {
		t.Fatal("malformed code accepted")
	}
	if _, e = s.DB.Exec(ctx, "UPDATE activation_codes SET expires_at=now()-interval '1 second' WHERE id=$1", code.ID); e != nil {
		t.Fatal(e)
	}
	if _, e = client.Enroll(ctx, raw, q, roots); e == nil || e.Error() != "ACTIVATION_EXPIRED" {
		t.Fatal("expired enrollment accepted")
	}
	// Admin operations do not become public through the new endpoint.
	res, e := server.Client().Get(server.URL + "/api/v1/codes")
	if e != nil {
		t.Fatal(e)
	}
	res.Body.Close()
	if res.StatusCode != 401 {
		t.Fatal("public admin list")
	}
	// Invalid signature/JSON is rejected without reflecting any credential.
	request, _ := json.Marshal(enrollment.Request{Code: raw})
	res, e = server.Client().Post(server.URL+"/api/v1/enroll", "application/json", bytes.NewReader(request))
	if e != nil {
		t.Fatal(e)
	}
	defer res.Body.Close()
	var failure struct {
		Error string `json:"error"`
	}
	if json.NewDecoder(res.Body).Decode(&failure) != nil || strings.Contains(failure.Error, raw) {
		t.Fatal("unsafe error")
	}
}
