package controlplane

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"github.com/buzzmean/neexitlag/core/optimizer"
	"github.com/buzzmean/neexitlag/core/profiles"
	"github.com/buzzmean/neexitlag/core/security"
	"github.com/jackc/pgx/v5/pgxpool"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

func TestPostgresAPIIdentityTicketConfigAndRevoke(t *testing.T) {
	url := os.Getenv("NEEXITLAG_TEST_DATABASE_URL")
	if url == "" {
		t.Skip("set NEEXITLAG_TEST_DATABASE_URL to a test PostgreSQL database")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	root, e := pgxpool.New(ctx, url)
	if e != nil {
		t.Fatal(e)
	}
	defer root.Close()
	suffix, _ := security.NewID()
	schema := "test_" + suffix
	if _, e = root.Exec(ctx, "CREATE SCHEMA "+schema); e != nil {
		t.Fatal(e)
	}
	defer root.Exec(context.Background(), "DROP SCHEMA "+schema+" CASCADE")
	cfg, e := pgxpool.ParseConfig(url)
	if e != nil {
		t.Fatal(e)
	}
	cfg.ConnConfig.RuntimeParams["search_path"] = schema
	pool, e := pgxpool.NewWithConfig(ctx, cfg)
	if e != nil {
		t.Fatal(e)
	}
	defer pool.Close()
	store := &Store{pool}
	if e = store.Migrate(ctx); e != nil {
		t.Fatal(e)
	}
	if e = store.Migrate(ctx); e != nil {
		t.Fatal("idempotent migration", e)
	}
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	caTemplate := &x509.Certificate{SerialNumber: big.NewInt(1), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(48 * time.Hour)}
	der, e := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, pub, key)
	if e != nil {
		t.Fatal(e)
	}
	ca, e := x509.ParseCertificate(der)
	if e != nil {
		t.Fatal(e)
	}
	token, _ := security.NewID()
	api, e := New(store, Settings{AdminToken: token, KeyID: "test", SigningKey: key, CA: ca, CAKey: key})
	if e != nil {
		t.Fatal(e)
	}
	if e = api.Initialize(ctx); e != nil {
		t.Fatal(e)
	}
	httpServer := httptest.NewServer(api.Handler())
	defer httpServer.Close()
	request := func(method, path string, value any, admin bool) (int, []byte) {
		t.Helper()
		var b []byte
		if value != nil {
			b, _ = json.Marshal(value)
		}
		r, _ := http.NewRequestWithContext(ctx, method, httpServer.URL+path, bytes.NewReader(b))
		if admin {
			r.Header.Set("Authorization", "Bearer "+token)
		}
		response, e := http.DefaultClient.Do(r)
		if e != nil {
			t.Fatal(e)
		}
		defer response.Body.Close()
		raw, _ := io.ReadAll(response.Body)
		return response.StatusCode, raw
	}
	if status, _ := request("GET", "/api/v1/devices", nil, false); status != 401 {
		t.Fatal("anonymous admin", status)
	}
	node := optimizer.RelayCandidate{ID: "FRA-01", Address: "127.0.0.1:4433", Region: "EU", City: "Frankfurt"}
	status, relayRaw := request("POST", "/api/v1/relays", node, true)
	if status != 201 {
		t.Fatalf("register relay %d %s", status, relayRaw)
	}
	var registration struct {
		HeartbeatToken string `json:"heartbeat_token"`
	}
	if e := json.Unmarshal(relayRaw, &registration); e != nil || len(registration.HeartbeatToken) != 32 {
		t.Fatal("scoped heartbeat token", e)
	}
	payload := []byte(`{"id":"FRA-01","healthy":true,"load":0.25}`)
	for _, credential := range []string{token, registration.HeartbeatToken} {
		r, _ := http.NewRequestWithContext(ctx, "POST", httpServer.URL+"/api/v1/relays/heartbeat", bytes.NewReader(payload))
		r.Header.Set("Authorization", "Bearer "+credential)
		res, err := http.DefaultClient.Do(r)
		if err != nil {
			t.Fatal(err)
		}
		res.Body.Close()
		want := 401
		if credential == registration.HeartbeatToken {
			want = 200
		}
		if res.StatusCode != want {
			t.Fatal("heartbeat authorization", res.StatusCode, want)
		}
	}
	devicePub, deviceKey, _ := ed25519.GenerateKey(rand.Reader)
	device := Device{ID: "test-device", Name: "Test device", PublicKey: base64.RawURLEncoding.EncodeToString(devicePub)}
	if status, b := request("POST", "/api/v1/devices", device, true); status != 201 {
		t.Fatalf("register device %d %s", status, b)
	}
	proof, _ := security.NewProof(device.ID, node.ID, deviceKey, time.Now())
	status, raw := request("POST", "/api/v1/auth", proof, false)
	if status != 200 {
		t.Fatalf("auth %d %s", status, raw)
	}
	_, metricsRaw := request("GET", "/metrics", nil, false)
	if !strings.Contains(string(metricsRaw), "neexitlag_connected_devices 1") || !strings.Contains(string(metricsRaw), "neexitlag_healthy_relays 1") {
		t.Fatal("real lease/heartbeat metrics", string(metricsRaw))
	}
	v := security.NewTicketVerifier(map[string]ed25519.PublicKey{"test": pub}, node.ID)
	if _, e = v.Accept(raw, devicePub, time.Now()); e != nil {
		t.Fatal(e)
	}
	if status, _ = request("POST", "/api/v1/auth", proof, false); status != 401 {
		t.Fatal("proof replay accepted", status)
	}
	custom := profiles.Profile{ID: "custom", Name: "Custom", Executables: []string{`C:\Games\Game.exe`}, Mode: profiles.Manual, RelayID: node.ID, Custom: true}
	if status, b := request("POST", "/api/v1/apps", custom, true); status != 201 {
		t.Fatalf("app %d %s", status, b)
	}
	status, raw = request("GET", "/api/v1/config", nil, false)
	if status != 200 {
		t.Fatal(status)
	}
	signed, e := security.ValidateConfig(map[string]ed25519.PublicKey{"test": pub}, raw, time.Now())
	if e != nil || len(signed.Relays) != 1 || len(signed.ApplicationProfiles) != len(profiles.Defaults())+1 {
		t.Fatal("signed config", e)
	}
	// Migrations publish all current builtin profiles plus the custom profile;
	// verify exact content as well as count so additions are not silently omitted.
	expected := map[string]string{}
	for _, profile := range append(profiles.Defaults(), custom) {
		b, err := json.Marshal(profile)
		if err != nil {
			t.Fatal(err)
		}
		expected[profile.ID] = string(b)
	}
	for _, profile := range signed.ApplicationProfiles {
		b, err := json.Marshal(profile)
		if err != nil {
			t.Fatal(err)
		}
		if expected[profile.ID] != string(b) {
			t.Fatalf("published application profile mismatch: %s", profile.ID)
		}
		delete(expected, profile.ID)
	}
	if len(expected) != 0 {
		t.Fatal("missing published profiles")
	}
	for _, path := range []string{"/api/v1/devices", "/api/v1/relays", "/api/v1/apps", "/api/v1/version", "/metrics", "/healthz"} {
		if status, _ := request("GET", path, nil, true); status != 200 {
			t.Fatal(path, status)
		}
	}
	if status, _ := request("POST", "/api/v1/telemetry", Telemetry{DeviceID: device.ID, RTTMS: 12, Loss: .01, Version: "test"}, true); status != 202 {
		t.Fatal("telemetry", status)
	}
	if status, _ := request("DELETE", "/api/v1/devices?id="+device.ID, nil, true); status != 200 {
		t.Fatal("revoke", status)
	}
	proof, _ = security.NewProof(device.ID, node.ID, deviceKey, time.Now())
	if status, _ := request("POST", "/api/v1/auth", proof, false); status != 401 {
		t.Fatal("revoked auth", status)
	}
	_, raw = request("GET", "/api/v1/config", nil, false)
	signed, e = security.ValidateConfig(map[string]ed25519.PublicKey{"test": pub}, raw, time.Now())
	if e != nil || len(signed.RevokedDevices) != 1 {
		t.Fatal("revocation config", e)
	}
	persisted, e := store.Device(ctx, device.ID)
	if e != nil || !persisted.Revoked {
		t.Fatal("persistence", e)
	}
	var audits int
	if e = pool.QueryRow(ctx, "SELECT count(*) FROM audit_log").Scan(&audits); e != nil || audits < 4 {
		t.Fatal("audit", e, audits)
	}
}
