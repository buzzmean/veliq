package clientservice

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/buzzmean/neexitlag/core/enrollment"
	"github.com/buzzmean/neexitlag/core/freshpc"
	"github.com/buzzmean/neexitlag/core/security"
	wp "github.com/buzzmean/neexitlag/platform/windows"
	cp "github.com/buzzmean/neexitlag/services/control-plane"
	"github.com/jackc/pgx/v5/pgxpool"
)

type accountFixtureMail struct {
	mu   sync.Mutex
	code string
}

func (m *accountFixtureMail) Send(_ context.Context, _, _, body string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.code = regexp.MustCompile(`\b[0-9]{6}\b`).FindString(body)
	return nil
}

type accountFixture struct {
	api    *cp.API
	store  *cp.Store
	server *httptest.Server
	mail   *accountFixtureMail
	ca     []byte
	cert   *x509.Certificate
	client *http.Client
}

func newAccountFixture(t *testing.T) *accountFixture {
	t.Helper()
	dsn := os.Getenv("NEEXITLAG_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("isolated PostgreSQL required")
	}
	ctx := context.Background()
	root, e := pgxpool.New(ctx, dsn)
	if e != nil {
		t.Fatal(e)
	}
	schemaID, _ := security.NewID()
	schema := "test_account_client_" + schemaID
	if _, e = root.Exec(ctx, "CREATE SCHEMA "+schema); e != nil {
		root.Close()
		t.Fatal(e)
	}
	cfg, e := pgxpool.ParseConfig(dsn)
	if e != nil {
		t.Fatal(e)
	}
	cfg.ConnConfig.RuntimeParams["search_path"] = schema
	pool, e := pgxpool.NewWithConfig(ctx, cfg)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { pool.Close(); root.Exec(context.Background(), "DROP SCHEMA "+schema+" CASCADE"); root.Close() })
	f := &accountFixture{store: &cp.Store{DB: pool}, mail: &accountFixtureMail{}}
	if e = f.store.Migrate(ctx); e != nil {
		t.Fatal(e)
	}
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	caKey, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	now := time.Now()
	caTemplate := &x509.Certificate{Subject: pkix.Name{CommonName: "VELIQ account fixture root"}, SerialNumber: big.NewInt(1), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(365 * 24 * time.Hour)}
	der, e := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, caKey.Public(), caKey)
	if e != nil {
		t.Fatal(e)
	}
	f.cert, _ = x509.ParseCertificate(der)
	f.ca = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	serverKey, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	leafTpl := &x509.Certificate{SerialNumber: big.NewInt(2), NotBefore: now.Add(-time.Minute), NotAfter: now.Add(24 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}}
	leaf, e := x509.CreateCertificate(rand.Reader, leafTpl, f.cert, serverKey.Public(), caKey)
	if e != nil {
		t.Fatal(e)
	}
	f.api, e = cp.New(f.store, cp.Settings{AdminToken: strings.Repeat("fixture-admin-", 3), EnrollmentProbeToken: strings.Repeat("fixture-probe-", 3), KeyID: "test", SigningKey: key, CA: f.cert, CAKey: caKey, Mailer: f.mail, Plans: []cp.Plan{{ID: "player", Kind: "player", Title: "Пользователь", PricePerSeatRub: 300, PeriodDays: 30, MaxSeats: 1}, {ID: "club", Kind: "club", Title: "Клуб", PricePerSeatRub: 200, PeriodDays: 30, MaxSeats: 10}}})
	if e != nil {
		t.Fatal(e)
	}
	if e = f.api.Initialize(ctx); e != nil {
		t.Fatal(e)
	}
	f.server = httptest.NewUnstartedServer(f.api.Handler())
	f.server.TLS = &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{{Certificate: [][]byte{leaf}, PrivateKey: serverKey}}}
	f.server.StartTLS()
	t.Cleanup(f.server.Close)
	f.api.Settings.AccountOrigin = f.server.URL
	roots := x509.NewCertPool()
	roots.AddCert(f.cert)
	jar, _ := cookiejar.New(nil)
	f.client = &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS13}, Proxy: nil}, Jar: jar, Timeout: 5 * time.Second}
	t.Cleanup(f.client.CloseIdleConnections)
	return f
}
func (f *accountFixture) call(t *testing.T, path string, payload any) map[string]any {
	t.Helper()
	b, _ := json.Marshal(payload)
	r, e := http.NewRequest("POST", f.server.URL+path, bytes.NewReader(b))
	if e != nil {
		t.Fatal(e)
	}
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Origin", f.server.URL)
	response, e := f.client.Do(r)
	if e != nil {
		t.Fatal("fixture HTTPS request", e)
	}
	defer response.Body.Close()
	var out map[string]any
	if json.NewDecoder(io.LimitReader(response.Body, 65536)).Decode(&out) != nil {
		t.Fatal("malformed fixture response")
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		t.Fatal("fixture API rejected", path, response.StatusCode)
	}
	return out
}
func (f *accountFixture) subscribe(t *testing.T, kind string, seats int) string {
	t.Helper()
	f.call(t, "/api/v1/account/login/start", map[string]string{"email": kind + "@example.test"})
	f.mail.mu.Lock()
	code := f.mail.code
	f.mail.mu.Unlock()
	f.call(t, "/api/v1/account/login/verify", map[string]string{"email": kind + "@example.test", "code": code})
	f.call(t, "/api/v1/account/profile", map[string]string{"kind": kind, "name": "Test " + kind})
	out := f.call(t, "/api/v1/account/subscriptions", map[string]any{"plan_id": kind, "seats": seats})
	id := out["id"].(string)
	if _, e := f.store.DB.Exec(context.Background(), "UPDATE subscriptions SET paid_until=now()+interval '30 days' WHERE id=$1", id); e != nil {
		t.Fatal(e)
	}
	return id
}
func (f *accountFixture) manifest(t *testing.T) Manifest {
	t.Helper()
	dir := t.TempDir()
	caPath := filepath.Join(dir, "ca.pem")
	if e := os.WriteFile(caPath, f.ca, 0600); e != nil {
		t.Fatal(e)
	}
	owner := "fixture-owner"
	if id, e := wp.NewDiscovery().Lookup(uint32(os.Getpid())); e == nil {
		if sid, e := wp.ProcessUserSID(id); e == nil {
			owner = sid
		}
	}
	return Manifest{OwnerSID: owner, ControlPlaneURL: f.server.URL, CAFile: caPath, ControlPlaneCAFile: caPath, ActivationCAFingerprint: freshpc.Fingerprint(f.cert), StateDirectory: filepath.Join(dir, "state"), DeviceIdentityFile: filepath.Join(dir, "identity.json"), DeviceCertificate: filepath.Join(dir, "device.pem"), TrustFile: filepath.Join(dir, "trust.json"), ProbeTokenFile: filepath.Join(dir, "probe.token")}
}
func accountFixtureHardware(context.Context) (enrollment.Hardware, error) {
	return enrollment.Hardware{UUID: "00112233-4455-6677-8899-aabbccddeeff", BoardSerial: "Fixture-board", MAC: "02:11:22:33:44:55"}, nil
}
func waitAccountFixture(t *testing.T, c *Controller, predicate func(accountConnectionStatus) bool) accountConnectionStatus {
	t.Helper()
	end := time.Now().Add(15 * time.Second)
	for time.Now().Before(end) {
		s := c.accountConnectionStatus()
		if predicate(s) {
			return s
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("account fixture condition not reached; confidential status suppressed")
	return accountConnectionStatus{}
}
func TestAccountHTTPSBrowserApprovalPersistsOwnDeviceWithoutCode(t *testing.T) {
	f := newAccountFixture(t)
	sub := f.subscribe(t, "player", 1)
	m := f.manifest(t)
	c := New(context.Background())
	t.Cleanup(c.Close)
	c.activation.hardware = accountFixtureHardware
	c.ConfigureActivation(m)
	if _, e := c.HandleOwnerIPC(context.Background(), "account.link.start", nil); e != nil {
		t.Fatal(e)
	}
	s := waitAccountFixture(t, c, func(s accountConnectionStatus) bool { return s.State == "WAITING_FOR_BROWSER" })
	r, e := readActivation(m)
	if e != nil || r.AccountLink == nil {
		t.Fatal("pending account request absent", e)
	}
	public, _ := json.Marshal(s)
	if bytes.Contains(public, []byte(r.AccountLink.Secret)) {
		t.Fatal("owner IPC leaked device polling secret")
	}
	f.call(t, "/api/v1/account/device-links/"+r.RequestID+"/approve", map[string]string{"subscription_id": sub})
	waitAccountFixture(t, c, func(s accountConnectionStatus) bool {
		record, e := readActivation(m)
		return e == nil && !record.Pending && s.State == "LINKED" && validActivationIdentity(m)
	})
	bound, e := readActivation(m)
	if e != nil || bound.Code != "" || bound.Account.Kind != "player" || bound.Account.Subscription != sub || bound.AccountLink != nil {
		t.Fatal("account did not replace manual activation")
	}
	if _, e = c.HandleOwnerIPC(context.Background(), "account.status", nil); e != nil {
		t.Fatal("account IPC dispatcher", e)
	}
}
func TestAccountClubTemplateApprovesWithoutKeyAndReenrollsAfterFreeze(t *testing.T) {
	f := newAccountFixture(t)
	sub := f.subscribe(t, "club", 2)
	m := f.manifest(t)
	b, _ := json.Marshal(m)
	if e := protectedActivationWrite(filepath.Join(filepath.Dir(m.DeviceIdentityFile), "service.json"), b); e != nil {
		t.Fatal(e)
	}
	b, _ = json.Marshal(accountImagePreparation{Version: 1, Owner: m.OwnerSID, Browsers: []string{}})
	if e := protectedActivationWrite(accountImagePreparationPath(m), b); e != nil {
		t.Fatal(e)
	}
	c := New(context.Background())
	t.Cleanup(c.Close)
	c.activation.hardware = accountFixtureHardware
	c.ConfigureActivation(m)
	if _, e := c.HandleOwnerIPC(context.Background(), "account.link.start", nil); e != nil {
		t.Fatal(e)
	}
	waitAccountFixture(t, c, func(s accountConnectionStatus) bool { return s.State == "WAITING_FOR_BROWSER" })
	r, e := readActivation(m)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = os.Stat(m.DeviceIdentityFile); !os.IsNotExist(e) {
		t.Fatal("image generated a device key before approval")
	}
	f.call(t, "/api/v1/account/device-links/"+r.RequestID+"/approve", map[string]string{"subscription_id": sub})
	waitAccountFixture(t, c, func(s accountConnectionStatus) bool { return s.State == "IMAGE_READY" })
	ready, e := readActivation(m)
	if e != nil || !ready.ImageTemplate || ready.BootstrapID == "" || ready.Code != "" {
		t.Fatal("code-free template not persisted", e)
	}
	if _, e = os.Stat(m.DeviceIdentityFile); !os.IsNotExist(e) {
		t.Fatal("template contains device identity")
	}
	publicStatus := c.accountConnectionStatus()
	publicJSON, _ := json.Marshal(publicStatus)
	if publicStatus.Email != "" || bytes.Contains(publicJSON, []byte(ready.BootstrapSecret)) {
		t.Fatal("club public status leaked owner credentials")
	}
	c.Close()
	previous := ""
	for i := 0; i < 3; i++ {
		boot := New(context.Background())
		boot.activation.hardware = accountFixtureHardware
		next := f.manifest(t)
		record, _, e := boot.activationAttempt(context.Background(), next, ready)
		if e != nil {
			boot.Close()
			t.Fatal("controlled freeze boot failed", i, e)
		}
		identity, _, e := security.LoadOrCreateIdentity(next.DeviceIdentityFile)
		boot.Close()
		if e != nil || identity.ID == previous || record.ImageTemplate || record.Account.Kind != "club" {
			t.Fatal("freeze cloned the key or lost club association", e)
		}
		previous = identity.ID
	}
	var seats int
	if e = f.store.DB.QueryRow(context.Background(), "SELECT count(*) FROM activation_slots WHERE NOT disabled").Scan(&seats); e != nil || seats != 1 {
		t.Fatal("freeze changed seat count", e, seats)
	}
}
