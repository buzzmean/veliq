package clientservice

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"github.com/buzzmean/veliq/core/enrollment"
	"github.com/buzzmean/veliq/core/freshpc"
	"github.com/buzzmean/veliq/core/security"
	cp "github.com/buzzmean/veliq/services/control-plane"
	"github.com/jackc/pgx/v5/pgxpool"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestActivationHTTPSCSRPrivateKeyFreezeAndLostResponse(t *testing.T) {
	dsn := os.Getenv("VELIQ_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("isolated PostgreSQL required")
	}
	ctx := context.Background()
	root, e := pgxpool.New(ctx, dsn)
	if e != nil {
		t.Fatal(e)
	}
	defer root.Close()
	schemaID, _ := security.NewID()
	schema := "test_activation_" + schemaID
	if _, e = root.Exec(ctx, "CREATE SCHEMA "+schema); e != nil {
		t.Fatal(e)
	}
	defer root.Exec(ctx, "DROP SCHEMA "+schema+" CASCADE")
	cfg, e := pgxpool.ParseConfig(dsn)
	if e != nil {
		t.Fatal(e)
	}
	cfg.ConnConfig.RuntimeParams["search_path"] = schema
	pool, e := pgxpool.NewWithConfig(ctx, cfg)
	if e != nil {
		t.Fatal(e)
	}
	defer pool.Close()
	store := &cp.Store{DB: pool}
	if e = store.Migrate(ctx); e != nil {
		t.Fatal(e)
	}
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	now := time.Now()
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: now.Add(-time.Hour), NotAfter: now.Add(365 * 24 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, e := x509.CreateCertificate(rand.Reader, tpl, tpl, pub, key)
	if e != nil {
		t.Fatal(e)
	}
	ca, _ := x509.ParseCertificate(der)
	serverPub, serverKey, _ := ed25519.GenerateKey(rand.Reader)
	leafTpl := &x509.Certificate{SerialNumber: big.NewInt(2), NotBefore: now.Add(-time.Minute), NotAfter: now.Add(30 * 24 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}}
	serverDER, e := x509.CreateCertificate(rand.Reader, leafTpl, ca, serverPub, key)
	if e != nil {
		t.Fatal(e)
	}
	serverLeaf, _ := x509.ParseCertificate(serverDER)
	pair := tls.Certificate{Certificate: [][]byte{serverDER}, PrivateKey: serverKey}
	api, e := cp.New(store, cp.Settings{AdminToken: strings.Repeat("x", 32), KeyID: "test", SigningKey: key, CA: ca, CAKey: key, ServerCertificate: serverLeaf, EnrollmentProbeToken: strings.Repeat("p", 32)})
	if e != nil {
		t.Fatal(e)
	}
	var committedBeforeDrop atomic.Bool
	var drop atomic.Bool
	drop.Store(true)
	handler := api.Handler()
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/enroll" && drop.CompareAndSwap(true, false) {
			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, r)
			if recorder.Code != 201 {
				http.Error(w, "fixture", 500)
				return
			}
			if recorder.Code == 201 {
				committedBeforeDrop.Store(true)
			}
			panic(http.ErrAbortHandler)
		}
		handler.ServeHTTP(w, r)
	}))
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{pair}}
	server.StartTLS()
	defer server.Close()
	code, raw, e := store.CreateCode(ctx, cp.ActivationCode{Kind: "club", Limit: 1, Name: "fixture", Expires: now.Add(time.Hour)})
	if e != nil {
		t.Fatal(e)
	}
	c := New(ctx)
	defer c.Close()
	c.activation.hardware = func(context.Context) (enrollment.Hardware, error) {
		return enrollment.Hardware{UUID: "00112233-4455-6677-8899-aabbccddeeff", BoardSerial: "Default string", MAC: "02:11:22:33:44:55"}, nil
	}
	var previousID string
	var lastManifest Manifest
	var lastRecord activationRecord
	// A sealed image has the SAME staged request ID on every freeze boot.
	requestID, _ := security.NewID()
	for i := 0; i < 5; i++ {
		dir := t.TempDir()
		caPath := filepath.Join(dir, "ca.pem")
		if e = os.WriteFile(caPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600); e != nil {
			t.Fatal(e)
		}
		m := Manifest{ControlPlaneURL: server.URL, CAFile: caPath, ActivationCAFingerprint: freshpc.Fingerprint(ca), StateDirectory: filepath.Join(dir, "state"), DeviceIdentityFile: filepath.Join(dir, "identity.json"), DeviceCertificate: filepath.Join(dir, "device.pem"), TrustFile: filepath.Join(dir, "trust.json"), ProbeTokenFile: filepath.Join(dir, "probe.token")}
		record := activationRecord{Code: raw, RequestID: requestID, Pending: true}
		start := time.Now()
		if i == 0 {
			if _, _, e = c.activationAttempt(ctx, m, record); e == nil {
				t.Fatal("ambiguous HTTP response was reported as success")
			}
			if !committedBeforeDrop.Load() {
				t.Fatal("lost response fixture did not commit")
			}
		}
		next, policy, e := c.activationAttempt(ctx, m, record)
		if e != nil || next.Pending || policy.ServerNotAfter == "" || !validActivationIdentity(m) {
			t.Fatal("activation validation/persistence failed", e)
		}
		if time.Since(start) > 4*time.Second {
			t.Fatal("local activation exceeded fixture budget")
		}
		id, _, e := security.LoadOrCreateIdentity(m.DeviceIdentityFile)
		if e != nil {
			t.Fatal(e)
		}
		if id.ID == previousID {
			t.Fatal("freeze reused private identity")
		}
		if previousID != "" {
			old, e := store.Device(ctx, previousID)
			if e != nil || !old.Revoked {
				t.Fatal("freeze predecessor active")
			}
		}
		previousID = id.ID
		lastManifest, lastRecord = m, next
	}
	machines, e := store.CodeMachines(ctx, code.ID)
	if e != nil || len(machines) != 1 || machines[0].Device != previousID {
		t.Fatal("freeze slot count changed", e)
	}
	// Exercise the actual idle manager + Change path, not just enrollmentAttempt.
	// Replacing a key stops old workers and must start workers for the new key.
	lastManifest.ControlPlaneCAFile = lastManifest.CAFile
	lastManifest.ProbeTarget = "127.0.0.1:40000"
	b, _ := json.Marshal(lastRecord)
	if e = protectedActivationWrite(activationFile(lastManifest), b); e != nil {
		t.Fatal(e)
	}
	if !c.ConfigureActivation(lastManifest) {
		t.Fatal("coded identity not managed")
	}
	wait := func(check func() bool) {
		t.Helper()
		until := time.Now().Add(6 * time.Second)
		for !check() {
			if time.Now().After(until) {
				t.Fatal("activation worker transition not observed")
			}
			time.Sleep(10 * time.Millisecond)
		}
	}
	var oldDone chan struct{}
	wait(func() bool {
		c.remoteMu.Lock()
		defer c.remoteMu.Unlock()
		oldDone = c.remoteDone
		return oldDone != nil
	})
	badCode, _ := enrollment.NewCode()
	badRequest, _ := json.Marshal(map[string]any{"code": badCode})
	if _, e = c.Handle(ctx, "activation.set", badRequest); e != nil {
		t.Fatal(e)
	}
	wait(func() bool { return c.activationStatus().Error == "ACTIVATION_INVALID" })
	c.remoteMu.Lock()
	same := c.remoteDone == oldDone
	select {
	case <-oldDone:
		same = false
	default:
	}
	c.remoteMu.Unlock()
	if !same {
		t.Fatal("rejected code interrupted working remote")
	}
	_, replacement, e := store.CreateCode(ctx, cp.ActivationCode{Kind: "personal", Limit: 2, Name: "replacement fixture", Expires: now.Add(time.Hour)})
	if e != nil {
		t.Fatal(e)
	}
	request, _ := json.Marshal(map[string]any{"code": replacement})
	if _, e = c.Handle(ctx, "activation.set", request); e != nil {
		t.Fatal(e)
	}
	wait(func() bool {
		status := c.activationStatus()
		r, e := readActivationRecord(activationFile(lastManifest))
		if e != nil || r.Code != replacement || status.State != "ACTIVATED" {
			return false
		}
		c.remoteMu.Lock()
		defer c.remoteMu.Unlock()
		if c.remoteDone == nil || c.remoteDone == oldDone {
			return false
		}
		select {
		case <-oldDone:
		default:
			return false
		}
		select {
		case <-c.remoteDone:
			return false
		default:
			return true
		}
	})

}
