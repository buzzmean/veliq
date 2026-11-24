package clientservice

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"github.com/buzzmean/veliq/core/controlclient"
	"github.com/buzzmean/veliq/core/optimizer"
	"github.com/buzzmean/veliq/core/routing"
	"github.com/buzzmean/veliq/core/security"
	"github.com/buzzmean/veliq/core/transport"
	"github.com/buzzmean/veliq/internal/e2eprobe"
	controlplane "github.com/buzzmean/veliq/services/control-plane"
	"github.com/buzzmean/veliq/services/relay"
	"github.com/jackc/pgx/v5/pgxpool"
	"math/big"
	"net"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// Portable transport integration only. There is deliberately no fake Windows capture backend.
func TestPrivateTLSControlPlaneAndAuthenticatedRemoteProbe(t *testing.T) {
	database := os.Getenv("NEEXITLAG_TEST_DATABASE_URL")
	if database == "" {
		t.Skip("PostgreSQL test URL required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	root, e := pgxpool.New(ctx, database)
	if e != nil {
		t.Fatal(e)
	}
	defer root.Close()
	id, _ := security.NewID()
	schema := "test_remote_" + id
	if _, e = root.Exec(ctx, "CREATE SCHEMA "+schema); e != nil {
		t.Fatal(e)
	}
	defer root.Exec(context.Background(), "DROP SCHEMA "+schema+" CASCADE")
	dbCfg, e := pgxpool.ParseConfig(database)
	if e != nil {
		t.Fatal(e)
	}
	dbCfg.MaxConns = 8
	dbCfg.ConnConfig.RuntimeParams["search_path"] = schema
	pool, e := pgxpool.NewWithConfig(ctx, dbCfg)
	if e != nil {
		t.Fatal(e)
	}
	defer pool.Close()
	store := &controlplane.Store{DB: pool}
	if e = store.Migrate(ctx); e != nil {
		t.Fatal(e)
	}
	dir := t.TempDir()
	put := func(name string, b []byte) string {
		p := filepath.Join(dir, name)
		if e := os.WriteFile(p, b, 0600); e != nil {
			t.Fatal(e)
		}
		return p
	}
	now := time.Now()
	caPub, caKey, _ := ed25519.GenerateKey(rand.Reader)
	caTemplate := &x509.Certificate{SerialNumber: big.NewInt(1), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(48 * time.Hour)}
	caDER, e := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, caPub, caKey)
	if e != nil {
		t.Fatal(e)
	}
	ca, _ := x509.ParseCertificate(caDER)
	caPath := put("ca.pem", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}))
	serverPub, serverKey, _ := ed25519.GenerateKey(rand.Reader)
	serverTemplate := &x509.Certificate{SerialNumber: big.NewInt(2), NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1)}, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	serverDER, e := x509.CreateCertificate(rand.Reader, serverTemplate, ca, serverPub, caKey)
	if e != nil {
		t.Fatal(e)
	}
	serverPath := put("server.pem", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: serverDER}))
	serverKeyDER, _ := x509.MarshalPKCS8PrivateKey(serverKey)
	keyPath := put("server.key", pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: serverKeyDER}))
	issuerPub, issuer, _ := ed25519.GenerateKey(rand.Reader)
	trust, _ := json.Marshal(map[string]string{"test": base64.RawURLEncoding.EncodeToString(issuerPub)})
	trustPath := put("trust.json", trust)
	tlsServer, e := transport.TLS(serverPath, keyPath, caPath, true)
	if e != nil {
		t.Fatal(e)
	}
	verifier := security.NewTicketVerifier(map[string]ed25519.PublicKey{"test": issuerPub}, "VPS-01")
	node, e := relay.Listen("127.0.0.1:0", relay.Config{TLS: tlsServer, TicketVerifier: verifier, Allow: []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")}})
	if e != nil {
		t.Fatal(e)
	}
	defer node.Close()
	if e = store.PutRelay(ctx, optimizer.RelayCandidate{ID: "VPS-01", Address: node.Addr().String()}); e != nil {
		t.Fatal(e)
	}
	admin, _ := security.NewID()
	api, e := controlplane.New(store, controlplane.Settings{AdminToken: admin, KeyID: "test", SigningKey: issuer, CA: ca, CAKey: caKey})
	if e != nil {
		t.Fatal(e)
	}
	if e = api.Initialize(ctx); e != nil {
		t.Fatal(e)
	}
	httpServer := httptest.NewUnstartedServer(api.Handler())
	httpServer.TLS = &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{{Certificate: [][]byte{serverDER}, PrivateKey: serverKey}}}
	httpServer.StartTLS()
	defer httpServer.Close()
	identityPath := filepath.Join(dir, "identity.json")
	device, deviceKey, e := security.LoadOrCreateIdentity(identityPath)
	if e != nil {
		t.Fatal(e)
	}
	httpClient, e := controlclient.HTTPSClient(caPath)
	if e != nil {
		t.Fatal(e)
	}
	cp := &controlclient.Client{BaseURL: httpServer.URL, HTTP: httpClient, DeviceID: device.ID, DeviceKey: deviceKey, Cache: security.NewConfigCache(map[string]ed25519.PublicKey{"test": issuerPub}, filepath.Join(dir, "cp-cache.json"))}
	cert, e := cp.Register(ctx, "portable integration", base64.RawURLEncoding.EncodeToString(deviceKey.Public().(ed25519.PublicKey)), admin)
	if e != nil {
		t.Fatal(e)
	}
	devicePath := put("device.pem", []byte(cert))
	echo, e := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if e != nil {
		t.Fatal(e)
	}
	defer echo.Close()
	echoToken, _ := security.NewID()
	echoStats := &e2eprobe.EchoStats{}
	go e2eprobe.Serve(ctx, echo, []byte(echoToken), echoStats)
	controller := New(ctx)
	defer controller.Close()
	manifest := Manifest{ControlPlaneURL: httpServer.URL, ControlPlaneCAFile: caPath, CAFile: caPath, TrustFile: trustPath, DeviceIdentityFile: identityPath, DeviceCertificate: devicePath, StateDirectory: dir, ProbeTokenFile: put("echo.token", []byte(echoToken)), ProbeTarget: echo.LocalAddr().String()}
	if e = controller.ConnectRemote(ctx, manifest); e != nil {
		t.Fatal("real remote bootstrap", e)
	}
	measurements := controller.Measurements.Round(ctx)
	if len(measurements) != 2 {
		t.Fatal("missing direct/relay measurements", measurements)
	}
	for _, m := range measurements {
		if !m.Available || m.RTT <= 0 || m.Loss != 0 {
			t.Fatal("real authenticated probe", m)
		}
	}
	// Both producers commit counters AFTER a successful socket write. The
	// client can observe its final reply before those goroutines resume; wait
	// for the same round's accounting, without sending extra probes or weakening
	// the forwarding/loss assertion above.
	accountingDeadline := time.Now().Add(time.Second)
	for node.Metrics.UDPPackets.Load() < 5 || echoStats.Accepted.Load() < 10 {
		if time.Now().After(accountingDeadline) {
			t.Fatalf("forwarding accounting incomplete: relay=%d echo=%d measurements=%+v", node.Metrics.UDPPackets.Load(), echoStats.Accepted.Load(), measurements)
		}
		time.Sleep(time.Millisecond)
	}
	// Exercise the actual control-plane proof/nonce consumption and fresh ticket
	// issuance through pool expansion on the unchanged authenticated relay.
	remotePool := controller.relayPools["VPS-01"]
	var held []routing.Datagram
	for i := 0; i < 75; i++ {
		d, err := remotePool.OpenDatagram(ctx, netip.MustParseAddrPort(echo.LocalAddr().String()))
		if err != nil {
			t.Fatal("fresh CP ticket/pool expansion", i, err)
		}
		held = append(held, d)
	}
	if s := remotePool.Snapshot(); s.HealthySessions < 2 || s.ActiveFlows != 75 {
		t.Fatal(s)
	}
	for _, d := range held {
		d.Close()
	}
	if controller.Snapshot().Connected {
		t.Fatal("portable transport falsely advertised Windows capture")
	}
	cp.Cache = security.NewConfigCache(map[string]ed25519.PublicKey{"test": issuerPub}, filepath.Join(dir, "signed-config.json"))
	if e = cp.Cache.Load(time.Now()); e != nil {
		t.Fatal("service did not persist signed LKG", e)
	}
	httpServer.Close()
	if _, e = cp.Config(ctx); e != nil {
		t.Fatal("valid LKG lost during real HTTPS outage", e)
	}
}
