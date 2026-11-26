package clientservice

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/buzzmean/veliq/core/optimizer"
	"github.com/buzzmean/veliq/core/routing"
	"github.com/buzzmean/veliq/core/security"
	"github.com/buzzmean/veliq/core/transport"
	wp "github.com/buzzmean/veliq/platform/windows"
	cp "github.com/buzzmean/veliq/services/control-plane"
)

func TestFleetColdConnectRemoteBeforeStartReservesAdmission(t *testing.T) {
	for _, mode := range []string{"fresh", "network-unavailable", "revoked"} {
		t.Run(mode, func(t *testing.T) {
			fixture := newAccountFixture(t)
			manifest := fixture.manifest(t)
			manifest.ProbeTarget = "127.0.0.1:9"
			if err := os.WriteFile(manifest.ProbeTokenFile, []byte(strings.Repeat("e", 32)), 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.MkdirAll(manifest.StateDirectory, 0700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(manifest.StateDirectory, fleetOptInFile), []byte(`{"scope":"application","application_id":"canary"}`), 0600); err != nil {
				t.Fatal(err)
			}
			identity, key, err := security.LoadOrCreateIdentity(manifest.DeviceIdentityFile)
			if err != nil {
				t.Fatal(err)
			}
			if err = fixture.store.Register(context.Background(), cp.Device{ID: identity.ID, Name: "cold fixture", PublicKey: base64.RawURLEncoding.EncodeToString(key.Public().(ed25519.PublicKey))}); err != nil {
				t.Fatal(err)
			}
			now := time.Now()
			template := &x509.Certificate{SerialNumber: big.NewInt(3), NotBefore: now.Add(-time.Hour), NotAfter: now.Add(48 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
			der, err := x509.CreateCertificate(rand.Reader, template, fixture.cert, key.Public(), fixture.api.Settings.CAKey)
			if err != nil {
				t.Fatal(err)
			}
			if err = os.WriteFile(manifest.DeviceCertificate, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600); err != nil {
				t.Fatal(err)
			}
			trust := map[string]string{"test": base64.RawURLEncoding.EncodeToString(fixture.api.Settings.SigningKey.Public().(ed25519.PublicKey))}
			rawTrust, _ := json.Marshal(trust)
			if err = os.WriteFile(manifest.TrustFile, rawTrust, 0600); err != nil {
				t.Fatal(err)
			}
			for _, id := range []string{"FI", "LEGACY-A", "LEGACY-B"} {
				if err = fixture.store.PutRelay(context.Background(), optimizer.RelayCandidate{ID: id, Address: "127.0.0.1:9"}); err != nil {
					t.Fatal(err)
				}
			}
			if mode == "revoked" {
				if err = fixture.store.Revoke(context.Background(), identity.ID); err != nil {
					t.Fatal(err)
				}
			}
			if _, err = fixture.store.Publish(context.Background(), "test", fixture.api.Settings.SigningKey, trust); err != nil {
				t.Fatal(err)
			}
			var inspected, policyCalls, legacyCalls atomic.Int32
			inspectEntered, allowInspect := make(chan struct{}), make(chan struct{})
			fleetEntered, allowFleet := make(chan struct{}), make(chan struct{})
			var inspectOnce, fleetOnce, releaseInspect, releaseFleet sync.Once
			defer releaseInspect.Do(func() { close(allowInspect) })
			defer releaseFleet.Do(func() { close(allowFleet) })
			regular := fixture.api.Handler()
			controller := New(context.Background())
			controller.networkInspector = func(ctx context.Context, _ []netip.Addr) wp.NetworkContext {
				inspected.Add(1)
				inspectOnce.Do(func() { close(inspectEntered) })
				select {
				case <-allowInspect:
				case <-ctx.Done():
					return wp.NetworkContext{Error: "fixture cancelled"}
				}
				if mode == "network-unavailable" {
					return wp.NetworkContext{Error: "fixture unavailable", ObservedAt: time.Now()}
				}
				return wp.NetworkContext{Fingerprint: strings.Repeat("a", 64), ObservedAt: time.Now()}
			}
			server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/api/v1/fleet/config":
					policyCalls.Add(1)
					fleetOnce.Do(func() { close(fleetEntered) })
					select {
					case <-allowFleet:
					case <-r.Context().Done():
						return
					}
					now := time.Now().UTC()
					policy := security.FleetPolicy{Schema: 1, Version: 1, Enabled: true, Device: identity.ID, IssuedAt: now, ExpiresAt: now.Add(security.FleetFreshness), Candidates: []security.FleetCandidate{{ID: "FI", Address: "127.0.0.1:9", Phase: security.FleetCanary, ObservedAt: now, LoadAvailable: true, Limits: security.FleetResources{Sessions: 10, Flows: 100, Packets: 1000, Bits: 100000, Opens: 30}}}}
					raw, e := security.Sign(security.FleetConfigDomain, "test", fixture.api.Settings.SigningKey, policy)
					if e != nil {
						w.WriteHeader(500)
						return
					}
					w.Write(raw)
				case "/api/v1/auth":
					var proof security.Proof
					_ = json.NewDecoder(r.Body).Decode(&proof)
					if proof.RelayID != "FI" {
						legacyCalls.Add(1)
					}
					<-r.Context().Done()
				default:
					regular.ServeHTTP(w, r)
				}
			}))
			server.TLS = fixture.server.TLS.Clone()
			server.StartTLS()
			defer server.Close()
			defer controller.Close()
			manifest.ControlPlaneURL = server.URL
			if controller.network.Load() != nil {
				t.Fatal("fixture did not begin with real New/networknil")
			}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			connected := make(chan error, 1)
			go func() { connected <- controller.ConnectRemote(ctx, manifest) }()
			if mode != "revoked" {
				attemptBeforePublication := func() {
					var wg sync.WaitGroup
					for i, id := range []string{"LEGACY-A", "LEGACY-B"} {
						wg.Add(1)
						go func(i int, id string) {
							defer wg.Done()
							attempt, stop := context.WithTimeout(context.Background(), 150*time.Millisecond)
							defer stop()
							flow := routing.Flow{PID: uint32(os.Getpid()), ProcessPath: "fixture.exe", ApplicationID: id, Source: netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(51001+i)), Destination: netip.MustParseAddrPort("127.0.0.1:9"), PinnedPolicy: &routing.Policy{Route: routing.Route{RelayID: id}, ExactRelay: true, RelayAddress: "127.0.0.1:9", BlockOnFailure: true}}
							conn, _ := controller.Engine.OpenTCP(attempt, flow)
							if conn != nil {
								conn.Close()
							}
						}(i, id)
					}
					wg.Wait()
					controller.mu.Lock()
					exposed := len(controller.relayPools) != 0
					controller.mu.Unlock()
					if exposed || legacyCalls.Load() != 0 {
						t.Error("legacy admission exposed while cold initialization was blocked")
					}
				}
				awaitFleetSetup(t, inspectEntered)
				attemptBeforePublication()
				releaseInspect.Do(func() { close(allowInspect) })
				awaitFleetSetup(t, fleetEntered)
				attemptBeforePublication()
				releaseFleet.Do(func() { close(allowFleet) })
			}
			err = <-connected
			if mode == "revoked" {
				if err == nil || !strings.Contains(err.Error(), "device revoked") || !controller.activation.networkBlocked.Load() || inspected.Load() != 0 || policyCalls.Load() != 0 {
					t.Fatal("revocation was bypassed by fleet bootstrap")
				}
				return
			}
			if err != nil || inspected.Load() != 1 || policyCalls.Load() < 1 {
				t.Fatal("cold remote bootstrap failed", err, inspected.Load(), policyCalls.Load())
			}
			if mode == "network-unavailable" {
				if controller.fleet.snapshot(time.Now())["admission"].(transport.FleetAdmissionSnapshot).State != "WAITING_NETWORK" {
					t.Fatal("missing network was not honest waiting")
				}
				controller.Start()
				if _, err = controller.Handle(ctx, "status", nil); err != nil {
					t.Fatal("service status unavailable without network", err)
				}
				return
			}
			controller.Start()
			var wg sync.WaitGroup
			for _, id := range []string{"LEGACY-A", "LEGACY-B"} {
				controller.mu.Lock()
				pool := controller.relayPools[id]
				controller.mu.Unlock()
				wg.Add(1)
				go func() {
					defer wg.Done()
					attempt, stop := context.WithTimeout(context.Background(), 200*time.Millisecond)
					defer stop()
					_ = pool.Warm(attempt)
				}()
			}
			wg.Wait()
			if legacyCalls.Load() > 1 || controller.fleet.budget.Snapshot().Sessions > 2 {
				t.Fatal("legacy creators stole the cold bootstrap slot", legacyCalls.Load())
			}
		})
	}
}
