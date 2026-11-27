package clientservice

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/buzzmean/veliq/core/controlclient"
	"github.com/buzzmean/veliq/core/optimizer"
	"github.com/buzzmean/veliq/core/security"
	"github.com/buzzmean/veliq/core/transport"
	wp "github.com/buzzmean/veliq/platform/windows"
	"github.com/buzzmean/veliq/services/relay"
	"github.com/buzzmean/veliq/tools/echo"
	"github.com/buzzmean/veliq/tools/labcert"
)

type fleetCapacityFixture struct {
	c         *Controller
	s         *remoteState
	pool      *transport.Pool
	server    *relay.Server
	tls       *tls.Config
	serverTLS *tls.Config
	public    ed25519.PublicKey
	key       ed25519.PrivateKey
	peer      string
	address   string
	target    netip.AddrPort
	version   uint64
	calls     atomic.Int32
	mu        sync.Mutex
	clients   []*transport.Client
}

func newFleetCapacityFixture(t *testing.T) *fleetCapacityFixture {
	t.Helper()
	x := &fleetCapacityFixture{c: New(context.Background())}
	t.Cleanup(func() { x.c.Close() })
	x.c.network.Store(&wp.NetworkContext{Fingerprint: strings.Repeat("a", 64), ObservedAt: time.Now()})
	serverTLS, clientTLS, err := labcert.Pair()
	if err != nil {
		t.Fatal(err)
	}
	x.tls = clientTLS
	x.serverTLS = serverTLS
	public, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	x.key = key
	x.public = public
	x.peer = security.Fingerprint(clientTLS.Certificates[0].PrivateKey.(ed25519.PrivateKey).Public().(ed25519.PublicKey))
	gate, err := relay.NewFleetAdmission("FI", map[string]ed25519.PublicKey{"test": public})
	if err != nil {
		t.Fatal(err)
	}
	x.server, err = relay.Listen("127.0.0.1:0", relay.Config{TLS: serverTLS, MaxSessions: 2, MaxFlows: 4, Fleet: gate,
		TicketVerifier: security.NewTicketVerifier(map[string]ed25519.PublicKey{"test": public}, "FI"), Allow: []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { x.server.Close() })
	x.address = x.server.Addr().String()
	now := time.Now()
	raw, err := security.Sign(security.FleetNodeDomain, "test", key, security.FleetNodePolicy{Schema: 1, Version: 1, NodeID: "FI", Phase: security.FleetCanary,
		IssuedAt: now, AdmitUntil: now.Add(security.FleetFreshness), CanaryDevice: "capacity-device", Limits: fleetCapacityLimits()})
	if err != nil {
		t.Fatal(err)
	}
	if err = gate.Apply(raw, now); err != nil {
		t.Fatal(err)
	}
	address, closeEcho, err := echo.TCP()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(closeEcho)
	x.target = netip.MustParseAddrPort(address.String())
	cfg := transport.DefaultPoolConfig()
	cfg.FleetBudget = &x.c.fleet.budget
	x.pool, err = transport.NewPool(context.Background(), cfg, x.factory)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { x.pool.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err = x.pool.Warm(ctx); err != nil {
		t.Fatal(err)
	}
	x.c.fleet.arm("capacity-device")
	x.s = &remoteState{controller: x.c, tls: clientTLS, clients: map[string]*transport.Pool{}, addresses: map[string]string{},
		fleet: &remoteFleet{cache: security.NewFleetCache(map[string]ed25519.PublicKey{"test": public}, "capacity-device", ""),
			pools: map[string]remoteFleetPool{"FI": {address: x.address, pool: x.pool, owned: true}}}}
	t.Cleanup(x.s.close)
	return x
}

func fleetCapacityLimits() security.FleetResources {
	return security.FleetResources{Sessions: 1, Flows: 1, Packets: 10000, Bits: 10000000, Opens: 1000}
}

func (x *fleetCapacityFixture) factory(ctx context.Context) (*transport.Client, error) {
	x.calls.Add(1)
	raw, err := x.ticket()
	if err != nil {
		return nil, err
	}
	client, err := transport.DialWithTicket(ctx, x.address, x.tls, raw)
	if err == nil {
		x.mu.Lock()
		x.clients = append(x.clients, client)
		x.mu.Unlock()
	}
	return client, err
}

func (x *fleetCapacityFixture) ticket() ([]byte, error) {
	id, err := security.NewID()
	if err != nil {
		return nil, err
	}
	now := time.Now()
	return security.Sign("ticket", "test", x.key, security.Ticket{ID: id, DeviceID: "capacity-device", DeviceKey: x.peer, RelayID: "FI", IssuedAt: now, ExpiresAt: now.Add(time.Minute)})
}

func (x *fleetCapacityFixture) apply(t *testing.T, mutate func(*security.FleetPolicy)) {
	t.Helper()
	x.version++
	now := time.Now()
	policy := security.FleetPolicy{Schema: 1, Version: x.version, Device: "capacity-device", Enabled: true, IssuedAt: now, ExpiresAt: now.Add(security.FleetFreshness),
		Candidates: []security.FleetCandidate{{ID: "FI", Address: x.address, Phase: security.FleetCanary, Limits: fleetCapacityLimits(), Used: security.FleetResources{Sessions: 1}, LoadAvailable: true, ObservedAt: now}}}
	if mutate != nil {
		mutate(&policy)
	}
	raw, err := security.Sign(security.FleetConfigDomain, "test", x.key, policy)
	if err != nil {
		t.Fatal(err)
	}
	verified, err := x.s.fleet.cache.Apply(raw, now)
	if err != nil {
		t.Fatal(err)
	}
	if err = x.s.applyFleetPolicy(verified, now); err != nil {
		t.Fatal(err)
	}
}

func fleetCapacityEcho(t *testing.T, c net.Conn) {
	t.Helper()
	if err := c.SetDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Write([]byte("reuse")); err != nil {
		t.Fatal(err)
	}
	data := make([]byte, 5)
	if _, err := io.ReadFull(c, data); err != nil || string(data) != "reuse" {
		t.Fatal("existing lease failed", err)
	}
	if err := c.SetDeadline(time.Time{}); err != nil {
		t.Fatal(err)
	}
}

func TestFleetCapacityOwnSessionRemainsReusableAtSignedSessionLimit(t *testing.T) {
	x := newFleetCapacityFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	for range 3 {
		x.apply(t, nil)
		if x.s.fleet.pools["FI"].pool != x.pool || len(x.c.fleet.nodes) != 1 || x.c.fleet.nodes[0].weight <= 0 {
			t.Fatal("signed sessions1/limit1 removed the own authenticated pool")
		}
		if x.pool.CanCreateFleetSession() {
			t.Fatal("reuse permission allowed another session")
		}
	}
	before := x.pool.Snapshot().Sessions[0].ID
	for range 50 {
		_ = x.c.fleet.snapshot(time.Now())
	}
	flow, err := x.pool.OpenFleetTCP(ctx, x.target)
	if err != nil {
		t.Fatal(err)
	}
	defer flow.Close()
	fleetCapacityEcho(t, flow)
	if x.calls.Load() != 1 || x.server.Metrics.Sessions.Load() != 1 || x.pool.Snapshot().Sessions[0].ID != before {
		t.Fatal("new flow dialed instead of reusing authenticated session")
	}
	x.apply(t, func(p *security.FleetPolicy) { p.Candidates[0].Used.Flows = 1 })
	if len(x.c.fleet.nodes) != 0 || x.s.fleet.pools["FI"].pool != x.pool {
		t.Fatal("flow quota confused lifecycle with admission")
	}
	if next, err := x.pool.OpenFleetTCP(ctx, x.target); err == nil {
		next.Close()
		t.Fatal("full flow quota admitted a new stream")
	}
	fleetCapacityEcho(t, flow)
	x.apply(t, nil)
	if len(x.c.fleet.nodes) != 1 || x.calls.Load() != 1 {
		t.Fatal("fresh spare flow quota recreated pool")
	}
	flow.Close()
	x.mu.Lock()
	client := x.clients[0]
	x.mu.Unlock()
	client.Close() // Simulated transport loss after shortlist, not a production action.
	for _, attempt := range []func() error{
		func() error { return x.pool.Warm(ctx) },
		func() error {
			c, err := x.pool.OpenFleetTCP(ctx, x.target)
			if c != nil {
				c.Close()
			}
			return err
		},
		func() error {
			d, err := x.pool.OpenFleetProbeDatagram(ctx, x.target)
			if d != nil {
				d.Close()
			}
			return err
		},
	} {
		if err := attempt(); err == nil {
			t.Fatal("dead reusable session bypassed full signed session quota")
		}
	}
	if x.calls.Load() != 1 {
		t.Fatal("loss after reuse decision caused a second factory call")
	}
}

func TestFleetCapacityFullOtherResourcesPreserveLeaseButDenyAdmission(t *testing.T) {
	for _, resource := range []string{"flows", "packets", "bits", "opens"} {
		t.Run(resource, func(t *testing.T) {
			x := newFleetCapacityFixture(t)
			x.apply(t, nil)
			flow, err := x.pool.OpenFleetTCP(context.Background(), x.target)
			if err != nil {
				t.Fatal(err)
			}
			defer flow.Close()
			x.apply(t, func(p *security.FleetPolicy) {
				n := &p.Candidates[0]
				switch resource {
				case "flows":
					n.Used.Flows = n.Limits.Flows
				case "packets":
					n.Used.Packets = n.Limits.Packets
				case "bits":
					n.Used.Bits = n.Limits.Bits
				case "opens":
					n.Used.Opens = n.Limits.Opens
				}
			})
			if len(x.c.fleet.nodes) != 0 || x.s.fleet.pools["FI"].pool != x.pool {
				t.Fatal("full resource retired the existing authenticated lease")
			}
			if c, err := x.pool.OpenFleetTCP(context.Background(), x.target); err == nil {
				c.Close()
				t.Fatal("quota-full prepared attempt reused a session")
			}
			fleetCapacityEcho(t, flow)
			if x.calls.Load() != 1 {
				t.Fatal("full resource triggered new dial")
			}
		})
	}
}

func TestFleetCapacityReuseRequiresExactKnownPool(t *testing.T) {
	for _, kind := range []string{"no-owned", "foreign", "changed-address"} {
		t.Run(kind, func(t *testing.T) {
			x := newFleetCapacityFixture(t)
			switch kind {
			case "no-owned":
				x.s.fleet.pools = map[string]remoteFleetPool{}
			case "foreign":
				x.s.fleet.pools["FI"] = remoteFleetPool{address: x.address, pool: x.pool, owned: false}
			}
			x.apply(t, func(p *security.FleetPolicy) {
				if kind == "changed-address" {
					p.Candidates[0].Address = "127.0.0.1:9"
				}
			})
			if len(x.c.fleet.nodes) != 0 || x.calls.Load() != 1 {
				t.Fatal("unknown identity/address was treated as owned spare session")
			}
		})
	}
}

func TestFleetCapacityPolicyInvalidationPreservesExistingFlow(t *testing.T) {
	for _, mode := range []string{"off", "suspend", "network", "stale", "removed"} {
		t.Run(mode, func(t *testing.T) {
			x := newFleetCapacityFixture(t)
			x.apply(t, nil)
			flow, err := x.pool.OpenFleetTCP(context.Background(), x.target)
			if err != nil {
				t.Fatal(err)
			}
			defer flow.Close()
			switch mode {
			case "off":
				x.apply(t, func(p *security.FleetPolicy) { p.Enabled = false; p.Candidates = nil })
			case "removed":
				x.apply(t, func(p *security.FleetPolicy) { p.Candidates = nil })
			case "stale":
				x.apply(t, func(p *security.FleetPolicy) { p.Candidates[0].ObservedAt = time.Now().Add(-46 * time.Second) })
			case "suspend":
				x.c.fleet.suspend()
			case "network":
				x.c.network.Store(&wp.NetworkContext{Fingerprint: strings.Repeat("b", 64), ObservedAt: time.Now()})
				x.c.fleet.networkChanged()
			}
			if next, err := x.pool.OpenFleetTCP(context.Background(), x.target); err == nil {
				next.Close()
				t.Fatal("stale prepared attempt survived authorization change")
			}
			fleetCapacityEcho(t, flow)
			if x.calls.Load() != 1 {
				t.Fatal("invalidation created a new session")
			}
		})
	}
}

func TestFleetCapacityLegacyOwnershipTransferKeepsTaggedGate(t *testing.T) {
	x := newFleetCapacityFixture(t)
	x.apply(t, nil)
	if err := x.s.apply(context.Background(), security.Config{Relays: []optimizer.RelayCandidate{{ID: "FI", Address: x.address}}}); err != nil {
		t.Fatal(err)
	}
	if x.s.clients["FI"] != x.pool || x.s.fleet.pools["FI"].owned {
		t.Fatal("same endpoint did not transfer ownership")
	}
	x.c.fleet.suspend()
	if c, err := x.pool.OpenFleetTCP(context.Background(), x.target); err == nil {
		c.Close()
		t.Fatal("borrowed alias lost tagged gate")
	}
	manual, err := x.pool.OpenTCP(context.Background(), x.target)
	if err != nil {
		t.Fatal("ordinary exact manual reuse was blocked", err)
	}
	defer manual.Close()
	fleetCapacityEcho(t, manual)
	if x.calls.Load() != 1 {
		t.Fatal("ownership transfer duplicated the session")
	}
}

func TestFleetCapacityRegularAddressChangeCannotReuseOldFleetAuthorization(t *testing.T) {
	x := newFleetCapacityFixture(t)
	x.apply(t, nil)
	if err := x.s.apply(context.Background(), security.Config{Relays: []optimizer.RelayCandidate{{ID: "FI", Address: x.address}}}); err != nil {
		t.Fatal(err)
	}
	oldFlow, err := x.pool.OpenTCP(context.Background(), x.target)
	if err != nil {
		t.Fatal(err)
	}
	defer oldFlow.Close()
	other, err := relay.Listen("127.0.0.1:0", relay.Config{TLS: x.serverTLS.Clone(), MaxSessions: 2, MaxFlows: 4,
		TicketVerifier: security.NewTicketVerifier(map[string]ed25519.PublicKey{"test": x.public}, "FI"), Allow: []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}})
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	var authCalls atomic.Int32
	deviceKey := x.tls.Certificates[0].PrivateKey.(ed25519.PrivateKey)
	cp := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/auth" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		body, err := io.ReadAll(io.LimitReader(r.Body, 4096))
		var proof security.Proof
		if err != nil || security.Parse(body, &proof) != nil || proof.DeviceID != "capacity-device" || proof.RelayID != "FI" || proof.Verify(deviceKey.Public().(ed25519.PublicKey), time.Now()) != nil {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		authCalls.Add(1)
		ticket, err := x.ticket()
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		_, _ = w.Write(ticket)
	}))
	defer cp.Close()
	x.s.cp = &controlclient.Client{BaseURL: cp.URL, HTTP: cp.Client(), DeviceID: "capacity-device", DeviceKey: deviceKey}
	address := other.Addr().String()
	if err = x.s.apply(context.Background(), security.Config{Relays: []optimizer.RelayCandidate{{ID: "FI", Address: address}}}); err != nil {
		t.Fatal(err)
	}
	// A real normal/manual open may authenticate to the new regular endpoint.
	manual, err := x.pool.OpenTCP(context.Background(), x.target)
	if err != nil {
		t.Fatal("normal manual endpoint update failed", err)
	}
	defer manual.Close()
	fleetCapacityEcho(t, manual)
	fleetCapacityEcho(t, oldFlow)
	if authCalls.Load() != 1 {
		t.Fatal("normal endpoint update did not create exactly one session")
	}
	if stale, err := x.pool.OpenFleetTCP(context.Background(), x.target); err == nil {
		stale.Close()
		t.Fatal("old fleet address authorization reused the new manual session")
	}
	if authCalls.Load() != 1 {
		t.Fatal("stale fleet attempt dialed another session")
	}
	x.apply(t, func(p *security.FleetPolicy) { p.Candidates[0].Address = address })
	manual.Close()
	fresh, err := x.pool.OpenFleetTCP(context.Background(), x.target)
	if err != nil {
		t.Fatal("matching fresh policy did not allow reuse", err)
	}
	defer fresh.Close()
	fleetCapacityEcho(t, fresh)
	if authCalls.Load() != 1 {
		t.Fatal("matching fresh policy did not reuse the manual session")
	}
	fleetCapacityEcho(t, oldFlow)
}
