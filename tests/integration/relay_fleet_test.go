package integration

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"io"
	"net/netip"
	"testing"
	"time"

	"github.com/buzzmean/veliq/core/security"
	"github.com/buzzmean/veliq/core/transport"
	"github.com/buzzmean/veliq/services/relay"
	"github.com/buzzmean/veliq/tools/labcert"
)

func TestFleetDrainRejectsNewHandshakeAndOpenWhileRenewing(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	serverTLS, clientTLS, err := labcert.Pair()
	if err != nil {
		t.Fatal(err)
	}
	pub, issuer, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	trust := map[string]ed25519.PublicKey{"issuer": pub}
	gate, err := relay.NewFleetAdmission("fleet-fixture", trust)
	if err != nil {
		t.Fatal(err)
	}
	server, err := relay.Listen("127.0.0.1:0", relay.Config{
		TLS: serverTLS, TicketVerifier: security.NewTicketVerifier(trust, "fleet-fixture"),
		Acceptance: &relay.AcceptanceConfig{LeaseDuration: 3 * time.Second},
		Allow:      []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")}, Fleet: gate,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	apply := func(version uint64, phase security.FleetPhase) {
		t.Helper()
		now := time.Now().UTC()
		raw, e := security.Sign(security.FleetNodeDomain, "issuer", issuer, security.FleetNodePolicy{
			Schema: 1, Version: version, NodeID: "fleet-fixture", Phase: phase, IssuedAt: now, AdmitUntil: now.Add(security.FleetFreshness),
			Limits: security.FleetResources{Sessions: 10, Flows: 80, Packets: 10000, Bits: 10000000, Opens: 30},
		})
		if e != nil {
			t.Fatal(e)
		}
		if e = gate.Apply(raw, now); e != nil {
			t.Fatal(e)
		}
	}
	apply(1, security.FleetActive)
	peer := clientTLS.Certificates[0].PrivateKey.(ed25519.PrivateKey).Public().(ed25519.PublicKey)
	issue := func(context.Context) ([]byte, error) {
		id, e := security.NewID()
		if e != nil {
			return nil, e
		}
		now := time.Now().UTC()
		return security.Sign("ticket", "issuer", issuer, security.Ticket{
			ID: id, DeviceID: "fixture", DeviceKey: security.Fingerprint(peer), RelayID: "fleet-fixture",
			IssuedAt: now, ExpiresAt: now.Add(time.Minute),
		})
	}
	first, err := issue(ctx)
	if err != nil {
		t.Fatal(err)
	}
	hold, err := transport.DialWithTicket(ctx, server.Addr().String(), clientTLS, first)
	if err != nil {
		t.Fatal(err)
	}
	defer hold.Close()
	tcp, _ := leaseTargets(t)
	stream, err := hold.OpenTCP(ctx, tcp)
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()
	oldTicket, err := issue(ctx)
	if err != nil {
		t.Fatal(err)
	}
	before := hold.Lease().ValidUntil
	hold.StartRenewal(issue)
	apply(2, security.FleetDrain)
	if opened, e := hold.OpenTCP(ctx, tcp); e == nil || !errors.Is(e, transport.ErrCapacity) {
		if opened != nil {
			_ = opened.Close()
		}
		t.Fatalf("additional OPEN in drain: %v", e)
	}
	newCtx, stop := context.WithTimeout(ctx, 2*time.Second)
	unexpected, e := transport.DialWithTicket(newCtx, server.Addr().String(), clientTLS, oldTicket)
	stop()
	if e == nil {
		_ = unexpected.Close()
		t.Fatal("previously issued unused ticket bypassed drain")
	}
	for server.Metrics.Renewals.Load() == 0 || !hold.Lease().ValidUntil.After(before) {
		select {
		case <-ctx.Done():
			t.Fatal("established lease did not renew during drain")
		case <-time.After(20 * time.Millisecond):
		}
	}
	deadline, _ := ctx.Deadline()
	_ = stream.SetDeadline(deadline)
	if _, e = stream.Write([]byte("drain-live")); e != nil {
		t.Fatal(e)
	}
	buf := make([]byte, 10)
	if _, e = io.ReadFull(stream, buf); e != nil || string(buf) != "drain-live" {
		t.Fatalf("established stream no longer passed data: %q %v", buf, e)
	}
}
