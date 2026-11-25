package integration

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"github.com/buzzmean/veliq/core/routing"
	"github.com/buzzmean/veliq/core/security"
	"github.com/buzzmean/veliq/core/transport"
	"github.com/buzzmean/veliq/services/relay"
	"github.com/buzzmean/veliq/tools/echo"
	"github.com/buzzmean/veliq/tools/labcert"
	"net/netip"
	"testing"
	"time"
)

func TestTicketSessionAndLiveRevoke(t *testing.T) {
	serverTLS, clientTLS, err := labcert.Pair()
	if err != nil {
		t.Fatal(err)
	}
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	verifier := security.NewTicketVerifier(map[string]ed25519.PublicKey{"issuer": pub}, "FRA")
	r, err := relay.Listen("127.0.0.1:0", relay.Config{TLS: serverTLS, TicketVerifier: verifier, Allow: []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")}})
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	deviceKey := clientTLS.Certificates[0].PrivateKey.(ed25519.PrivateKey).Public().(ed25519.PublicKey)
	now := time.Now()
	ticket := security.Ticket{ID: "session-nonce", DeviceID: "device", DeviceKey: security.Fingerprint(deviceKey), RelayID: "FRA", IssuedAt: now, ExpiresAt: now.Add(time.Minute)}
	raw, _ := security.Sign("ticket", "issuer", key, ticket)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	client, err := transport.DialWithTicket(ctx, r.Addr().String(), clientTLS, raw)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if lease := client.Lease(); !lease.Supported || lease.Duration != 30*time.Minute {
		t.Fatal("production lease default changed", lease)
	}
	target, stop, err := echo.UDP()
	if err != nil {
		t.Fatal(err)
	}
	defer stop()
	flow, err := client.OpenUDP(ctx, netip.MustParseAddrPort(target.String()))
	if err != nil {
		t.Fatal(err)
	}
	defer flow.Close()
	if err = flow.Send([]byte("authenticated")); err != nil {
		t.Fatal(err)
	}
	b, err := flow.Receive(ctx)
	if err != nil || string(b) != "authenticated" {
		t.Fatal("ticket flow", err)
	}
	if replay, err := transport.DialWithTicket(ctx, r.Addr().String(), clientTLS, raw); err == nil {
		replay.Close()
		t.Fatal("ticket replay accepted")
	}
	verifier.Update(map[string]ed25519.PublicKey{"issuer": pub}, []string{"device"})
	select {
	case <-client.Done():
	case <-ctx.Done():
		t.Fatal("revoked live session survived")
	}
}
func TestSecondaryRelayOnPrimaryFailure(t *testing.T) {
	r1, c1, _ := setup(t, 5*time.Second)
	r2, c2, _ := setup(t, 5*time.Second)
	r1.Close()
	<-c1.Done()
	a, stop, err := echo.UDP()
	if err != nil {
		t.Fatal(err)
	}
	defer stop()
	engine := routing.New(10)
	engine.SetRelay("primary", c1)
	engine.SetRelay("secondary", c2)
	engine.SetPolicy("game", routing.Policy{Route: routing.Route{RelayID: "primary"}, Backups: []routing.Route{{RelayID: "secondary"}}})
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	f := routing.Flow{Source: netip.MustParseAddrPort("127.0.0.1:34000"), Destination: netip.MustParseAddrPort(a.String()), PID: 123, ProcessPath: "game.exe", ApplicationID: "game"}
	d, err := engine.OpenUDP(ctx, f)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	d.Send([]byte("backup"))
	b, err := d.Receive(ctx)
	if err != nil || string(b) != "backup" {
		t.Fatal(err)
	}
	deadline := time.Now().Add(time.Second)
	for r2.Metrics.UDPPackets.Load() != 1 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if engine.Snapshot()[0].Route.RelayID != "secondary" || r2.Metrics.UDPPackets.Load() != 1 {
		t.Fatalf("not pinned to secondary: flows=%+v udp=%d", engine.Snapshot(), r2.Metrics.UDPPackets.Load())
	}
}
