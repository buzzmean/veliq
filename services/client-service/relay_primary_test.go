package clientservice

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net"
	"net/netip"
	"os"
	"testing"
	"time"

	"github.com/buzzmean/veliq/core/routing"
	"github.com/buzzmean/veliq/core/security"
	"github.com/buzzmean/veliq/core/transport"
)

type primaryFixture struct {
	healthy, fail bool
	opens         int
	peers         []net.Conn
}

func (f *primaryFixture) Healthy() bool { return f.healthy }
func (f *primaryFixture) OpenTCP(context.Context, netip.AddrPort) (net.Conn, error) {
	f.opens++
	if f.fail {
		return nil, errors.New("injected unavailable")
	}
	a, b := net.Pipe()
	f.peers = append(f.peers, b)
	return a, nil
}
func (f *primaryFixture) OpenDatagram(context.Context, netip.AddrPort) (routing.Datagram, error) {
	return nil, errors.New("injected no UDP")
}
func TestP0PrimaryUniqueAudienceAndFailClosedNewOpensPreserveExisting(t *testing.T) {
	primary, standby := &primaryFixture{healthy: true}, &primaryFixture{healthy: true}
	r := newRelayPrimary()
	p := &primaryRelayProvider{primary: primary, standby: standby, runtime: r, primaryAddress: "146.0.77.98:4433", standbyAddress: "2.56.177.4:4433"}
	t.Cleanup(func() {
		for _, f := range []*primaryFixture{primary, standby} {
			for _, c := range f.peers {
				c.Close()
			}
		}
	})
	dst := netip.MustParseAddrPort("1.1.1.1:443")
	first, e := p.OpenTCP(context.Background(), dst)
	if e != nil {
		t.Fatal(e)
	}
	defer first.Close()
	primary.fail = true
	second, e := p.OpenTCP(context.Background(), dst)
	if e != nil {
		t.Fatal(e)
	}
	defer second.Close()
	if primary.opens != 2 || standby.opens != 1 {
		t.Fatal("new selection failed")
	}
	done := make(chan error, 1)
	go func() { _, e := primary.peers[0].Write([]byte("x")); done <- e }()
	b := make([]byte, 1)
	if _, e = first.Read(b); e != nil || b[0] != 'x' {
		t.Fatal("unrelated live stream disrupted", e)
	}
	if e = <-done; e != nil {
		t.Fatal(e)
	}
	standby.fail = true
	if c, e := p.OpenTCP(context.Background(), dst); e == nil || c != nil {
		t.Fatal("unavailable relays returned a DIRECT socket")
	}
	// Ticket audience separation prevents cross-server replay. No production CP.
	signerPub, signer, _ := ed25519.GenerateKey(rand.Reader)
	device, _, _ := ed25519.GenerateKey(rand.Reader)
	now := time.Now()
	ticket := security.Ticket{ID: "unique-ticket", DeviceID: "fixture", DeviceKey: security.Fingerprint(device), RelayID: primaryRelayID, IssuedAt: now, ExpiresAt: now.Add(time.Minute)}
	raw, e := security.Sign("ticket", "fixture", signer, ticket)
	if e != nil {
		t.Fatal(e)
	}
	newVerifier := security.NewTicketVerifier(map[string]ed25519.PublicKey{"fixture": signerPub}, primaryRelayID)
	oldVerifier := security.NewTicketVerifier(map[string]ed25519.PublicKey{"fixture": signerPub}, "VPS-01")
	if _, e = newVerifier.Accept(raw, device, now); e != nil {
		t.Fatal(e)
	}
	if _, e = newVerifier.Accept(raw, device, now); e == nil {
		t.Fatal("same node replay accepted")
	}
	if _, e = oldVerifier.Accept(raw, device, now); e == nil {
		t.Fatal("cross-audience replay accepted")
	}
}

func TestP0EmptySignedRegistryDoesNotPublishTypedNilRelay(t *testing.T) {
	c := New(context.Background())
	defer c.Close()
	s := &remoteState{controller: c, clients: map[string]*transport.Pool{}, addresses: map[string]string{}}
	if err := s.apply(context.Background(), security.Config{}); err != nil {
		t.Fatal(err)
	}
	listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	path, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	// Identity is required: unauthenticated flows intentionally ignore pinned
	// policies and stay DIRECT. Never make this security assertion depend on WAN.
	f := routing.Flow{PID: uint32(os.Getpid()), ProcessPath: path, ApplicationID: "fixture-protected", Protocol: "tcp", Source: netip.MustParseAddrPort("127.0.0.1:50001"), Destination: listener.Addr().(*net.TCPAddr).AddrPort(), PinnedPolicy: &routing.Policy{Route: routing.Route{RelayID: "VPS-01"}, BlockOnFailure: true}}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if conn, err := c.Engine.OpenTCP(ctx, f); err == nil || conn != nil {
		if conn != nil {
			conn.Close()
		}
		t.Fatal("empty signed registry did not fail closed")
	}
	listener.SetDeadline(time.Now().Add(30 * time.Millisecond))
	if conn, err := listener.Accept(); conn != nil || err == nil {
		if conn != nil {
			conn.Close()
		}
		t.Fatal("DIRECT leak to isolated sentinel")
	}
}
