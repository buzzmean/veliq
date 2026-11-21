package integration

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/buzzmean/neexitlag/core/controlclient"
	"github.com/buzzmean/neexitlag/core/protocol"
	"github.com/quic-go/quic-go"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/buzzmean/neexitlag/core/routing"
	"github.com/buzzmean/neexitlag/core/security"
	"github.com/buzzmean/neexitlag/core/transport"
	"github.com/buzzmean/neexitlag/services/relay"
	"github.com/buzzmean/neexitlag/tools/echo"
	"github.com/buzzmean/neexitlag/tools/labcert"
)

type leaseFixture struct {
	tls      *tls.Config
	key      ed25519.PrivateKey
	peer     ed25519.PublicKey
	server   *relay.Server
	client   *transport.Client
	verifier *security.TicketVerifier
	ticket   func(context.Context) ([]byte, error)
}

func newLeaseFixture(t *testing.T, duration time.Duration, drop int) *leaseFixture {
	t.Helper()
	st, ct, err := labcert.Pair()
	if err != nil {
		t.Fatal(err)
	}
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	v := security.NewTicketVerifier(map[string]ed25519.PublicKey{"issuer": pub}, "VPS-01")
	server, err := relay.Listen("127.0.0.1:0", relay.Config{TLS: st, TicketVerifier: v, Acceptance: &relay.AcceptanceConfig{LeaseDuration: duration, DropRenewalACKs: drop}, Allow: []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { server.Close() })
	peer := ct.Certificates[0].PrivateKey.(ed25519.PrivateKey).Public().(ed25519.PublicKey)
	ticket := func(ctx context.Context) ([]byte, error) {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		id, _ := security.NewID()
		now := time.Now()
		return security.Sign("ticket", "issuer", key, security.Ticket{ID: id, DeviceID: "machine", DeviceKey: security.Fingerprint(peer), RelayID: "VPS-01", IssuedAt: now, ExpiresAt: now.Add(time.Minute)})
	}
	// Exercise the existing signed-proof ticket client on every renewal, with
	// a bounded isolated issuer. Production continues to use the real CP API/DB.
	var proofMu sync.Mutex
	nonces := map[string]bool{}
	issue := ticket
	issuer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var proof security.Proof
		if r.Method != "POST" || r.URL.Path != "/api/v1/auth" || json.NewDecoder(http.MaxBytesReader(w, r.Body, 8192)).Decode(&proof) != nil || proof.DeviceID != "machine" || proof.RelayID != "VPS-01" || proof.Verify(peer, time.Now()) != nil {
			http.Error(w, "invalid device proof", 401)
			return
		}
		proofMu.Lock()
		used := nonces[proof.Nonce]
		if len(nonces) >= 128 {
			used = true
		}
		nonces[proof.Nonce] = true
		proofMu.Unlock()
		if used {
			http.Error(w, "proof replay or capacity", 401)
			return
		}
		raw, err := issue(r.Context())
		if err != nil {
			http.Error(w, "ticket unavailable", 503)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(raw)
	}))
	t.Cleanup(issuer.Close)
	cp := &controlclient.Client{BaseURL: issuer.URL, DeviceID: "machine", DeviceKey: ct.Certificates[0].PrivateKey.(ed25519.PrivateKey)}
	ticket = func(ctx context.Context) ([]byte, error) { return cp.Ticket(ctx, "VPS-01") }
	raw, _ := ticket(context.Background())
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	c, err := transport.DialWithTicket(ctx, server.Addr().String(), ct, raw)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return &leaseFixture{server: server, client: c, verifier: v, ticket: ticket, tls: ct, key: key, peer: peer}
}
func leaseTargets(t *testing.T) (netip.AddrPort, netip.AddrPort) {
	t.Helper()
	tcp, tc, e := echo.TCP()
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(tc)
	udp, uc, e := echo.UDP()
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(uc)
	return netip.MustParseAddrPort(tcp.String()), netip.MustParseAddrPort(udp.String())
}

// This test is also shipped as a Windows test executable. The explicit env
// override is read only here, never by production relay/service configuration.
func TestAcceleratedLeaseAcceptance(t *testing.T) {
	duration := 4 * time.Second
	if s := os.Getenv("NEEXITLAG_ACCEPTANCE_LEASE_SECONDS"); s != "" {
		n, e := strconv.Atoi(s)
		if e != nil || n < 60 || n > 90 {
			t.Fatal("explicit acceptance lease must be 60..90 seconds")
		}
		duration = time.Duration(n) * time.Second
	}
	x := newLeaseFixture(t, duration, 0)
	tcp, udp := leaseTargets(t)
	ctx, cancel := context.WithTimeout(context.Background(), 3*duration)
	defer cancel()
	c, err := x.client.OpenTCP(ctx, tcp)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	u, err := x.client.OpenUDP(ctx, udp)
	if err != nil {
		t.Fatal(err)
	}
	defer u.Close()
	stream := c.(interface{ StreamID() int64 }).StreamID()
	us := u.StreamID()
	id := u.FlowID()
	initial := x.client.Lease()
	x.client.StartRenewal(x.ticket)
	ticker := time.NewTicker(min(50*time.Millisecond, duration/30))
	defer ticker.Stop()
	probes := 0
	var maxProbeRTT time.Duration
	for x.client.Lease().Renewals < 2 || probes < 3 {
		probeStarted := time.Now()
		c.SetDeadline(time.Now().Add(3 * time.Second))
		p := []byte(fmt.Sprintf("lease-%08d", probes))
		if _, err = c.Write(p); err != nil {
			t.Fatal("established TCP write interrupted", err)
		}
		b := make([]byte, len(p))
		if _, err = io.ReadFull(c, b); err != nil || string(b) != string(p) {
			t.Fatalf("established TCP response: err=%v probe=%d lease=%+v session_end=%s server_renewals=%d server_expiries=%d", err, probes, x.client.Lease(), x.client.SessionEndReason(), x.server.Metrics.Renewals.Load(), x.server.Metrics.LeaseExpiries.Load())
		}
		if err = u.Send(p); err != nil {
			t.Fatal("established UDP send interrupted", err)
		}
		read, stop := context.WithTimeout(ctx, 3*time.Second)
		b, err = u.Receive(read)
		stop()
		if err != nil || string(b) != string(p) {
			t.Fatalf("established UDP response: err=%v probe=%d lease=%+v session_end=%s client_drops=%d local_drops=%+v server_udp=%d server_drops=%d server_flows=%d", err, probes, x.client.Lease(), x.client.SessionEndReason(), x.client.Dropped(), x.client.LocalDrops.Snapshot(), x.server.Metrics.UDPPackets.Load(), x.server.Metrics.Drops.Load(), x.server.Metrics.Flows.Load())
		}
		if c.(interface{ StreamID() int64 }).StreamID() != stream || u.StreamID() != us || u.FlowID() != id {
			t.Fatal("established flow replaced")
		}
		if x.server.Metrics.Sessions.Load() != 1 || x.server.Metrics.TCPConnections.Load() != 1 || x.server.Metrics.Flows.Load() != 2 {
			t.Fatal("server connection/flow replaced")
		}
		maxProbeRTT = max(maxProbeRTT, time.Since(probeStarted))
		probes++
		select {
		case <-ctx.Done():
			t.Fatal("two renewals not completed", x.client.Lease())
		case <-ticker.C:
		}
	}
	after := x.client.Lease()
	if !after.Deadline.After(initial.Deadline) || x.server.Metrics.Renewals.Load() < 2 || x.server.Metrics.LeaseExpiries.Load() != 0 {
		t.Fatal("renewal evidence", after)
	}
	t.Logf("PASS same_session=true tcp_stream=%d udp_stream=%d udp_flow=%d probes=%d renewals=%d max_probe_roundtrip=%s deadline_before=%s deadline_after=%s relay_only_transport_fixture=true", stream, us, id, probes, after.Renewals, maxProbeRTT, initial.Deadline.Format(time.RFC3339Nano), after.Deadline.Format(time.RFC3339Nano))
}
func TestLeaseLostACKAndTemporaryCPOutage(t *testing.T) {
	x := newLeaseFixture(t, 4*time.Second, 1)
	var calls atomic.Int32
	x.client.StartRenewal(func(ctx context.Context) ([]byte, error) {
		if calls.Add(1) == 1 {
			return nil, errors.New("temporary CP unavailable")
		}
		return x.ticket(ctx)
	})
	deadline := time.NewTimer(12 * time.Second)
	defer deadline.Stop()
	for x.client.Lease().Renewals < 2 {
		select {
		case <-x.client.Done():
			t.Fatal("session lost", x.client.Lease())
		case <-deadline.C:
			t.Fatal("renewal stalled", x.client.Lease())
		case <-time.After(20 * time.Millisecond):
		}
	}
	if x.client.Lease().Failures < 2 || x.client.Lease().ReceiptRetries == 0 {
		t.Fatal("outage/lost receipt not exercised", x.client.Lease())
	}
	// Lost ACK receipt recovery must extend once, not once per retry.
	if x.server.Metrics.Renewals.Load() != x.client.Lease().Renewals {
		t.Fatal("receipt extended lease twice")
	}
}
func TestLeaseHardExpiryFailsClosed(t *testing.T) {
	x := newLeaseFixture(t, 800*time.Millisecond, 0)
	_, dst := leaseTargets(t)
	e := routing.New(8)
	e.SetRelay("VPS-01", x.client)
	e.SetPolicy("protected", routing.Policy{Route: routing.Route{RelayID: "VPS-01"}, BlockOnFailure: true})
	f := routing.Flow{Source: netip.MustParseAddrPort("127.0.0.1:19001"), Destination: dst, PID: 99, ProcessPath: "selected.exe", ApplicationID: "protected"}
	d, err := e.OpenUDP(context.Background(), f)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	x.client.StartRenewal(func(context.Context) ([]byte, error) { return nil, errors.New("CP offline") })
	select {
	case <-x.client.Done():
	case <-time.After(3 * time.Second):
		t.Fatal("unbounded authorization")
	}
	if err = d.Send([]byte("must not go direct")); err == nil {
		t.Fatal("expired flow sent")
	}
	for _, f := range e.Snapshot() {
		if f.Route.Direct() {
			t.Fatal("DIRECT leak")
		}
	}
	if x.client.SessionEndReason() != "authorization_lease_expired" {
		t.Fatal(x.client.SessionEndReason())
	}
}
func TestLeaseSaturationAndIndependentPeer(t *testing.T) {
	x := newLeaseFixture(t, 4*time.Second, 0)
	_, dst := leaseTargets(t)
	var held []*transport.UDPFlow
	for i := 0; i < 64; i++ {
		f, err := x.client.OpenUDP(context.Background(), dst)
		if err != nil {
			t.Fatalf("flow %d: %v", i, err)
		}
		held = append(held, f)
	}
	defer func() {
		for _, f := range held {
			f.Close()
		}
	}()
	peer := newLeaseFixture(t, 900*time.Millisecond, 0)
	x.client.StartRenewal(x.ticket)
	peer.client.StartRenewal(func(context.Context) ([]byte, error) { return nil, errors.New("peer CP unavailable") })
	until := time.Now().Add(12 * time.Second)
	for x.client.Lease().Renewals < 2 && time.Now().Before(until) {
		if err := held[0].Send([]byte("active")); err != nil {
			t.Fatal(err)
		}
		time.Sleep(20 * time.Millisecond)
	}
	if x.client.Lease().Renewals < 2 {
		t.Fatal("flow saturation prevented control", x.client.Lease())
	}
	select {
	case <-peer.client.Done():
	default:
		t.Fatal("failed peer did not expire")
	}
	select {
	case <-x.client.Done():
		t.Fatal("peer failure killed healthy session")
	default:
	}
}

func TestLeaseRenewalReplayAndDeviceBinding(t *testing.T) {
	x := newLeaseFixture(t, 2*time.Second, 0)
	cfg := x.tls.Clone()
	cfg.NextProtos = []string{protocol.LeaseALPN}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := quic.DialAddr(ctx, x.server.Addr().String(), cfg, transport.QUICConfig())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.CloseWithError(0, "test done")
	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		t.Fatal(err)
	}
	stream.SetDeadline(time.Now().Add(12 * time.Second))
	initial, _ := x.ticket(ctx)
	if err = protocol.WriteTicket(stream, initial); err != nil {
		t.Fatal(err)
	}
	if _, err = protocol.ReadLeaseAck(stream); err != nil {
		t.Fatal(err)
	}
	raw, _ := x.ticket(ctx)
	requestResult := func(seq uint64, raw []byte) (protocol.LeaseAck, error) {
		t.Helper()
		frames, err := protocol.LeaseRequests(seq, raw)
		if err != nil {
			return protocol.LeaseAck{}, err
		}
		for _, frame := range frames {
			if err = conn.SendDatagram(frame); err != nil {
				return protocol.LeaseAck{}, err
			}
		}
		b, err := conn.ReceiveDatagram(ctx)
		if err != nil {
			return protocol.LeaseAck{}, err
		}
		return protocol.ParseLeaseAckFrame(b)
	}
	request := func(seq uint64, raw []byte) protocol.LeaseAck {
		t.Helper()
		ack, err := requestResult(seq, raw)
		if err != nil {
			t.Fatal(err)
		}
		if ack.Sequence != seq {
			t.Fatalf("wrong ACK sequence: got %d want %d", ack.Sequence, seq)
		}
		return ack
	}
	first := request(1, raw)
	if first.Status != 0 {
		t.Fatal("renewal rejected")
	}
	receipt := request(1, raw)
	if receipt.Status != 0 || !receipt.Deadline.Equal(first.Deadline) {
		t.Fatal("receipt not idempotent")
	}
	if ack := request(2, raw); ack.Status == 0 {
		t.Fatal("one-shot ticket replay accepted as new renewal")
	}
	for _, binding := range []struct {
		device, audience string
		peer             ed25519.PublicKey
	}{{"other", "VPS-01", x.peer}, {"machine", "wrong-relay", x.peer}, {"machine", "VPS-01", ed25519.PublicKey(make([]byte, 32))}} {
		id, _ := security.NewID()
		now := time.Now()
		bad, _ := security.Sign("ticket", "issuer", x.key, security.Ticket{ID: id, DeviceID: binding.device, DeviceKey: security.Fingerprint(binding.peer), RelayID: binding.audience, IssuedAt: now, ExpiresAt: now.Add(time.Minute)})
		if ack := request(2, bad); ack.Status == 0 {
			t.Fatal("wrong renewal binding accepted", binding)
		}
	}
	// The same consumed renewal ticket cannot authenticate another QUIC session.
	if c, err := transport.DialWithTicket(ctx, x.server.Addr().String(), x.tls, raw); err == nil {
		c.Close()
		t.Fatal("cross-session replay accepted")
	}
	fresh, _ := x.ticket(ctx)
	approved := request(2, fresh)
	if approved.Status != 0 {
		t.Fatal("fresh ticket rejected")
	}
	renewals := x.server.Metrics.Renewals.Load()
	clientDeadline := x.client.Lease().Deadline
	x.verifier.Update(map[string]ed25519.PublicKey{"issuer": x.key.Public().(ed25519.PublicKey)}, []string{"machine"})
	fresh, _ = x.ticket(ctx)
	// Revocation guard and renewal control run independently. QUIC DATAGRAM
	// enqueue does not guarantee an ACK will arrive before CONNECTION_CLOSE.
	ack, revokeErr := requestResult(3, fresh)
	if !validRevocationOutcome(ack, revokeErr, 3, approved.Deadline) {
		t.Fatalf("revocation outcome invalid: status=%d sequence=%d err=%v", ack.Status, ack.Sequence, revokeErr)
	}
	select {
	case <-conn.Context().Done():
	case <-ctx.Done():
		t.Fatal("revoked live session survived")
	}
	if !exactRemoteRevocation(context.Cause(conn.Context())) {
		t.Fatalf("session closed without exact remote revoke: %v", context.Cause(conn.Context()))
	}
	if got := x.server.Metrics.Renewals.Load(); got != renewals {
		t.Fatalf("revocation extended authorization: renewals %d -> %d", renewals, got)
	}
	// Exercise the production client's error classifier on the other live
	// session, not only the raw QUIC test peer. No application reconnect.
	select {
	case <-x.client.Done():
	case <-ctx.Done():
		t.Fatal("production client missed revocation")
	}
	if x.client.SessionEndReason() != "device_revoked" || x.client.Lease().State != "device_revoked" {
		t.Fatal("production client lost revoke reason", x.client.SessionEndReason(), x.client.Lease())
	}
	if !x.client.Lease().Deadline.Equal(clientDeadline) {
		t.Fatal("revoked production client extended lease")
	}

}
func TestLeaseMultipleSessionsRenewIndependently(t *testing.T) {
	a := newLeaseFixture(t, 3*time.Second, 0)
	b := newLeaseFixture(t, 4*time.Second, 0)
	a.client.StartRenewal(a.ticket)
	b.client.StartRenewal(b.ticket)
	until := time.Now().Add(12 * time.Second)
	for (a.client.Lease().Renewals < 2 || b.client.Lease().Renewals < 2) && time.Now().Before(until) {
		time.Sleep(20 * time.Millisecond)
	}
	if a.client.Lease().Renewals < 2 || b.client.Lease().Renewals < 2 {
		t.Fatal(a.client.Lease(), b.client.Lease())
	}
}
func TestProtectedUDPRecoversAfterSessionDeath(t *testing.T) {
	cfg := transport.DefaultPoolConfig()
	x := newPoolFixture(t, cfg, nil)
	engine := routing.New(8)
	engine.SetRelay("VPS-01", x.pool)
	engine.SetPolicy("protected", routing.Policy{Route: routing.Route{RelayID: "VPS-01"}, BlockOnFailure: true})
	_, dst := leaseTargets(t)
	f := routing.Flow{Source: netip.MustParseAddrPort("127.0.0.1:19002"), Destination: dst, PID: 99, ProcessPath: "selected.exe", ApplicationID: "protected"}
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
	defer cancel()
	d, err := engine.OpenUDP(ctx, f)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	if err = d.Send([]byte("before")); err != nil {
		t.Fatal(err)
	}
	if _, err = d.Receive(ctx); err != nil {
		t.Fatal(err)
	}
	x.mu.Lock()
	old := x.clients[0]
	x.mu.Unlock()
	old.Close()
	<-old.Done()
	if err = d.Send([]byte("lost-not-replayed")); !errors.Is(err, routing.ErrUDPRecovering) {
		t.Fatal("loss not explicit", err)
	}
	ticker := time.NewTicker(120 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			t.Fatal("protected UDP remained blocked")
		case <-ticker.C:
		}
		if err = d.Send([]byte("after")); errors.Is(err, routing.ErrUDPRecovering) {
			continue
		} else if err != nil {
			t.Fatal(err)
		}
		b, err := d.Receive(ctx)
		if err != nil || string(b) != "after" {
			t.Fatal("fresh authenticated relay response", string(b), err)
		}
		break
	}
	if x.issued.Load() < 2 || engine.Snapshot()[0].Route.RelayID != "VPS-01" || len(engine.Snapshot()) != 1 {
		t.Fatal("route/recovery", x.pool.Snapshot(), engine.Snapshot())
	}
}

func TestLeaseRenewalWithUnreadTCPStreams(t *testing.T) {
	x := newLeaseFixture(t, 4*time.Second, 0)
	tcp, _ := leaseTargets(t)
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	var conns []net.Conn
	var writers sync.WaitGroup
	defer func() {
		for _, c := range conns {
			c.Close()
		}
		writers.Wait()
	}()
	for i := 0; i < 8; i++ {
		c, err := x.client.OpenTCP(ctx, tcp)
		if err != nil {
			t.Fatal(err)
		}
		conns = append(conns, c)
	}
	x.client.StartRenewal(x.ticket)
	for _, c := range conns {
		writers.Add(1)
		go func() {
			defer writers.Done()
			c.SetWriteDeadline(time.Now().Add(10 * time.Second))
			_, _ = c.Write(make([]byte, 2<<20))
		}()
	}
	// Never read echoes: eight stream receive windows exceed the bounded QUIC
	// connection receive credit. Renewal must not depend on that credit.
	for x.client.Lease().Renewals < 2 {
		select {
		case <-ctx.Done():
			t.Fatal("unread stream credit starved renewal", x.client.Lease())
		case <-x.client.Done():
			t.Fatal("session interrupted")
		case <-time.After(20 * time.Millisecond):
		}
	}
	if x.server.Metrics.TCPConnections.Load() != 8 || x.server.Metrics.LeaseExpiries.Load() != 0 {
		t.Fatal("application connections replaced/expired")
	}
}

func TestLeaseBlockedTicketFetcherCannotExtendAuthorization(t *testing.T) {
	x := newLeaseFixture(t, 2*time.Second, 0)
	release := make(chan struct{})
	defer close(release)
	x.client.StartRenewal(func(context.Context) ([]byte, error) { <-release; return nil, errors.New("blocked issuer") })
	select {
	case <-x.client.Done():
	case <-time.After(4 * time.Second):
		t.Fatal("blocked issuer extended authorization")
	}
	if x.client.SessionEndReason() != "authorization_lease_expired" {
		t.Fatal(x.client.SessionEndReason())
	}
}

func TestLeaseServerExpiresUncooperativeClient(t *testing.T) {
	x := newLeaseFixture(t, 2*time.Second, 0)
	_, dst := leaseTargets(t)
	d, err := x.client.OpenUDP(context.Background(), dst)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	// No client renewal/watchdog: the server itself must enforce authorization.
	until := time.NewTimer(5 * time.Second)
	defer until.Stop()
	tick := time.NewTicker(50 * time.Millisecond)
	defer tick.Stop()
	for {
		select {
		case <-x.client.Done():
			if x.server.Metrics.LeaseExpiries.Load() != 1 || x.client.SessionEndReason() != "authorization_lease_expired" {
				t.Fatal("server expiry missing", x.client.SessionEndReason())
			}
			return
		case <-until.C:
			t.Fatal("active traffic bypassed server lease expiry")
		case <-tick.C:
			_ = d.Send([]byte("active but not renewed"))
		}
	}
}

// Test-only predicate: no generic close/timeout/EOF counts as revocation proof.
func exactRemoteRevocation(err error) bool {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return false
	}
	var app *quic.ApplicationError
	return errors.As(err, &app) && app.Remote && app.ErrorCode == protocol.RevokedCode
}
func validRevocationOutcome(ack protocol.LeaseAck, err error, seq uint64, previous time.Time) bool {
	if err != nil {
		return exactRemoteRevocation(err)
	}
	return ack.Status != 0 && ack.Sequence == seq && !ack.Deadline.After(previous)
}
func TestLeaseRevocationOutcomeRejectsUnrelatedFailures(t *testing.T) {
	now := time.Now()
	revoke := &quic.ApplicationError{Remote: true, ErrorCode: protocol.RevokedCode, ErrorMessage: "device_revoked"}
	cases := []struct {
		name string
		ack  protocol.LeaseAck
		err  error
		want bool
	}{
		{name: "negative-ack", ack: protocol.LeaseAck{Status: 1, Sequence: 3}, want: true},
		{name: "exact-remote-revoke", err: fmt.Errorf("wrapped: %w", revoke), want: true},
		{name: "success-ack", ack: protocol.LeaseAck{Status: 0, Sequence: 3}},
		{name: "wrong-sequence", ack: protocol.LeaseAck{Status: 1, Sequence: 2}},
		{name: "lease-extension", ack: protocol.LeaseAck{Status: 1, Sequence: 3, Deadline: now.Add(time.Minute)}},
		{name: "timeout", err: context.DeadlineExceeded},
		{name: "cancel", err: context.Canceled},
		{name: "eof", err: io.EOF},
		{name: "other-code", err: &quic.ApplicationError{Remote: true, ErrorCode: protocol.LeaseExpiredCode}},
		{name: "local-revoke", err: &quic.ApplicationError{ErrorCode: protocol.RevokedCode}},
		{name: "timeout-with-revoke", err: errors.Join(context.DeadlineExceeded, revoke)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := validRevocationOutcome(tc.ack, tc.err, 3, now); got != tc.want {
				t.Fatalf("accepted=%v want=%v", got, tc.want)
			}
		})
	}
}
