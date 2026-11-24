package browserproxy

import (
	"bytes"
	"context"
	"errors"
	"github.com/buzzmean/veliq/core/flowpolicy"
	"github.com/quic-go/quic-go"
	"io"
	"net"
	"net/netip"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

var retryServerHello = append([]byte{22, 3, 3, 0, 42, 2, 0, 0, 38}, make([]byte, 38)...)

var retryHello = []byte{22, 3, 1, 0, 7, 1, 0, 0, 3, 1, 2, 3}

func originFixture(t *testing.T, kind string, reply []byte) net.Conn {
	t.Helper()
	a, b := net.Pipe()
	t.Cleanup(func() { a.Close(); b.Close() })
	go func() {
		defer b.Close()
		got := make([]byte, len(retryHello))
		if _, e := io.ReadFull(b, got); e != nil {
			return
		}
		if !bytes.Equal(got, retryHello) {
			return
		}
		if kind == "silent" {
			var one [1]byte
			b.Read(one[:])
			return
		}
		if kind == "reply" {
			b.Write(reply)
		}
	}()
	return a
}
func TestRelayOriginSilenceOrEOFRecoversOnlyClientHello(t *testing.T) {
	for _, kind := range []string{"silent", "eof"} {
		t.Run(kind, func(t *testing.T) {
			h := NewOriginHealth()
			one := netip.MustParseAddrPort("8.8.8.8:443")
			two := netip.MustParseAddrPort("8.8.4.4:443")
			calls := 0
			x := WatchRelayOrigin(originFixture(t, kind, nil), OriginConfig{Context: context.Background(), Health: h, Scope: "network/profile/web.telegram.org/443/relay", Initial: one, Candidates: []netip.AddrPort{one, two}, Open: func(context.Context, netip.AddrPort) (net.Conn, error) {
				calls++
				return originFixture(t, "reply", retryServerHello), nil
			}})
			defer x.Close()
			x.SetDeadline(time.Now().Add(3 * time.Second))
			if _, err := x.Write(retryHello); err != nil {
				t.Fatal(err)
			}
			got, err := io.ReadAll(x)
			if err != nil || !bytes.Equal(got, retryServerHello) || calls != 1 {
				t.Fatal(got, err, calls)
			}
			r := x.(OriginReporter).OriginAttempts()
			if r.AddressAttempts != 2 || r.Selected != two.String() || r.ReplayedBytes != uint64(len(retryHello)) {
				t.Fatal(r)
			}
			if ip, _ := h.Pick("network/profile/web.telegram.org/443/relay", []netip.AddrPort{one, two}, nil, time.Now()); ip != two {
				t.Fatal(ip)
			}
		})
	}
}
func TestRelayOriginNeverReplaysAfterAnyOriginByte(t *testing.T) {
	for _, reply := range [][]byte{{21}, {21, 3, 3, 0, 2}, {21, 3, 3, 0, 2, 2, 40}} {
		t.Run(string(reply), func(t *testing.T) {
			h := NewOriginHealth()
			one := netip.MustParseAddrPort("8.8.8.8:443")
			var calls atomic.Int32
			x := WatchRelayOrigin(originFixture(t, "reply", reply), OriginConfig{Context: context.Background(), Health: h, Scope: "test", Initial: one, Open: func(context.Context, netip.AddrPort) (net.Conn, error) {
				calls.Add(1)
				return nil, errors.New("must not open")
			}})
			defer x.Close()
			x.Write(retryHello)
			got, err := io.ReadAll(x)
			if err != nil || !bytes.Equal(got, reply) || calls.Load() != 0 {
				t.Fatal(got, err, calls.Load())
			}
			if ip, _ := h.Pick("test", []netip.AddrPort{one}, nil, time.Now()); ip.IsValid() {
				t.Fatal("early EOF/alert not quarantined")
			}
		})
	}
}
func TestRelayOriginLimitsAndUnsafeFlight(t *testing.T) {
	for _, unsafe := range []bool{false, true} {
		t.Run(map[bool]string{false: "three_addresses", true: "early_data_no_replay"}[unsafe], func(t *testing.T) {
			one := netip.MustParseAddrPort("8.8.8.8:443")
			h := NewOriginHealth()
			calls := 0
			a, b := net.Pipe()
			defer b.Close()
			go io.Copy(io.Discard, b)
			x := WatchRelayOrigin(a, OriginConfig{Context: context.Background(), Health: h, Scope: "test", Initial: one, Candidates: []netip.AddrPort{one, netip.MustParseAddrPort("8.8.4.4:443"), netip.MustParseAddrPort("1.1.1.1:443"), netip.MustParseAddrPort("9.9.9.9:443")}, Open: func(context.Context, netip.AddrPort) (net.Conn, error) {
				calls++
				return originFixture(t, "eof", nil), nil
			}})
			defer x.Close()
			flight := append([]byte(nil), retryHello...)
			if unsafe {
				flight = append(flight, 23, 3, 3, 0, 1, 42)
			}
			x.Write(flight)
			start := time.Now()
			_, err := io.ReadAll(x)
			if err == nil {
				t.Fatal("unavailable origins accepted")
			}
			if unsafe && (calls != 0 || !errors.Is(err, ErrOriginReplayUnsafe)) {
				t.Fatal(calls, err)
			}
			if !unsafe && calls != 2 {
				t.Fatal("attempt budget not enforced", calls, err)
			}
			if time.Since(start) > OriginRecoveryBudget+time.Second {
				t.Fatal("budget exceeded")
			}
		})
	}
}
func TestRelayOriginUsesIndependentDNSAndDoesNotRepeatTriedAddress(t *testing.T) {
	h := NewOriginHealth()
	one := netip.MustParseAddrPort("8.8.8.8:443")
	two := netip.MustParseAddrPort("8.8.4.4:443")
	lookups := 0
	x := WatchRelayOrigin(originFixture(t, "eof", nil), OriginConfig{Context: context.Background(), Health: h, Scope: "test", Initial: one, Resolve: func(context.Context) (DNSAnswer, error) {
		lookups++
		return DNSAnswer{Addresses: []netip.Addr{one.Addr(), two.Addr()}}, nil
	}, Open: func(_ context.Context, ip netip.AddrPort) (net.Conn, error) {
		if ip != two {
			t.Fatal(ip)
		}
		return originFixture(t, "reply", retryServerHello), nil
	}})
	defer x.Close()
	x.Write(retryHello)
	_, err := io.ReadAll(x)
	if err != nil || lookups != 1 || x.(OriginReporter).OriginAttempts().DNS != "RELAY_DOH" {
		t.Fatal(err, lookups, x.(OriginReporter).OriginAttempts())
	}
}
func TestOriginNegativeTTLAndNetworkProfileDomainScope(t *testing.T) {
	h := NewOriginHealth()
	one := netip.MustParseAddrPort("8.8.8.8:443")
	now := time.Now()
	h.Failed("networkA/profileA/domainA/443/relay", one, now)
	if ip, _ := h.Pick("networkA/profileA/domainA/443/relay", []netip.AddrPort{one}, nil, now); ip.IsValid() {
		t.Fatal(ip)
	}
	if ip, _ := h.Pick("networkB/profileA/domainA/443/relay", []netip.AddrPort{one}, nil, now); ip != one {
		t.Fatal("cache escaped network scope")
	}
	if ip, _ := h.Pick("networkA/profileA/domainA/443/relay", []netip.AddrPort{one}, nil, now.Add(OriginNegativeTTL)); ip != one {
		t.Fatal("negative did not expire")
	}
	for i := 0; i < 2000; i++ {
		h.Failed(string(rune(i)), one, now)
	}
	if len(h.bad) > 1024 {
		t.Fatal("unbounded negatives")
	}
}

func TestOriginDNSCacheSingleflightTTLAndFailureCooldown(t *testing.T) {
	h := NewOriginHealth()
	calls := 0
	lookup := func(context.Context) (DNSAnswer, error) {
		calls++
		return DNSAnswer{Addresses: []netip.Addr{netip.MustParseAddr("8.8.4.4")}, TTL: time.Minute, ObtainedAt: time.Now()}, nil
	}
	for i := 0; i < 2; i++ {
		a, e := h.Resolve(context.Background(), "net/profile/domain", lookup)
		if e != nil || len(a.Addresses) != 1 {
			t.Fatal(a, e)
		}
		a.Addresses[0] = netip.MustParseAddr("1.1.1.1")
	}
	if calls != 1 {
		t.Fatal(calls)
	}
	h.mu.Lock()
	h.dns["net/profile/domain"].until = time.Now().Add(-time.Second)
	h.mu.Unlock()
	h.Resolve(context.Background(), "net/profile/domain", lookup)
	if calls != 2 {
		t.Fatal("DNS TTL not respected", calls)
	}
	fail := func(context.Context) (DNSAnswer, error) {
		calls++
		return DNSAnswer{}, errors.New("fixture unavailable")
	}
	for i := 0; i < 2; i++ {
		if _, err := h.Resolve(context.Background(), "fail", fail); err == nil {
			t.Fatal("negative DNS lost its error")
		}
	}
	if calls != 3 {
		t.Fatal("negative DNS cooldown ignored", calls)
	}
}

func TestOriginCancellationDeadlineAndLateExpiryCannotKillAnsweredFlow(t *testing.T) {
	a, b := net.Pipe()
	defer b.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	x := WatchRelayOrigin(a, OriginConfig{Context: ctx, Health: NewOriginHealth(), Initial: netip.MustParseAddrPort("8.8.8.8:443")}).(*originConn)
	defer x.Close()
	x.mu.Lock()
	x.responded = true
	x.progressed = true
	x.mu.Unlock()
	x.closeWithReason("RECOVERY_BUDGET_EXPIRED", true)
	x.mu.Lock()
	closed := x.closed
	x.mu.Unlock()
	if closed {
		t.Fatal("late expiry closed answered flow")
	}
	x.SetReadDeadline(time.Now().Add(20 * time.Millisecond))
	start := time.Now()
	var p [1]byte
	_, err := x.Read(p[:])
	if err == nil || time.Since(start) > time.Second {
		t.Fatal("caller deadline lost", err)
	}
	cancel()
	select {
	case <-x.done:
	case <-time.After(time.Second):
		t.Fatal("cancel leaked live connection")
	}
}

type alreadyClosedOrigin struct{ net.Conn }

func (alreadyClosedOrigin) Read([]byte) (int, error)         { return 0, io.EOF }
func (alreadyClosedOrigin) Write([]byte) (int, error)        { return 0, syscall.EPIPE }
func (alreadyClosedOrigin) Close() error                     { return nil }
func (alreadyClosedOrigin) SetReadDeadline(time.Time) error  { return nil }
func (alreadyClosedOrigin) SetWriteDeadline(time.Time) error { return nil }
func (alreadyClosedOrigin) SetDeadline(time.Time) error      { return nil }
func TestOriginConcurrentEarlyReadAndWriteClosureRetriesExactlyOnce(t *testing.T) {
	for i := 0; i < 20; i++ {
		var opens atomic.Int32
		one := netip.MustParseAddrPort("8.8.8.8:443")
		two := netip.MustParseAddrPort("8.8.4.4:443")
		x := WatchRelayOrigin(alreadyClosedOrigin{}, OriginConfig{Context: context.Background(), Health: NewOriginHealth(), Initial: one, Candidates: []netip.AddrPort{one, two}, Open: func(context.Context, netip.AddrPort) (net.Conn, error) {
			opens.Add(1)
			return originFixture(t, "reply", retryServerHello), nil
		}})
		done := make(chan error, 1)
		go func() { _, err := x.Write(retryHello); done <- err }()
		body, err := io.ReadAll(x)
		writeErr := <-done
		x.Close()
		if err != nil || writeErr != nil || len(body) != len(retryServerHello) || opens.Load() != 1 {
			t.Fatal(i, err, writeErr, len(body), opens.Load())
		}
	}
}

func TestOriginHardBudgetClosesUnconsumedHandshake(t *testing.T) {
	a, b := net.Pipe()
	defer b.Close()
	go io.Copy(io.Discard, b)
	x := WatchRelayOrigin(a, OriginConfig{Context: context.Background(), Health: NewOriginHealth(), Initial: netip.MustParseAddrPort("8.8.8.8:443")}).(*originConn)
	defer x.Close()
	x.Write(retryHello)
	select {
	case <-x.done:
	case <-time.After(OriginRecoveryBudget + time.Second):
		t.Fatal("unbounded unanswered handshake")
	}
	if x.OriginAttempts().State != "RECOVERY_BUDGET_EXPIRED" {
		t.Fatal(x.OriginAttempts())
	}
}
func TestRetargetCannotInheritAnotherIPsVerifiedHTTP(t *testing.T) {
	one := netip.MustParseAddrPort("8.8.8.8:443")
	two := netip.MustParseAddrPort("8.8.4.4:443")
	p := Plan{Destination: one, Probe: "DNS_RELAY_HTTP_VERIFIED", HTTPStatus: 200, DNSRecovery: &DNSRecoveryResult{Verified: true, Destination: one}, Policy: flowpolicy.Result{Action: flowpolicy.RelayRequired, Fallback: flowpolicy.Required, RelayID: "VPS-01", Source: "browser_dns_recovered"}}
	next := RetargetOrigin(p, two)
	if next.Destination != two || next.HTTPStatus != 0 || next.DNSRecovery != nil || next.Policy.Action != p.Policy.Action || next.Policy.Fallback != p.Policy.Fallback || next.Policy.RelayID != p.Policy.RelayID {
		t.Fatal(next)
	}
}

type sessionFailedOrigin struct{ alreadyClosedOrigin }

func (sessionFailedOrigin) Read([]byte) (int, error) {
	return 0, &quic.ApplicationError{ErrorCode: 11, ErrorMessage: "device_revoked"}
}
func (sessionFailedOrigin) Write(p []byte) (int, error) { return len(p), nil }
func TestOriginSessionFailureDoesNotPoisonIPOrAttemptDNS(t *testing.T) {
	h := NewOriginHealth()
	one := netip.MustParseAddrPort("8.8.8.8:443")
	var calls atomic.Int32
	x := WatchRelayOrigin(sessionFailedOrigin{}, OriginConfig{Context: context.Background(), Health: h, Scope: "test", Initial: one, Resolve: func(context.Context) (DNSAnswer, error) { calls.Add(1); return DNSAnswer{}, nil }})
	defer x.Close()
	x.Write(retryHello)
	_, err := io.ReadAll(x)
	if err == nil || calls.Load() != 0 {
		t.Fatal(err, calls.Load())
	}
	if ip, _ := h.Pick("test", []netip.AddrPort{one}, nil, time.Now()); ip != one {
		t.Fatal("session error quarantined IP")
	}
}

func TestOriginPartialTLSHeaderNeverReplaysOrWaitsIndefinitely(t *testing.T) {
	a, b := net.Pipe()
	defer b.Close()
	one := netip.MustParseAddrPort("8.8.8.8:443")
	h := NewOriginHealth()
	var calls atomic.Int32
	x := WatchRelayOrigin(a, OriginConfig{Context: context.Background(), Health: h, Scope: "partial", Initial: one, Open: func(context.Context, netip.AddrPort) (net.Conn, error) {
		calls.Add(1)
		return nil, errors.New("no replay after header")
	}})
	defer x.Close()
	go func() {
		p := make([]byte, len(retryHello))
		io.ReadFull(b, p)
		b.Write([]byte{21, 3, 3, 0, 2})
		io.Copy(io.Discard, b)
	}()
	x.Write(retryHello)
	start := time.Now()
	data, err := io.ReadAll(x)
	if len(data) != 5 || err == nil || calls.Load() != 0 || time.Since(start) > OriginRecoveryBudget+time.Second {
		t.Fatal(data, err, calls.Load())
	}
	if ip, _ := h.Pick("partial", []netip.AddrPort{one}, nil, time.Now()); ip.IsValid() {
		t.Fatal("partial reply timeout not quarantined")
	}
}

func TestOriginRecoveryPreservesLargeFragmentedClientHelloByteForByte(t *testing.T) {
	// Two TLS records hold one 2048-byte ClientHello. Only framing is relevant to
	// replay safety; no HTTPS decryption or extension re-encoding is permitted.
	handshake := make([]byte, 2052)
	handshake[0] = 1
	handshake[1] = 0
	handshake[2] = 8
	handshake[3] = 0
	for i := 4; i < len(handshake); i++ {
		handshake[i] = byte(i * 31)
	}
	flight := append([]byte{22, 3, 1, 4, 0}, handshake[:1024]...)
	flight = append(flight, []byte{22, 3, 3, 4, 4}...)
	flight = append(flight, handshake[1024:]...)
	received := make(chan []byte, 2)
	endpoint := func(reply bool) net.Conn {
		a, b := net.Pipe()
		go func() {
			defer b.Close()
			raw := make([]byte, len(flight))
			if _, e := io.ReadFull(b, raw); e != nil {
				return
			}
			received <- raw
			if reply {
				b.Write(retryServerHello)
			}
		}()
		return a
	}
	one := netip.MustParseAddrPort("8.8.8.8:443")
	two := netip.MustParseAddrPort("8.8.4.4:443")
	x := WatchRelayOrigin(endpoint(false), OriginConfig{Context: context.Background(), Health: NewOriginHealth(), Scope: "large-hello", Initial: one, Candidates: []netip.AddrPort{one, two}, Open: func(context.Context, netip.AddrPort) (net.Conn, error) { return endpoint(true), nil }})
	defer x.Close()
	x.SetDeadline(time.Now().Add(3 * time.Second))
	for _, part := range [][]byte{flight[:300], flight[300:1400], flight[1400:]} {
		if _, e := x.Write(part); e != nil {
			t.Fatal(e)
		}
	}
	if body, e := io.ReadAll(x); e != nil || len(body) != len(retryServerHello) {
		t.Fatal(e, len(body))
	}
	for i := 0; i < 2; i++ {
		select {
		case got := <-received:
			if !bytes.Equal(got, flight) {
				t.Fatal("TLS stream changed during forwarding/retry")
			}
		case <-time.After(time.Second):
			t.Fatal("missing initial/retried flight")
		}
	}
	if report := x.(OriginReporter).OriginAttempts(); report.ReplayedBytes != uint64(len(flight)) || report.AddressAttempts != 2 {
		t.Fatal(report)
	}
}
