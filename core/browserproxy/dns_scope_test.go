package browserproxy

import (
	"context"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"
)

func TestDNSRecoveryScopeRejectsObsoleteLookupAndProbe(t *testing.T) {
	for _, when := range []string{"before-lookup", "after-lookup", "during-probe"} {
		t.Run(when, func(t *testing.T) {
			r := NewDNSRecovery()
			var valid atomic.Bool
			valid.Store(when != "before-lookup")
			lookups, opens := 0, 0
			lookup := func(context.Context, string, DNSOpen) (DNSAnswer, error) {
				lookups++
				if when == "after-lookup" {
					valid.Store(false)
				}
				return DNSAnswer{Addresses: []netip.Addr{netip.MustParseAddr("8.8.8.8")}, TTL: time.Minute}, nil
			}
			open := func(context.Context, netip.AddrPort) (net.Conn, error) {
				opens++
				valid.Store(false)
				return nil, net.ErrClosed
			}
			got := r.RecoverScoped(context.Background(), "scope", "example.com", 443, nil, lookup, open, valid.Load)
			if got.Usable() || got.Failure != "DNS_RECOVERY_SCOPE_CHANGED" {
				t.Fatal("obsolete DNS result accepted", got)
			}
			if _, ok := r.Lookup("scope", time.Now()); ok {
				t.Fatal("obsolete DNS result cached")
			}
			if when == "before-lookup" && lookups != 0 || when != "during-probe" && opens != 0 || opens > 1 {
				t.Fatal("obsolete DNS triggered more work", lookups, opens)
			}
		})
	}
}

func TestDNSRecoveryScopeDropsLateVerifiedHTTP(t *testing.T) {
	var valid, invalidate atomic.Bool
	valid.Store(true)
	invalidate.Store(true)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if invalidate.Load() {
			valid.Store(false)
		}
		_, _ = io.WriteString(w, "verified response from previous scope")
	}))
	defer server.Close()
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	host := server.Certificate().DNSNames[0]
	lookup := func(context.Context, string, DNSOpen) (DNSAnswer, error) {
		return DNSAnswer{Addresses: []netip.Addr{netip.MustParseAddr("8.8.8.8")}, TTL: time.Minute}, nil
	}
	open := func(ctx context.Context, _ netip.AddrPort) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "tcp", server.Listener.Addr().String())
	}
	r := NewDNSRecovery()
	got := r.RecoverScoped(context.Background(), "scope", host, 443, roots, lookup, open, valid.Load)
	if got.Usable() || got.Failure != "DNS_RECOVERY_SCOPE_CHANGED" {
		t.Fatal("late verified response accepted", got)
	}
	if _, ok := r.Lookup("scope", time.Now()); ok {
		t.Fatal("late verified DNS cached")
	}
	valid.Store(true)
	invalidate.Store(false)
	got = r.RecoverScoped(context.Background(), "scope", host, 443, roots, lookup, open, valid.Load)
	if !got.Usable() || !got.Verified {
		t.Fatal("current verified response blocked", got)
	}
}

func TestDNSRecoveryScopeCancellationReleasesSingleflightWaiter(t *testing.T) {
	r := NewDNSRecovery()
	var valid atomic.Bool
	valid.Store(true)
	entered, release := make(chan struct{}), make(chan struct{})
	results := make(chan DNSRecoveryResult, 2)
	go func() {
		results <- r.RecoverScoped(context.Background(), "scope", "example.com", 443, nil, func(context.Context, string, DNSOpen) (DNSAnswer, error) {
			close(entered)
			<-release
			return DNSAnswer{}, errors.New("late old-network DNS failure")
		}, nil, valid.Load)
	}()
	<-entered
	ctx := &originScopeWaitContext{Context: context.Background(), entered: make(chan struct{})}
	go func() { results <- r.Recover(ctx, "scope", "example.com", 443, nil, nil, nil) }()
	<-ctx.entered
	valid.Store(false)
	close(release)
	for i := 0; i < 2; i++ {
		if got := <-results; got.Usable() || got.Failure != "DNS_RECOVERY_SCOPE_CHANGED" {
			t.Fatal("waiter accepted an obsolete result", got)
		}
	}
	if _, ok := r.Lookup("scope", time.Now()); ok {
		t.Fatal("stale cooldown remained cached")
	}
	calls := 0
	r.Recover(context.Background(), "scope", "example.com", 443, nil, func(context.Context, string, DNSOpen) (DNSAnswer, error) {
		calls++
		return DNSAnswer{}, errors.New("fresh lookup")
	}, nil)
	if calls != 1 {
		t.Fatal("new flow inherited stale cooldown")
	}
}
