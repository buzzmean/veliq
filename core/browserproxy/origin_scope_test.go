package browserproxy

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestOriginScopeInvalidationStopsLearningAndRecovery(t *testing.T) {
	for _, stage := range []string{"before-failure", "during-dns", "failed-open", "successful-open"} {
		t.Run(stage, func(t *testing.T) {
			h := NewOriginHealth()
			one, two := netip.MustParseAddrPort("8.8.8.8:443"), netip.MustParseAddrPort("8.8.4.4:443")
			var valid atomic.Bool
			valid.Store(true)
			var lookups, opens, failures atomic.Int32
			var latePeer net.Conn
			cfg := OriginConfig{Context: context.Background(), Health: h, Scope: "original", Initial: one, ScopeCurrent: valid.Load, RetryOpen: func(error) bool { return true }, OnFailure: func(string) { failures.Add(1) }}
			cfg.Resolve = func(context.Context) (DNSAnswer, error) {
				lookups.Add(1)
				valid.Store(false)
				return DNSAnswer{Addresses: []netip.Addr{two.Addr()}}, nil
			}
			cfg.Open = func(context.Context, netip.AddrPort) (net.Conn, error) {
				opens.Add(1)
				valid.Store(false)
				if stage == "successful-open" {
					a, peer := net.Pipe()
					latePeer = peer
					return a, nil
				}
				return nil, context.DeadlineExceeded
			}
			if stage != "during-dns" {
				cfg.Candidates = []netip.AddrPort{one, two}
			}
			x := WatchRelayOrigin(originFixture(t, "eof", nil), cfg)
			defer x.Close()
			x.SetDeadline(time.Now().Add(time.Second))
			if _, err := x.Write(retryHello); err != nil {
				t.Fatal(err)
			}
			if stage == "before-failure" {
				valid.Store(false)
			}
			_, err := io.ReadAll(x)
			if !errors.Is(err, ErrOriginScopeChanged) || x.(OriginReporter).OriginAttempts().ReplayedBytes != 0 {
				t.Fatal("obsolete scope continued", err, x.(OriginReporter).OriginAttempts())
			}
			if stage == "before-failure" {
				selected, _ := h.Pick("original", []netip.AddrPort{one}, nil, time.Now())
				if selected != one || lookups.Load() != 0 || opens.Load() != 0 || failures.Load() != 0 {
					t.Fatal("obsolete first failure was learned", selected, lookups.Load(), opens.Load(), failures.Load())
				}
			} else {
				selected, _ := h.Pick("original", []netip.AddrPort{two}, nil, time.Now())
				if selected != two || failures.Load() != 1 {
					t.Fatal("late failure was learned", selected, failures.Load())
				}
				if stage == "during-dns" && (lookups.Load() != 1 || opens.Load() != 0) {
					t.Fatal("stale DNS result opened another peer", lookups.Load(), opens.Load())
				}
			}
			if latePeer != nil {
				defer latePeer.Close()
				latePeer.SetReadDeadline(time.Now().Add(time.Second))
				var b [1]byte
				if n, err := latePeer.Read(b[:]); n != 0 || !errors.Is(err, io.EOF) {
					t.Fatal("late successful socket not closed before payload", n, err)
				}
			}
		})
	}
}

func TestOriginScopeDoesNotQuarantineLatePartialReply(t *testing.T) {
	h := NewOriginHealth()
	one := netip.MustParseAddrPort("8.8.8.8:443")
	var valid atomic.Bool
	valid.Store(true)
	var failures atomic.Int32
	x := WatchRelayOrigin(originFixture(t, "reply", []byte{21}), OriginConfig{Context: context.Background(), Health: h, Scope: "test", Initial: one, ScopeCurrent: valid.Load, OnFailure: func(string) { failures.Add(1) }})
	defer x.Close()
	x.Write(retryHello)
	var b [1]byte
	if n, err := x.Read(b[:]); n != 1 || err != nil {
		t.Fatal(n, err)
	}
	valid.Store(false)
	// The real recovery timer calls this exact branch after a partial response.
	x.(*originConn).closeWithReason("RECOVERY_BUDGET_EXPIRED", true)
	selected, _ := h.Pick("test", []netip.AddrPort{one}, nil, time.Now())
	if selected != one || failures.Load() != 0 {
		t.Fatal("stale partial response changed health", selected, failures.Load())
	}
}

func TestOriginScopeConcurrentRetryKeepsRespondedStreamPinned(t *testing.T) {
	a, peer := net.Pipe()
	defer peer.Close()
	var valid atomic.Bool
	valid.Store(true)
	x := WatchRelayOrigin(a, OriginConfig{Context: context.Background(), Health: NewOriginHealth(), Scope: "test", Initial: netip.MustParseAddrPort("8.8.8.8:443"), ScopeCurrent: valid.Load})
	defer x.Close()
	x.SetDeadline(time.Now().Add(2 * time.Second))
	payload := []byte("established stream remains pinned")
	got := make(chan []byte, 1)
	go func() {
		_, _ = io.CopyN(io.Discard, peer, int64(len(retryHello)))
		_, _ = peer.Write(retryServerHello)
		data := make([]byte, len(payload))
		_, _ = io.ReadFull(peer, data)
		got <- data
	}()
	if _, err := x.Write(retryHello); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(x, make([]byte, len(retryServerHello))); err != nil {
		t.Fatal(err)
	}
	valid.Store(false)
	// A failed writer can have waited for readGate while this reader committed
	// the first reply. Its delayed retry must honor responded before scope abort.
	err := x.(*originConn).retry(a, "ORIGIN_EARLY_WRITE_CLOSED", true)
	if !errors.Is(err, net.ErrClosed) {
		t.Fatal("late retry did not preserve the established-stream invariant", err)
	}
	if _, err := x.Write(payload); err != nil {
		t.Fatal("scope guard closed an established stream", err)
	}
	if data := <-got; string(data) != string(payload) {
		t.Fatal("established payload changed", string(data))
	}
}

type originScopeWaitContext struct {
	context.Context
	entered chan struct{}
	once    sync.Once
}

func (c *originScopeWaitContext) Done() <-chan struct{} {
	c.once.Do(func() { close(c.entered) })
	return c.Context.Done()
}

func TestOriginDNSDoesNotCacheScopeCancellationForWaiters(t *testing.T) {
	h := NewOriginHealth()
	entered, release := make(chan struct{}), make(chan struct{})
	results := make(chan error, 2)
	go func() {
		a, err := h.Resolve(context.Background(), "same", func(context.Context) (DNSAnswer, error) {
			close(entered)
			<-release
			return DNSAnswer{Addresses: []netip.Addr{netip.MustParseAddr("8.8.8.8")}, TTL: time.Minute}, ErrOriginScopeChanged
		})
		if len(a.Addresses) != 0 {
			err = errors.New("cancelled answer escaped to primary")
		}
		results <- err
	}()
	<-entered
	ctx := &originScopeWaitContext{Context: context.Background(), entered: make(chan struct{})}
	go func() {
		a, err := h.Resolve(ctx, "same", func(context.Context) (DNSAnswer, error) { return DNSAnswer{}, errors.New("duplicate lookup") })
		if len(a.Addresses) != 0 {
			err = errors.New("cancelled answer escaped to waiter")
		}
		results <- err
	}()
	<-ctx.entered
	close(release)
	for i := 0; i < 2; i++ {
		if err := <-results; !errors.Is(err, ErrOriginScopeChanged) {
			t.Fatal(err)
		}
	}
	calls := 0
	answer, err := h.Resolve(context.Background(), "same", func(context.Context) (DNSAnswer, error) {
		calls++
		return DNSAnswer{Addresses: []netip.Addr{netip.MustParseAddr("8.8.4.4")}, TTL: time.Minute}, nil
	})
	if err != nil || calls != 1 || len(answer.Addresses) != 1 {
		t.Fatal("cancelled scope result persisted", calls, answer, err)
	}
}
