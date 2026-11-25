package browserproxy

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/buzzmean/veliq/core/flowpolicy"
	"github.com/buzzmean/veliq/core/routing"
)

// listener helpers -----------------------------------------------------------------

type recorded struct {
	mu   sync.Mutex
	data []byte
}

func (r *recorded) add(b []byte) { r.mu.Lock(); r.data = append(r.data, b...); r.mu.Unlock() }
func (r *recorded) get() string  { r.mu.Lock(); defer r.mu.Unlock(); return string(r.data) }

// silentOrigin accepts, reads and records everything, and never answers (a DPI blackhole).
func silentOrigin(t *testing.T, reset bool) (string, *recorded) {
	t.Helper()
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	rec := &recorded{}
	go func() {
		for {
			c, e := l.Accept()
			if e != nil {
				return
			}
			go func() {
				buf := make([]byte, 4096)
				n, _ := c.Read(buf)
				rec.add(buf[:n])
				if reset {
					c.(*net.TCPConn).SetLinger(0)
					c.Close()
					return
				}
				io.Copy(io.Discard, c)
			}()
		}
	}()
	return l.Addr().String(), rec
}

// answeringOrigin replies "SERVER-HELLO" to the first bytes it receives.
func answeringOrigin(t *testing.T) (string, *recorded) {
	t.Helper()
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	rec := &recorded{}
	go func() {
		for {
			c, e := l.Accept()
			if e != nil {
				return
			}
			go func() {
				defer c.Close()
				buf := make([]byte, 4096)
				n, e := c.Read(buf)
				if n > 0 {
					rec.add(buf[:n])
					c.Write([]byte("SERVER-HELLO"))
				}
				_ = e
				io.Copy(io.Discard, c)
			}()
		}
	}()
	return l.Addr().String(), rec
}

type stallHarness struct {
	server  *Server
	stalls  atomic.Int32
	plans   chan Plan
	stallFn func(context.Context, Request, Plan) (net.Conn, Plan, error)
}

func newStallProxy(t *testing.T, direct string, action flowpolicy.Action, timeout time.Duration, onStall func(context.Context, Request, Plan) (net.Conn, Plan, error)) *stallHarness {
	t.Helper()
	h := &stallHarness{plans: make(chan Plan, 4)}
	h.stallFn = onStall
	cfg := Config{
		Authorize: func(context.Context, netip.AddrPort, netip.AddrPort) (Owner, error) { return Owner{PID: 1}, nil },
		Plan: func(context.Context, Request) (Plan, error) {
			return Plan{Enabled: true, Policy: flowpolicy.Result{Action: action}}, nil
		},
		Open: func(ctx context.Context, _ Request, _ Plan) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "tcp", direct)
		},
		StallTimeout: timeout,
	}
	if onStall != nil {
		cfg.OnStall = func(ctx context.Context, q Request, p Plan) (net.Conn, Plan, error) {
			h.stalls.Add(1)
			return h.stallFn(ctx, q, p)
		}
	}
	s, err := Listen(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	h.server = s
	return h
}

func connectVia(t *testing.T, proxy, target string) (net.Conn, *bufio.Reader) {
	t.Helper()
	c, err := net.Dial("tcp", proxy)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	c.SetDeadline(time.Now().Add(6 * time.Second))
	fmt.Fprintf(c, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target)
	r := bufio.NewReader(c)
	resp, err := http.ReadResponse(r, &http.Request{Method: "CONNECT"})
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("CONNECT failed: %v %v", resp, err)
	}
	return c, r
}

func relayDialer(addr string) func(context.Context, Request, Plan) (net.Conn, Plan, error) {
	return func(ctx context.Context, _ Request, p Plan) (net.Conn, Plan, error) {
		c, err := (&net.Dialer{}).DialContext(ctx, "tcp", addr)
		p.Policy = flowpolicy.Result{Action: flowpolicy.RelayRequired, RelayID: "VPS-01", Fallback: flowpolicy.Required, Source: "direct_stall_retry"}
		return c, p, err
	}
}

// tests ---------------------------------------------------------------------------

func TestStalledDirectTunnelIsRetriedViaRelayBeforeTheBrowserSeesAnError(t *testing.T) {
	for _, reset := range []bool{false, true} {
		t.Run(fmt.Sprintf("reset=%v", reset), func(t *testing.T) {
			dead, deadSaw := silentOrigin(t, reset)
			relay, relaySaw := answeringOrigin(t)
			h := newStallProxy(t, dead, flowpolicy.Direct, 150*time.Millisecond, relayDialer(relay))
			c, r := connectVia(t, h.server.Address(), "www.youtube.com:443")
			started := time.Now()
			fmt.Fprint(c, "CLIENT-HELLO-1923-BYTES")
			got := make([]byte, len("SERVER-HELLO"))
			if _, err := io.ReadFull(r, got); err != nil || string(got) != "SERVER-HELLO" {
				t.Fatalf("browser did not get the relay's answer: %q %v", got, err)
			}
			if d := time.Since(started); d > 3*time.Second {
				t.Fatalf("retry took too long: %v", d)
			}
			if h.stalls.Load() != 1 {
				t.Fatalf("OnStall called %d times", h.stalls.Load())
			}
			if relaySaw.get() != "CLIENT-HELLO-1923-BYTES" {
				t.Fatalf("relay got %q: the first flight must be replayed exactly once", relaySaw.get())
			}
			if deadSaw.get() != "CLIENT-HELLO-1923-BYTES" {
				t.Fatalf("direct origin saw %q", deadSaw.get())
			}
			// Later client bytes reach the new upstream only.
			fmt.Fprint(c, "MORE")
			time.Sleep(100 * time.Millisecond)
			if relaySaw.get() != "CLIENT-HELLO-1923-BYTES" && relaySaw.get() != "CLIENT-HELLO-1923-BYTESMORE" {
				t.Fatalf("relay stream corrupted: %q", relaySaw.get())
			}
			snap := h.server.Snapshot()
			if snap.Failures["DIRECT_STALL"] != 1 || snap.Failures["DIRECT_STALL_RETRIED_VIA_RELAY"] != 1 {
				t.Fatalf("stall not visible in diagnostics: %+v", snap.Failures)
			}
			if len(snap.Records) != 1 || !snap.Records[0].StallRetried || snap.Records[0].Plan.Policy.Action != flowpolicy.RelayRequired {
				t.Fatalf("record does not show the retry: %+v", snap.Records)
			}
		})
	}
}

func TestResponsiveOriginNeverTriggersStallRetry(t *testing.T) {
	good, _ := answeringOrigin(t)
	relay, relaySaw := answeringOrigin(t)
	h := newStallProxy(t, good, flowpolicy.Direct, 150*time.Millisecond, relayDialer(relay))
	c, r := connectVia(t, h.server.Address(), "ordinary.example:443")
	fmt.Fprint(c, "HELLO")
	got := make([]byte, 12)
	if _, err := io.ReadFull(r, got); err != nil || string(got) != "SERVER-HELLO" {
		t.Fatal(string(got), err)
	}
	time.Sleep(400 * time.Millisecond) // well past the stall timeout
	if h.stalls.Load() != 0 || relaySaw.get() != "" {
		t.Fatalf("healthy origin was retried: stalls=%d relay=%q", h.stalls.Load(), relaySaw.get())
	}
}

func TestServerSpeaksFirstProtocolIsNotAStall(t *testing.T) {
	l, _ := net.Listen("tcp4", "127.0.0.1:0")
	defer l.Close()
	go func() {
		c, err := l.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		time.Sleep(500 * time.Millisecond) // slower than the stall timeout, but the client never spoke
		c.Write([]byte("BANNER"))
		io.Copy(io.Discard, c)
	}()
	relay, _ := answeringOrigin(t)
	h := newStallProxy(t, l.Addr().String(), flowpolicy.Direct, 150*time.Millisecond, relayDialer(relay))
	c, r := connectVia(t, h.server.Address(), "banner.example:443")
	got := make([]byte, 6)
	if _, err := io.ReadFull(r, got); err != nil || string(got) != "BANNER" {
		t.Fatal(string(got), err)
	}
	if h.stalls.Load() != 0 {
		t.Fatal("timer must start at the client's first byte, not at tunnel start")
	}
	_ = c
}

func TestFailedRetryClosesTheTunnelAndNeverFallsBackToDirect(t *testing.T) {
	dead, deadSaw := silentOrigin(t, false)
	h := newStallProxy(t, dead, flowpolicy.Direct, 120*time.Millisecond, func(context.Context, Request, Plan) (net.Conn, Plan, error) {
		return nil, Plan{}, errors.New("relay unavailable")
	})
	c, r := connectVia(t, h.server.Address(), "www.youtube.com:443")
	fmt.Fprint(c, "HELLO")
	if _, err := r.ReadByte(); err == nil {
		t.Fatal("tunnel stayed open after the retry failed")
	}
	if h.stalls.Load() != 1 {
		t.Fatalf("stalls=%d", h.stalls.Load())
	}
	if deadSaw.get() != "HELLO" {
		t.Fatalf("direct origin saw %q", deadSaw.get())
	}
}

func TestRetryIsLimitedToOrdinaryDirectPort443(t *testing.T) {
	relay, _ := answeringOrigin(t)
	cases := map[string]struct {
		action flowpolicy.Action
		target string
	}{
		"relay-required (protected) stays relay": {flowpolicy.RelayRequired, "chatgpt.com:443"},
		"DIRECT+ is left to its own logic":       {flowpolicy.DirectPlus, "www.youtube.com:443"},
		"non-443 port":                           {flowpolicy.Direct, "chat.example:5222"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			dead, _ := silentOrigin(t, false)
			h := newStallProxy(t, dead, tc.action, 100*time.Millisecond, relayDialer(relay))
			c, _ := connectVia(t, h.server.Address(), tc.target)
			fmt.Fprint(c, "HELLO")
			time.Sleep(500 * time.Millisecond)
			if h.stalls.Load() != 0 {
				t.Fatal("stall retry applied where it must not be")
			}
		})
	}
}

func TestOversizedFirstFlightIsNotReplayed(t *testing.T) {
	dead, _ := silentOrigin(t, false)
	relay, _ := answeringOrigin(t)
	h := newStallProxy(t, dead, flowpolicy.Direct, 100*time.Millisecond, relayDialer(relay))
	c, _ := connectVia(t, h.server.Address(), "upload.example:443")
	c.Write(make([]byte, 80*1024))
	time.Sleep(500 * time.Millisecond)
	if h.stalls.Load() != 0 {
		t.Fatal("more than the replay buffer cannot be replayed safely; the original tunnel must be left alone")
	}
}

func TestTwoSilentDirectAddressesThenRelayWithinSharedBudget(t *testing.T) {
	first, _ := silentOrigin(t, false)
	second, _ := silentOrigin(t, false)
	relay, rec := answeringOrigin(t)
	var opens atomic.Int32
	a := netip.MustParseAddrPort(first)
	b := netip.MustParseAddrPort(second)
	cfg := Config{Authorize: func(context.Context, netip.AddrPort, netip.AddrPort) (Owner, error) { return Owner{PID: 1}, nil },
		Plan: func(context.Context, Request) (Plan, error) {
			return Plan{Enabled: true, Destination: a, DirectCandidates: []netip.AddrPort{a, b}, DirectDeadline: time.Now().Add(400 * time.Millisecond), DirectAttempts: 1, Policy: flowpolicy.Result{Action: flowpolicy.Direct}}, nil
		},
		Open: func(ctx context.Context, _ Request, _ Plan) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "tcp", first)
		},
		OnStall: func(ctx context.Context, _ Request, p Plan) (net.Conn, Plan, error) {
			n := opens.Add(1)
			addr := relay
			if n == 1 {
				addr = second
				p.Destination = b
				p.DirectAttempts = 2
			} else {
				p.Policy = flowpolicy.Result{Action: flowpolicy.RelayRequired, Fallback: flowpolicy.Required, RelayID: "VPS-01"}
			}
			c, e := (&net.Dialer{}).DialContext(ctx, "tcp", addr)
			return c, p, e
		}}
	s, e := Listen(context.Background(), cfg)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	client, reader := connectVia(t, s.Address(), "youtube.com:443")
	start := time.Now()
	client.Write([]byte("CLIENT-HELLO"))
	data := make([]byte, len("SERVER-HELLO"))
	if _, e = io.ReadFull(reader, data); e != nil {
		t.Fatal(e)
	}
	if opens.Load() != 2 || time.Since(start) > time.Second || rec.get() != "CLIENT-HELLO" {
		t.Fatal("ladder/budget/replay", opens.Load(), time.Since(start), rec.get())
	}
	client.Write([]byte("ESTABLISHED-BYTES"))
	time.Sleep(30 * time.Millisecond)
	if opens.Load() != 2 {
		t.Fatal("established connection retried")
	}
}

type engineFixtureRelay struct{ destination string }

func (r engineFixtureRelay) OpenTCP(ctx context.Context, _ netip.AddrPort) (net.Conn, error) {
	return (&net.Dialer{}).DialContext(ctx, "tcp", r.destination)
}
func (r engineFixtureRelay) OpenDatagram(context.Context, netip.AddrPort) (routing.Datagram, error) {
	return nil, errors.New("UDP unused")
}
func TestStallReleasesActualEngineTupleBeforeOpeningRequiredRelay(t *testing.T) {
	dead, _ := silentOrigin(t, false)
	relay, _ := answeringOrigin(t)
	engine := routing.New(8)
	engine.SetRelay("VPS-01", engineFixtureRelay{relay})
	f := routing.Flow{PID: 7, ProcessPath: "chrome.exe", ApplicationID: "chrome", Source: netip.MustParseAddrPort("127.0.0.1:5555"), Destination: netip.MustParseAddrPort(dead), PinnedPolicy: &routing.Policy{}}
	cfg := Config{Authorize: func(context.Context, netip.AddrPort, netip.AddrPort) (Owner, error) { return Owner{PID: 7}, nil }, Plan: func(context.Context, Request) (Plan, error) {
		return Plan{Enabled: true, Policy: flowpolicy.Result{Action: flowpolicy.Direct}}, nil
	},
		Open: func(ctx context.Context, _ Request, _ Plan) (net.Conn, error) { return engine.OpenTCP(ctx, f) }, StallTimeout: 60 * time.Millisecond,
		OnStall: func(ctx context.Context, _ Request, p Plan) (net.Conn, Plan, error) {
			next := f
			next.PinnedPolicy = &routing.Policy{Route: routing.Route{RelayID: "VPS-01"}, BlockOnFailure: true}
			conn, e := engine.OpenTCP(ctx, next)
			p.Policy = flowpolicy.Result{Action: flowpolicy.RelayRequired, Fallback: flowpolicy.Required, RelayID: "VPS-01"}
			return conn, p, e
		}}
	s, e := Listen(context.Background(), cfg)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	client, reader := connectVia(t, s.Address(), "youtube.com:443")
	client.Write([]byte("CLIENT-HELLO"))
	data := make([]byte, 12)
	if _, e = io.ReadFull(reader, data); e != nil {
		t.Fatal("same-tuple relay retry failed", e)
	}
	snapshot := engine.Snapshot()
	if len(snapshot) != 1 || snapshot[0].Route.RelayID != "VPS-01" {
		t.Fatal("relay reservation lost to old Close", snapshot)
	}
}
