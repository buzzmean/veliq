package clientservice

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/buzzmean/neexitlag/core/browserproxy"
	"github.com/buzzmean/neexitlag/core/flowpolicy"
	"github.com/buzzmean/neexitlag/core/profiles"
)

type tcpSink struct {
	mu   sync.Mutex
	data []byte
	n    int
}

func (s *tcpSink) add(b []byte) { s.mu.Lock(); s.data = append(s.data, b...); s.n++; s.mu.Unlock() }
func (s *tcpSink) text() string { s.mu.Lock(); defer s.mu.Unlock(); return string(s.data) }
func (s *tcpSink) conns() int   { s.mu.Lock(); defer s.mu.Unlock(); return s.n }

// startOrigin accepts connections and reads the client's first bytes (the ClientHello). With
// answer set it replies like a server; otherwise it stays silent: a path that completes the
// TCP handshake and then swallows the TLS data.
func startOrigin(t *testing.T, answer bool) (string, *tcpSink) {
	t.Helper()
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	sink := &tcpSink{}
	go func() {
		for {
			c, e := l.Accept()
			if e != nil {
				return
			}
			go func() {
				defer c.Close()
				buf := make([]byte, 8192)
				n, _ := c.Read(buf)
				if n > 0 {
					sink.add(buf[:n])
					if answer {
						c.Write([]byte("SERVER-HELLO"))
					}
				}
				io.Copy(io.Discard, c)
			}()
		}
	}()
	return l.Addr().String(), sink
}

// The whole chain as the service wires it: real browser proxy, real DIRECT-timeout cache,
// controller stall hook. DIRECT is a TCP server that reads the ClientHello and stays silent.
func TestSilentDirectOriginIsRetriedViaRelayThenCachedRelayFirst(t *testing.T) {
	c := New(context.Background())
	t.Cleanup(c.Close)
	enableYouTubeRelay(c)
	cur := profilesResult{profile: profiles.Profile{ID: "chrome-x"}, network: "net-1", enabled: true}
	silent, silentSaw := startOrigin(t, false)
	relay, relaySaw := startOrigin(t, true)
	dial := func(ctx context.Context, addr string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "tcp", addr)
	}
	open := func(ctx context.Context, q browserproxy.Request, plan browserproxy.Plan) (net.Conn, error) {
		if plan.Policy.Action == flowpolicy.RelayRequired {
			return dial(ctx, relay)
		}
		conn, err := dial(ctx, silent)
		c.observeDirectOpen(cur, q, plan, err, time.Now()) // what browserOpen does
		return conn, err
	}
	server, err := browserproxy.Listen(context.Background(), browserproxy.Config{
		Authorize: func(context.Context, netip.AddrPort, netip.AddrPort) (browserproxy.Owner, error) {
			return browserproxy.Owner{PID: 1}, nil
		},
		Plan: func(_ context.Context, q browserproxy.Request) (browserproxy.Plan, error) {
			plan := browserproxy.Plan{Network: "net-1", Enabled: true, Policy: flowpolicy.Result{Action: flowpolicy.Direct, Fallback: flowpolicy.FailOpen, Source: "browser_domain"}, Probe: "NOT_PROBED"}
			// the YouTube branch of browserPlan
			if steered, ok := c.steerTimedOutOrigin(plan, cur, q, time.Now()); ok {
				return steered, nil
			}
			return plan, nil
		},
		Open: open,
		OnStall: func(ctx context.Context, q browserproxy.Request, plan browserproxy.Plan) (net.Conn, browserproxy.Plan, error) {
			return c.stallRetry(ctx, cur, q, plan, open)
		},
		OnDirectAnswered: func(q browserproxy.Request, plan browserproxy.Plan) { c.recordAnswered(cur, q, plan) },
		StallTimeout:     200 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { server.Close() })

	browser := func(host string) (time.Duration, string) {
		conn, err := net.Dial("tcp", server.Address())
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(5 * time.Second))
		fmt.Fprintf(conn, "CONNECT %s:443 HTTP/1.1\r\nHost: %s:443\r\n\r\n", host, host)
		r := bufio.NewReader(conn)
		if resp, err := http.ReadResponse(r, &http.Request{Method: "CONNECT"}); err != nil || resp.StatusCode != 200 {
			t.Fatalf("CONNECT: %v %v", resp, err)
		}
		started := time.Now()
		fmt.Fprint(conn, "CLIENT-HELLO")
		got := make([]byte, len("SERVER-HELLO"))
		if _, err := io.ReadFull(r, got); err != nil {
			t.Fatalf("the browser got an error instead of an answer: %v", err)
		}
		return time.Since(started), string(got)
	}

	// Empty cache: only the first group member pays the DIRECT timeout. Every
	// subsequent sibling must open relay-first, including previously unseen CDNs.
	for i, host := range []string{"www.youtube.com", "rr3---sn-4g5e6nzs.googlevideo.com"} {
		took, got := browser(host)
		t.Logf("tunnel %d (%s): answer %q after %v via relay (direct origin saw %d conns)", i+1, host, got, took.Round(time.Millisecond), silentSaw.conns())
		if got != "SERVER-HELLO" || i == 0 && took < 150*time.Millisecond || i > 0 && took >= 150*time.Millisecond {
			t.Fatalf("tunnel %d: %q after %v", i+1, got, took)
		}
	}
	if stats := c.browser.directTimeouts.Stats(); stats.Stalls != 1 || stats.StallRetries != 1 || stats.ActiveOrigins != 1 {
		t.Fatalf("one stall must confirm the entire group: %+v", stats)
	}
	took, _ := browser("www.youtube.com") // already cached after the first stall
	t.Logf("tunnel 3 (www.youtube.com again): answered via relay after %v (cached after first stall)", took.Round(time.Millisecond))

	directBefore := silentSaw.conns()
	took, got := browser("www.youtube.com") // cached: straight to the relay, no waiting
	t.Logf("tunnel 4 (www.youtube.com, cached): %q after %v, DIRECT not touched (direct conns before=%d after=%d)", got, took.Round(time.Millisecond), directBefore, silentSaw.conns())
	if took > 150*time.Millisecond {
		t.Fatalf("a cached origin still waited for the stall timeout: %v", took)
	}
	if silentSaw.conns() != directBefore {
		t.Fatal("a cached relay-first origin was opened DIRECT again")
	}
	stats := c.browser.directTimeouts.Stats()
	t.Logf("direct_timeout_cache: %+v", stats)
	if stats.Stalls != 1 || stats.StallRetries != 1 || stats.StallRetryFails != 0 || stats.Hits < 1 || stats.ActiveOrigins < 1 {
		t.Fatalf("counters wrong: %+v", stats)
	}
	if relaySaw.text() != "CLIENT-HELLOCLIENT-HELLOCLIENT-HELLOCLIENT-HELLO" {
		t.Fatalf("relay got %q: every ClientHello must be delivered exactly once", relaySaw.text())
	}
	rec := server.Snapshot().Records
	// Records come from a map: the newest tunnel is the one with the highest ID.
	last := rec[0]
	for _, r := range rec {
		if r.ID > last.ID {
			last = r
		}
	}
	for _, r := range rec {
		if r.Plan.Policy.Action == flowpolicy.Direct && r.Result != "" && r.StallRetried == false && r.Domain == "www.youtube.com" && r.Received == 0 && !r.Active {
			t.Fatalf("a YouTube tunnel finished DIRECT with zero bytes and no retry: %+v", r)
		}
	}
	if last.Plan.Policy.Source != "direct_timeout_cache" {
		t.Fatalf("last tunnel was not steered by the cache: %+v", last.Plan.Policy)
	}
}
