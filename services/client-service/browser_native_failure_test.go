package clientservice

import (
	"bytes"
	"errors"
	"io"
	"net"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/buzzmean/neexitlag/core/flowpolicy"
	"github.com/buzzmean/neexitlag/core/profiles"
)

type firstResponseFixture struct {
	net.Conn
	reply    []byte
	writeErr error
	closed   atomic.Bool
	written  bytes.Buffer
}

func (f *firstResponseFixture) Write(p []byte) (int, error) {
	if f.writeErr != nil {
		return 0, f.writeErr
	}
	return f.written.Write(p)
}
func (f *firstResponseFixture) Read(p []byte) (int, error) {
	if len(f.reply) == 0 {
		return 0, io.EOF
	}
	n := copy(p, f.reply)
	f.reply = f.reply[n:]
	return n, nil
}
func (f *firstResponseFixture) Close() error { f.closed.Store(true); return nil }

func TestNativeTLSFirstResponseRequiresServerHelloAndPublishesBeforeClose(t *testing.T) {
	hello := []byte{22, 3, 3, 0, 4, 1, 0, 0, 0}
	for _, tc := range []struct {
		name        string
		reply       []byte
		writeErr    error
		wantFailure bool
	}{
		{"header-only", []byte{22, 3, 3, 0, 80}, nil, true},
		{"alert", []byte{21, 3, 3, 0, 2, 2, 40}, nil, true},
		{"EOF", nil, nil, true},
		{"write-RST", nil, errors.New("connection reset"), true},
		{"tiny-serverhello", []byte{22, 3, 3, 0, 8, 2, 0, 0, 4, 3, 3, 0, 0}, nil, true},
		{"serverhello", append([]byte{22, 3, 3, 0, 42, 2, 0, 0, 38}, make([]byte, 38)...), nil, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw := &firstResponseFixture{reply: tc.reply, writeErr: tc.writeErr}
			calls := 0
			conn := &nativeFirstReplyConn{Conn: raw, timeout: time.Hour, failed: func(reason string) {
				calls++
				if raw.closed.Load() {
					t.Error("cache published after close")
				}
				if !strings.HasPrefix(reason, "DIRECT_TLS_") {
					t.Error(reason)
				}
			}}
			defer conn.Close()
			conn.Write(hello)
			conn.Read(make([]byte, 128))
			conn.fail()
			conn.fail()
			if (calls == 1) != tc.wantFailure || calls > 1 {
				t.Fatal("bad health classification", calls, tc.wantFailure)
			}
			if tc.writeErr == nil && !bytes.Equal(raw.written.Bytes(), hello) {
				t.Fatal("application first flight changed/replayed")
			}
		})
	}
}
func TestNativePreconnectAndOwnerCloseDoNotLearnFailure(t *testing.T) {
	for _, written := range []bool{false, true} {
		raw := &firstResponseFixture{}
		calls := 0
		conn := &nativeFirstReplyConn{Conn: raw, timeout: time.Hour, failed: func(string) { calls++ }}
		if written {
			conn.Write([]byte{22, 3, 3, 0, 4, 1, 0, 0, 0})
		}
		conn.Close()
		conn.Read(make([]byte, 10))
		conn.fail()
		if calls != 0 {
			t.Fatal("client cancellation poisoned cache")
		}
	}
}
func TestOpaqueGoogleRelayNeedsTwoIPsAndStaysScopedBounded(t *testing.T) {
	c, _, _ := nativeEdgeFixture(t)
	p := profiles.Profile{ID: "chrome", Executables: []string{`C:\Apps\chrome.exe`}, Mode: profiles.Auto, BrowserTransport: "native"}
	first := netip.MustParseAddrPort("64.233.162.95:443")
	second := netip.MustParseAddrPort("142.251.1.94:443")
	tuple := policyTuple("tcp", 443)
	tuple.Destination = netip.MustParseAddrPort("173.194.180.1:443")
	now := time.Now()
	x := &c.browser.domains
	x.googleFailed("network", p.ID, first, "DIRECT_TLS_FIRST_REPLY_TIMEOUT", now)
	x.googleFailed("network", p.ID, first, "DIRECT_TLS_EARLY_EOF_OR_RESET", now)
	if x.googleRelay("network", p.ID, tuple.Destination, now) {
		t.Fatal("one failed IP poisoned all Google")
	}
	x.googleFailed("network", p.ID, second, "DIRECT_TLS_EARLY_ALERT_OR_INVALID_RECORD", now)
	plan := c.nativeOpaquePlan(p, tuple, "network", browserDomainEvidence{})
	if plan.Policy.Action != flowpolicy.RelayRequired || plan.Policy.Fallback != flowpolicy.Required || plan.Policy.Source != "browser_opaque_google_failure_cache" {
		t.Fatal(plan)
	}
	if x.googleRelay("other", p.ID, tuple.Destination, now) || x.googleRelay("network", "edge", tuple.Destination, now) || x.googleRelay("network", p.ID, tuple.Destination, now.Add(3*time.Minute)) {
		t.Fatal("cache leaked scope/TTL")
	}
	for _, dst := range []string{"87.240.137.208:443", "77.88.55.88:443", "64.233.162.188:5228"} {
		tuple.Destination = netip.MustParseAddrPort(dst)
		if plan = c.nativeOpaquePlan(p, tuple, "network", browserDomainEvidence{}); plan.Policy.Action != flowpolicy.Direct {
			t.Fatal("unrelated site/port relayed", dst, plan)
		}
	}
	tuple.Destination = first
	p.Rules = []flowpolicy.Rule{{ID: "blocked", CIDRs: []string{"64.233.162.95/32"}, Action: flowpolicy.Block}}
	if plan = c.nativeOpaquePlan(p, tuple, "network", browserDomainEvidence{}); plan.Policy.Action != flowpolicy.Block {
		t.Fatal("explicit block ignored")
	}
	for i := 0; i < 100; i++ {
		x.googleFailed("network", string(rune(i+1)), first, "DIRECT_TCP_OPEN_FAILED", now)
	}
	if len(x.google) > 64 {
		t.Fatal("unbounded family failures")
	}
}
func TestOpaqueGoogleCannotConsumeDedicatedVideoAdmissions(t *testing.T) {
	u := &browserRelayUsage{}
	var release []func()
	for i := 0; i < opaqueGoogleRelayLimit; i++ {
		r, ok := u.acquireVideoContext(t.Context(), true)
		if !ok {
			t.Fatal(i)
		}
		release = append(release, r)
	}
	for i := 0; i < videoRelayLimit; i++ {
		r, ok := u.acquireVideoContext(t.Context())
		if !ok {
			t.Fatal("opaque starved video", i)
		}
		release = append(release, r)
	}
	s := u.snapshot()
	if s.VideoActive != videoRelayLimit || s.OpaqueGoogleActive != opaqueGoogleRelayLimit || s.TotalGoogleActive != 16 || s.SharedVideoActive != videoRelayLimit || s.VideoTimeouts != 0 {
		t.Fatal(s)
	}
	if _, ok := u.acquireVideo(); ok {
		t.Fatal("video cap bypassed")
	}
	if _, ok := u.tryAcquireVideo(true, true); ok {
		t.Fatal("opaque cap bypassed")
	}
	for _, r := range release {
		r()
		r()
	}
	if s = u.snapshot(); s.TotalGoogleActive != 0 {
		t.Fatal(s)
	}
}

func TestNativeTLSHeaderOnlyStillExpiresAndPollingTimeoutDoesNotConfirmOrFail(t *testing.T) {
	for _, polling := range []bool{false, true} {
		t.Run(map[bool]string{false: "header-only-silence", true: "harmless-poll-timeout"}[polling], func(t *testing.T) {
			a, b := net.Pipe()
			defer b.Close()
			failed := make(chan string, 1)
			timeout := 40 * time.Millisecond
			if polling {
				timeout = time.Second
			}
			c := &nativeFirstReplyConn{Conn: a, timeout: timeout, failed: func(s string) { failed <- s }}
			defer c.Close()
			done := make(chan struct{})
			go func() {
				defer close(done)
				io.ReadFull(b, make([]byte, 9))
				if !polling {
					b.Write([]byte{22, 3, 3, 0, 80})
				}
			}()
			if _, err := c.Write([]byte{22, 3, 3, 0, 4, 1, 0, 0, 0}); err != nil {
				t.Fatal(err)
			}
			if polling {
				c.SetReadDeadline(time.Now().Add(10 * time.Millisecond))
				if _, err := c.Read(make([]byte, 128)); err == nil {
					t.Fatal("missing poll timeout")
				}
				select {
				case s := <-failed:
					t.Fatal("harmless poll poisoned health", s)
				default:
				}
				c.SetReadDeadline(time.Time{})
				go b.Write(append([]byte{22, 3, 3, 0, 42, 2, 0, 0, 38}, make([]byte, 38)...))
				if _, err := c.Read(make([]byte, 128)); err != nil {
					t.Fatal(err)
				}
				c.fail()
				select {
				case s := <-failed:
					t.Fatal("healthy ServerHello poisoned", s)
				default:
				}
			} else {
				if _, err := io.ReadFull(c, make([]byte, 5)); err != nil {
					t.Fatal(err)
				}
				select {
				case s := <-failed:
					if s != "DIRECT_TLS_FIRST_REPLY_TIMEOUT" {
						t.Fatal(s)
					}
				case <-time.After(time.Second):
					t.Fatal("header-only canceled watchdog")
				}
			}
			<-done
		})
	}
}
