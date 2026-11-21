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
	"testing"
	"time"

	"github.com/buzzmean/neexitlag/core/flowpolicy"
)

func TestFirstByteCloseReasonsDoNotConfuseCleanupPreconnectAndFailure(t *testing.T) {
	for _, tc := range []struct {
		side         string
		err          error
		sent, origin bool
		want         string
	}{
		{"client-read", io.EOF, false, false, "CLIENT_CLOSED_BEFORE_REQUEST"},
		{"client-read", io.EOF, true, false, "CLIENT_CLOSED_BEFORE_REPLY"},
		{"upstream-read", io.EOF, true, false, "UPSTREAM_EOF"},
		{"upstream-read", io.EOF, false, false, "UPSTREAM_EOF_WITHOUT_REQUEST"},
		{"upstream-read", context.DeadlineExceeded, true, false, "TIMEOUT"},
		{"upstream-write", errors.New("fixture IO error"), true, false, "UPSTREAM_ERROR"},
		{"client-write", errors.New("fixture delivery error"), true, true, "CLIENT_DELIVERY_ERROR"},
	} {
		e := &tunnelCloseEvidence{ctx: context.Background()}
		e.clientData.Store(tc.sent)
		e.originData.Store(tc.origin)
		e.terminal(tc.side, tc.err)
		e.forcing.Store(true)
		e.terminal("client-read", net.ErrClosed)
		if e.cause() != tc.want {
			t.Fatal(tc, e.cause())
		}
	}
	var l firstByteLedger
	r := Record{Domain: "i.ytimg.com", NoReplyReason: "TIMEOUT", RequestPayloadSeen: true}
	l.observe(r, -1)
	copyRows, _ := l.snapshot()
	l.observe(r, -1)
	if copyRows[0].NoReplyReasons["TIMEOUT"] != 1 {
		t.Fatal("snapshot map aliases live counters")
	}
	rows, _ := l.snapshot()
	if rows[0].NoReply != 2 || rows[0].NoReplyReasons["TIMEOUT"] != 2 || rows[0].NoReplyWithRequest != 2 {
		t.Fatal(rows)
	}
}

// Real CONNECT/socket paths, not a JSON-only classifier test. These endpoints
// are isolated and deliberately produce no origin bytes. Never claim page PASS.
func TestFirstByteNoReplyReasonsOnActualConnect(t *testing.T) {
	for _, kind := range []string{"preconnect", "client-after-payload", "upstream-eof", "upstream-error", "timeout", "dns"} {
		t.Run(kind, func(t *testing.T) {
			gotPayload := make(chan struct{})
			origin, err := net.Listen("tcp4", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer origin.Close()
			go func() {
				b, err := origin.Accept()
				if err != nil {
					return
				}
				defer b.Close()
				if kind == "upstream-eof" {
					return
				}
				var payload [1]byte
				if _, err := io.ReadFull(b, payload[:]); err == nil {
					close(gotPayload)
				}
				_, _ = io.Copy(io.Discard, b)
			}()
			s, err := Listen(context.Background(), Config{
				Authorize: func(context.Context, netip.AddrPort, netip.AddrPort) (Owner, error) {
					return Owner{Profile: "chrome"}, nil
				},
				Plan: func(context.Context, Request) (Plan, error) {
					p := Plan{Enabled: true, Network: "network", Policy: flowpolicy.Result{Action: flowpolicy.RelayRequired, Fallback: flowpolicy.Required}}
					if kind == "dns" {
						return p, ErrOriginDNS
					}
					return p, nil
				},
				Open: func(context.Context, Request, Plan) (net.Conn, error) {
					if kind == "timeout" {
						return nil, context.DeadlineExceeded
					}
					if kind == "upstream-error" {
						return nil, errors.New("isolated upstream failure")
					}
					return net.Dial("tcp4", origin.Addr().String())
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			c, err := net.Dial("tcp", s.Address())
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			c.SetDeadline(time.Now().Add(3 * time.Second))
			fmt.Fprint(c, "CONNECT r.googlevideo.com:443 HTTP/1.1\r\nHost: r.googlevideo.com:443\r\n\r\n")
			response, err := http.ReadResponse(bufio.NewReader(c), nil)
			if err != nil {
				t.Fatal(err)
			}
			switch kind {
			case "preconnect":
				c.(*net.TCPConn).CloseWrite()
			case "client-after-payload":
				fmt.Fprint(c, "x")
				select {
				case <-gotPayload:
				case <-time.After(time.Second):
					t.Fatal("payload not delivered")
				}
				c.(*net.TCPConn).CloseWrite()
			}

			if kind == "timeout" || kind == "dns" || kind == "upstream-error" {
				if response.StatusCode != 502 {
					t.Fatal(response.StatusCode)
				}
			}
			var report FirstByteReport
			until := time.Now().Add(time.Second)
			for {
				report = s.FirstBytes()
				if len(report.Metrics) == 1 && report.Metrics[0].NoReply == 1 {
					break
				}
				if time.Now().After(until) {
					t.Fatal("no completed evidence", report)
				}
				time.Sleep(time.Millisecond)
			}
			m := report.Metrics[0]
			var sum uint64
			for _, n := range m.NoReplyReasons {
				sum += n
			}
			if sum != 1 || m.Replies != 0 || m.MinMS != -1 {
				t.Fatal(m)
			}
			switch kind {
			case "preconnect":
				if m.NoReplyReasons["CLIENT_CLOSED_BEFORE_REQUEST"] != 1 || m.NoReplyWithoutRequest != 1 {
					t.Fatal(m)
				}
			case "client-after-payload":
				if m.NoReplyReasons["CLIENT_CLOSED_BEFORE_REPLY"] != 1 || m.NoReplyWithRequest != 1 {
					t.Fatal(m)
				}
			case "upstream-eof":
				if m.NoReplyReasons["UPSTREAM_EOF_WITHOUT_REQUEST"] != 1 {
					t.Fatal(m)
				}
			case "dns":
				if m.NoReplyReasons["ORIGIN_DNS_FAILED"] != 1 {
					t.Fatal(m)
				}
			case "timeout":
				if m.NoReplyReasons["TIMEOUT"] != 1 {
					t.Fatal(m)
				}
			case "upstream-error":
				if m.NoReplyReasons["UPSTREAM_ERROR"] != 1 {
					t.Fatal(m)
				}
			}
		})
	}
}

type localAdmissionError string

func (e localAdmissionError) Error() string         { return string(e) }
func (e localAdmissionError) FailureReason() string { return string(e) }
func (e localAdmissionError) Unwrap() error         { return ErrVideoRelayAdmission }
func TestOpaqueAdmissionIsNotReportedAsVideoOrUpstreamFailure(t *testing.T) {
	err := localAdmissionError("OPAQUE_GOOGLE_RELAY_ADMISSION_CAPACITY")
	if got := openFailure(err); got != "OPAQUE_GOOGLE_RELAY_ADMISSION_CAPACITY" {
		t.Fatal(got)
	}
	if got := noReplyFailure(err); got != "OPAQUE_GOOGLE_ADMISSION" {
		t.Fatal(got)
	}
	if got := noReplyFailure(ErrVideoRelayAdmission); got != "GOOGLEVIDEO_ADMISSION" {
		t.Fatal(got)
	}
}
