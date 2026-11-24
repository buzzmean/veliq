package browserproxy

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"testing"
	"time"

	"github.com/buzzmean/veliq/core/flowpolicy"
)

func TestPACPathsOpenBudgetAndFirstExchange(t *testing.T) {
	var planning context.Context
	s, err := Listen(context.Background(), Config{
		Authorize: func(context.Context, netip.AddrPort, netip.AddrPort) (Owner, error) {
			return Owner{Profile: "edge", PID: 1, Birth: 2}, nil
		},
		Plan: func(ctx context.Context, q Request) (Plan, error) {
			planning = ctx
			if q.Ingress != "PAC_CONNECT" {
				t.Error(q.Ingress)
			}
			return Plan{Policy: flowpolicy.Result{Action: flowpolicy.Direct}}, nil
		},
		Open: func(ctx context.Context, _ Request, _ Plan) (net.Conn, error) {
			if planning.Err() != context.Canceled {
				t.Error("PLAN context not released before independent OPEN")
			}
			if ctx.Err() != nil {
				t.Error("OPEN inherited expired PLAN")
			}
			deadline, ok := ctx.Deadline()
			if !ok || time.Until(deadline) > 3*time.Second || time.Until(deadline) < 2*time.Second {
				t.Error("unbounded/exhausted OPEN", deadline)
			}
			a, b := net.Pipe()
			go func() { defer b.Close(); io.Copy(b, b) }()
			return a, nil
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
	io.WriteString(c, "CONNECT ordinary.example:443 HTTP/1.1\r\nHost: ordinary.example:443\r\n\r\n")
	b := bufio.NewReader(c)
	response, err := http.ReadResponse(b, nil)
	if err != nil || response.StatusCode != 200 {
		t.Fatal(response, err)
	}
	io.WriteString(c, "ping")
	got := make([]byte, 4)
	if _, err = io.ReadFull(b, got); err != nil || string(got) != "ping" {
		t.Fatal(string(got), err)
	}
	until := time.Now().Add(time.Second)
	for {
		snap := s.Snapshot()
		// The echo can arrive before the upload goroutine accounts a completed
		// Write. Wait for both directions, then keep every strict assertion.
		if len(snap.PathMetrics) == 1 && snap.PathMetrics[0].Received == 4 && snap.PathMetrics[0].Sent == 4 {
			m := snap.PathMetrics[0]
			if len(snap.FirstByteMetrics) != 1 || snap.FirstByteMetrics[0].Replies != 1 || snap.FirstByteMetrics[0].Mode != "DIRECT_FIRST" || snap.Records[0].FirstByteMS < 0 || snap.Records[0].AcceptedAt.IsZero() {
				t.Fatal("missing actual connection-to-first-byte evidence", snap)
			}
			if snap.Path != "PAC_CONNECT" || m.Accepted != 1 || m.Opened != 1 || m.Failed != 0 || m.Sent != 4 || m.FirstOpened.IsZero() || m.FirstExchange.IsZero() || m.FirstOpenMS < 0 || m.FirstExchangeMS < 0 {
				t.Fatal(snap)
			}
			break
		}
		if time.Now().After(until) {
			t.Fatal(snap)
		}
		time.Sleep(time.Millisecond)
	}
}
func TestPACFailureIsScopedAndNotDoublePrefixed(t *testing.T) {
	s, err := Listen(context.Background(), Config{
		Authorize: func(context.Context, netip.AddrPort, netip.AddrPort) (Owner, error) {
			return Owner{Profile: "chrome"}, nil
		},
		Plan: func(context.Context, Request) (Plan, error) {
			return Plan{Policy: flowpolicy.Result{Action: flowpolicy.RelayRequired}}, nil
		},
		Open: func(context.Context, Request, Plan) (net.Conn, error) { return nil, context.DeadlineExceeded },
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
	c.SetDeadline(time.Now().Add(time.Second))
	io.WriteString(c, "CONNECT failed.example:443 HTTP/1.1\r\nHost: failed.example:443\r\n\r\n")
	response, err := http.ReadResponse(bufio.NewReader(c), nil)
	if err != nil || response.StatusCode != 502 {
		t.Fatal(response, err)
	}
	snap := s.Snapshot()
	if snap.Failures["UPSTREAM_OPEN_TIMEOUT"] != 1 || len(snap.FailureDetails) != 1 || snap.FailureDetails[0].Domain != "failed.example" || snap.FailureDetails[0].Phase != "OPEN" || snap.PathMetrics[0].Failed != 1 || snap.PathMetrics[0].Opened != 0 {
		t.Fatal(snap)
	}
	if !snap.PathMetrics[0].FirstOpened.IsZero() {
		t.Fatal("failure fabricated first tunnel")
	}
	if openFailure(errors.New("token=secret")) != "UPSTREAM_OPEN_FAILED" {
		t.Fatal("raw error leaked")
	}
}
func TestPACSummarySurvivesLedgerEvictionAndStaysBounded(t *testing.T) {
	s := &Server{started: time.Now()}
	for i := 0; i < 1000; i++ {
		s.pathBeginLocked("chrome")
		s.pathOpenedLocked("chrome")
		s.pathBytesLocked(Record{Owner: Owner{Profile: "chrome"}, Sent: 2, Received: 3}, 2, 3)
	}
	p := s.paths["chrome"]
	if p.Opened != 1000 || p.Sent != 2000 || p.Received != 3000 {
		t.Fatal(p)
	}
	for i := 0; i < 1000; i++ {
		s.pathFailureLocked(Record{Owner: Owner{Profile: "chrome"}, Domain: netip.AddrFrom4([4]byte{1, 2, byte(i / 256), byte(i % 256)}).String()}, "OPEN", "UPSTREAM_OPEN_TIMEOUT")
	}
	if len(s.failureDetails) != 128 || s.failureDetailsLost != 872 {
		t.Fatal(len(s.failureDetails), s.failureDetailsLost)
	}
}

func TestPACStallGetsFreshBoundedBudgetNotExpiredOpen(t *testing.T) {
	s, err := Listen(context.Background(), Config{
		StallTimeout: 10 * time.Millisecond,
		Authorize: func(context.Context, netip.AddrPort, netip.AddrPort) (Owner, error) {
			return Owner{Profile: "chrome"}, nil
		},
		Plan: func(context.Context, Request) (Plan, error) {
			return Plan{Enabled: true, Policy: flowpolicy.Result{Action: flowpolicy.Direct}}, nil
		},
		Open: func(context.Context, Request, Plan) (net.Conn, error) {
			a, b := net.Pipe()
			go func() { defer b.Close(); io.Copy(io.Discard, b) }()
			return a, nil
		},
		OnStall: func(ctx context.Context, _ Request, p Plan) (net.Conn, Plan, error) {
			deadline, ok := ctx.Deadline()
			if !ok || time.Until(deadline) < 4*time.Second || time.Until(deadline) > 5*time.Second {
				t.Error("stall inherited consumed OPEN budget", deadline)
			}
			a, b := net.Pipe()
			go func() { defer b.Close(); io.Copy(b, b) }()
			p.Policy.Action = flowpolicy.RelayRequired
			return a, p, nil
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
	c.SetDeadline(time.Now().Add(time.Second))
	io.WriteString(c, "CONNECT ordinary.example:443 HTTP/1.1\r\nHost: ordinary.example:443\r\n\r\n")
	b := bufio.NewReader(c)
	response, err := http.ReadResponse(b, nil)
	if err != nil || response.StatusCode != 200 {
		t.Fatal(response, err)
	}
	io.WriteString(c, "ping")
	got := make([]byte, 4)
	if _, err = io.ReadFull(b, got); err != nil || string(got) != "ping" {
		t.Fatal(string(got), err)
	}
}
