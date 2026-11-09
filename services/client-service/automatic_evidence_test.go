package clientservice

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/buzzmean/neexitlag/core/browserproxy"
	"github.com/buzzmean/neexitlag/core/flowpolicy"
	wp "github.com/buzzmean/neexitlag/platform/windows"
)

func evidenceConnection(t *testing.T) (*Controller, *nativeBrowserConn, net.Conn) {
	t.Helper()
	c := New(context.Background())
	t.Cleanup(c.Close)
	n := &c.browser.applications
	dst := netip.MustParseAddrPort("93.184.216.34:443")
	id, err := n.begin(browserproxy.Request{Ingress: "AUTOMATIC_TCP", Host: "ordinary.example.org"}, wp.Tuple{Protocol: "tcp", Destination: dst})
	if err != nil {
		t.Fatal(err)
	}
	n.opened(id, browserproxy.Plan{Destination: dst, Policy: flowpolicy.Result{Action: flowpolicy.Direct}}, nil)
	a, b := net.Pipe()
	conn := newNativeBrowserConn(a, n, id)
	t.Cleanup(func() { conn.Close(); b.Close() })
	a.SetDeadline(time.Now().Add(3 * time.Second))
	b.SetDeadline(time.Now().Add(3 * time.Second))
	return c, conn, b
}

func evidenceRow(t *testing.T, c *Controller) nativeBrowserRecord {
	t.Helper()
	v, err := c.Handle(context.Background(), "automation.status", nil)
	if err != nil {
		t.Fatal(err)
	}
	s := v.(map[string]any)
	r := s["records"].([]nativeBrowserRecord)
	if s["version"] != 2 || len(r) != 1 || r[0].Evidence == nil || r[0].Evidence.Application != "NOT_VERIFIED" {
		t.Fatal(s)
	}
	return r[0]
}

func evidenceTransfer(t *testing.T, to net.Conn, from net.Conn, p []byte) {
	t.Helper()
	wrote := make(chan error, 1)
	go func() { _, err := from.Write(p); wrote <- err }()
	got := make([]byte, len(p))
	if _, err := io.ReadFull(to, got); err != nil {
		t.Fatal(err)
	}
	if err := <-wrote; err != nil || !bytes.Equal(got, p) {
		t.Fatal("passive diagnostics altered bytes", err)
	}
}

func TestAutomaticEvidenceSeparatesTransportTLSAndApplication(t *testing.T) {
	c, conn, peer := evidenceConnection(t)
	initial := evidenceRow(t, c)
	if initial.Evidence.Connection != "OPEN" || initial.Evidence.Transport != "NO_DATA" || initial.Evidence.TLS != "NOT_OBSERVED" {
		t.Fatal(initial.Evidence)
	}
	// Real I/O through the production wrapper, one fragmented ServerHello. No
	// status observation should mutate policy, synthesize a success, or consume data.
	hello := append([]byte{22, 3, 3, 0, 42, 2, 0, 0, 38}, make([]byte, 38)...)
	evidenceTransfer(t, peer, conn, []byte{22, 3, 3, 0, 4, 1, 0, 0, 0})
	evidenceTransfer(t, conn, peer, hello[:6])
	partial := evidenceRow(t, c)
	if partial.TLS == nil || partial.Evidence.TLS != "ORIGIN_TLS_INCOMPLETE" || partial.TLS.Origin.ServerHelloComplete || partial.LastSent.IsZero() || partial.LastReceived.IsZero() {
		t.Fatal(partial)
	}
	evidenceTransfer(t, conn, peer, hello[6:])
	if got := evidenceRow(t, c); got.Evidence.TLS != "SERVER_HELLO_OBSERVED" || !got.TLS.Origin.ServerHelloComplete {
		t.Fatal(got)
	}
	// TLS1.3 encrypted handshake and even a service error look like type23.
	// None may become a page/Gemini/region PASS without application evidence.
	evidenceTransfer(t, conn, peer, []byte{23, 3, 3, 0, 4, 42, 42, 42, 42})
	got := evidenceRow(t, c)
	if got.Evidence.TLS != "ENCRYPTED_RECORDS_OBSERVED" || got.Evidence.Transport != "BIDIRECTIONAL_BYTES" || got.Policy.Action != flowpolicy.Direct || got.Evidence.Failure != "NONE_OBSERVED" {
		t.Fatal(got)
	}
	got.TLS.Origin.Records[0].Length = 999
	if evidenceRow(t, c).TLS.Origin.Records[0].Length == 999 {
		t.Fatal("live evidence aliases snapshot")
	}
	conn.Close()
	if got := evidenceRow(t, c); got.Evidence.Connection != "CLOSED" || got.Evidence.Application != "NOT_VERIFIED" {
		t.Fatal(got)
	}
}

func TestAutomaticEvidenceKeepsAlertAndEndOfStreamDistinct(t *testing.T) {
	c, conn, peer := evidenceConnection(t)
	evidenceTransfer(t, peer, conn, []byte{22, 3, 3, 0, 4, 1, 0, 0, 0})
	evidenceTransfer(t, conn, peer, []byte{21, 3, 3, 0, 2, 2, 40})
	peer.Close()
	if _, err := conn.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
		t.Fatal(err)
	}
	got := evidenceRow(t, c)
	if got.Evidence.Failure != "TLS_ALERT" || got.Evidence.Cause != "UNKNOWN" || got.LastIO == nil || got.LastIO.Outcome != "PEER_EOF" || got.LastIO.Operation != "READ" {
		t.Fatal(got)
	}
	got.LastIO.Outcome = "tampered"
	if evidenceRow(t, c).LastIO.Outcome != "PEER_EOF" {
		t.Fatal("I/O snapshot alias")
	}
}

func TestAutomaticEvidenceRetainsRedactedIOFailureWithoutLearning(t *testing.T) {
	c, conn, _ := evidenceConnection(t)
	n := &c.browser.applications
	n.observeIOEnd(conn.record, "WRITE", errors.New("Authorization: private payload"))
	n.observeIOEnd(conn.record, "READ", io.EOF)
	n.observeIOEnd(conn.record, "READ", net.ErrClosed)
	got := evidenceRow(t, c)
	raw, _ := json.Marshal(got)
	if bytes.Contains(raw, []byte("private")) || got.LastIO.Operation != "WRITE" || got.Evidence.Failure != "IO_ERROR" || got.Evidence.Cause != "UNKNOWN" || got.Policy.Action != flowpolicy.Direct {
		t.Fatal(string(raw))
	}
	n.observeIOEnd(conn.record, "READ", os.ErrDeadlineExceeded)
	if got := evidenceRow(t, c); got.LastIO.Outcome != "IO_ERROR" {
		t.Fatal(got)
	}
}

func TestAutomaticEvidencePollingDeadlineDoesNotMakeHealthySocketFailed(t *testing.T) {
	c, conn, peer := evidenceConnection(t)
	conn.SetReadDeadline(time.Now().Add(-time.Millisecond))
	if _, err := conn.Read(make([]byte, 1)); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatal(err)
	}
	if got := evidenceRow(t, c); got.LastIO == nil || got.LastIO.Outcome != "IO_TIMEOUT" || got.Evidence.Failure != "NONE_OBSERVED" {
		t.Fatal(got)
	}
	conn.SetReadDeadline(time.Now().Add(time.Second))
	hello := append([]byte{22, 3, 3, 0, 42, 2, 0, 0, 38}, make([]byte, 38)...)
	evidenceTransfer(t, conn, peer, hello)
	if got := evidenceRow(t, c); got.Evidence.Failure != "NONE_OBSERVED" || got.Evidence.TLS != "SERVER_HELLO_OBSERVED" || got.LastReceived.Before(got.LastIO.At) {
		t.Fatal(got)
	}
}

type automaticEvidenceReporter struct {
	plan   browserproxy.Plan
	origin browserproxy.OriginReport
}

func (r *automaticEvidenceReporter) CurrentPlan() browserproxy.Plan            { return r.plan }
func (r *automaticEvidenceReporter) OriginAttempts() browserproxy.OriginReport { return r.origin }

func TestAutomaticEvidenceRefreshesPlanAttemptsAndPreservesBounds(t *testing.T) {
	c, conn, _ := evidenceConnection(t)
	n := &c.browser.applications
	reporter := &automaticEvidenceReporter{plan: browserproxy.Plan{Destination: netip.MustParseAddrPort("1.1.1.1:443"), Policy: flowpolicy.Result{Action: flowpolicy.RelayRequired}}, origin: browserproxy.OriginReport{Selected: "invalid AddrPort", State: "WAITING_ORIGIN"}}
	n.mu.Lock()
	r := n.records[conn.record]
	r.planReporter, r.originReporter = reporter, reporter
	n.records[conn.record] = r
	n.mu.Unlock()
	if got := evidenceRow(t, c); got.Upstream != "1.1.1.1:443" || got.Origin == nil || got.Origin.State != "WAITING_ORIGIN" || got.Policy.Action != flowpolicy.RelayRequired {
		t.Fatal(got)
	}
	reporter.origin = browserproxy.OriginReport{Selected: "8.8.8.8:443", State: "ORIGIN_BYTES_NO_REPLAY", AddressAttempts: 2}
	if got := evidenceRow(t, c); got.Upstream != "8.8.8.8:443" || got.Origin.AddressAttempts != 2 {
		t.Fatal(got)
	}
	for i := 0; i < 12; i++ {
		if _, err := n.begin(browserproxy.Request{}, wp.Tuple{}); err != nil {
			t.Fatal(err)
		}
	}
	n.mu.Lock()
	n.lost = 3
	n.mu.Unlock()
	s := c.automaticStatus()
	if len(s["records"].([]nativeBrowserRecord)) != 8 || s["records_total"] != 13 || s["records_omitted"] != 5 || s["records_lost"] != uint64(3) {
		t.Fatal(s)
	}
	n.mu.Lock()
	for id, row := range n.records {
		row.Policy.Reason = strings.Repeat("x", 12000)
		n.records[id] = row
	}
	n.mu.Unlock()
	s = c.automaticStatus()
	raw, _ := json.Marshal(s)
	rows := s["records"].([]nativeBrowserRecord)
	if len(raw) > 60*1024 || len(rows) >= 8 || len(rows) == 0 || s["records_omitted"] != 13-len(rows) || s["records_truncated"] != true {
		t.Fatal("IPC size/omission contract", len(raw), len(rows), s["records_omitted"])
	}
}
