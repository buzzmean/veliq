package windowsplatform

import (
	"encoding/binary"
	"errors"
	"github.com/buzzmean/neexitlag/core/protocol"
	"github.com/quic-go/quic-go"
	"io"
	"net/netip"
	"testing"
	"time"

	"github.com/buzzmean/neexitlag/core/flowpolicy"
	"github.com/buzzmean/neexitlag/core/routing"
)

func TestUDPAdmissionReserveAndDNSChurn(t *testing.T) {
	var a udpAdmission
	for i := 0; i < 384; i++ {
		if !a.acquire(false) {
			t.Fatal("ordinary capacity", i)
		}
	}
	if a.acquire(false) {
		t.Fatal("DNS consumed media reserve")
	}
	for i := 0; i < 128; i++ {
		if !a.acquire(true) {
			t.Fatal("reserved media blocked", i)
		}
	}
	if a.acquire(true) {
		t.Fatal("unbounded admission")
	}
	// Reclaim only idle DNS, not live media. Churn cannot evict occupied leases.
	for round := 0; round < 100; round++ {
		for i := 0; i < 384; i++ {
			a.release(false)
		}
		if a.total != 128 {
			t.Fatal("media lease evicted")
		}
		for i := 0; i < 384; i++ {
			if !a.acquire(false) {
				t.Fatal("DNS slots not reusable")
			}
		}
	}
	for i := 0; i < 384; i++ {
		a.release(false)
	}
	for i := 0; i < 128; i++ {
		a.release(true)
	}
	if a.total != 0 || a.ordinary != 0 {
		t.Fatal("leaked leases", a)
	}
}
func TestUDPIdleBoundary(t *testing.T) {
	now := time.Now()
	tuple := Tuple{Protocol: "udp", Destination: netip.MustParseAddrPort("1.1.1.1:53")}
	limit := udpIdleLimit(tuple, false)
	if limit != 5*time.Second {
		t.Fatal(limit)
	}
	for _, x := range []struct {
		age     time.Duration
		pending int
		idle    bool
	}{
		{limit - time.Nanosecond, 0, false}, {limit, 0, true}, {limit + time.Nanosecond, 0, true},
		{limit, 1, false}, {0, 0, false}, // queued/resumed request wins the deadline race
	} {
		if got := udpIdle(now, now.Add(-x.age), x.pending, limit); got != x.idle {
			t.Fatal(x, got)
		}
	}
	if udpIdleLimit(tuple, true) != 30*time.Second {
		t.Fatal("media used DNS lifetime")
	}
}
func TestTCPDropAndFailureEvidence(t *testing.T) {
	for _, normal := range []bool{true, false} {
		l := NewEvidenceLedger()
		id := ProcessIdentity{PID: 42, CreationTime: 1, Path: `C:\Apps\msedge.exe`}
		tuple := Tuple{Protocol: "tcp", Source: netip.MustParseAddrPort("192.0.2.1:1234"), Destination: netip.MustParseAddrPort("203.0.113.2:443")}
		l.BeginFlow(id, tuple)
		l.RecordPolicy(id, tuple, Decision{Policy: flowpolicy.Result{Action: flowpolicy.RelayRequired, Fallback: flowpolicy.Required}}, "")
		l.RecordBytes(id, tuple, "relay", "VPS-01", 100)
		l.RecordBytes(id, tuple, "reply", "VPS-01", 200)
		if !normal {
			l.RecordFailure(id, tuple, "TCP_RELAY_READ_FAILED", true)
		} else {
			l.RecordLifecycle(id, tuple, "TCP_CLOSED")
		}
		for i := 0; i < 7; i++ {
			l.RecordDrop(id, tuple, tcpPacketDropCause("closed"), false)
		}
		// Late observations may not clear a real failure.
		l.RecordBytes(id, tuple, "reply", "VPS-01", 1)
		f := l.Snapshot(42).Flows[0]
		if normal {
			if f.Route != "RELAY" || f.RequiredBlocked || f.FailureCause != "" {
				t.Fatal(f)
			}
		} else if f.Route != "BLOCK" || !f.RequiredBlocked || f.FailureCause != "TCP_RELAY_READ_FAILED" {
			t.Fatal(f)
		}
		if f.Counters.Dropped != 7 || f.Counters.DirectBytes != 0 || f.RelayID != "VPS-01" {
			t.Fatal(f)
		}
	}
}
func TestTCPCopyFailureClassification(t *testing.T) {
	for _, x := range []struct {
		event  string
		r, w   error
		stop   bool
		failed bool
	}{
		{"reply", io.EOF, nil, false, false}, // normal FIN / server destination RST mapped to EOF
		{"relay", errors.New("app reset"), nil, false, false},
		{"reply", nil, errors.New("app closed"), false, false},
		{"reply", errors.New("session lost"), nil, false, true},
		{"relay", nil, io.ErrClosedPipe, false, true},
		{"reply", errors.New("shutdown"), nil, true, false},
	} {
		if got := tcpCopyFailure(x.event, x.r, x.w, x.stop); (got != "") != x.failed {
			t.Fatal(x, got)
		}
	}
}
func TestWorkerRejectionIsExplicitFailClosed(t *testing.T) {
	l := NewEvidenceLedger()
	id := ProcessIdentity{PID: 1, CreationTime: 2, Path: "edge.exe"}
	tuple := Tuple{Protocol: "udp", Destination: netip.MustParseAddrPort("1.1.1.1:53")}
	l.BeginFlow(id, tuple)
	l.RecordPolicy(id, tuple, Decision{Route: routing.Route{RelayID: "VPS-01"}, Policy: flowpolicy.Result{Action: flowpolicy.RelayRequired, Fallback: flowpolicy.Required}}, "")
	l.RecordFailure(id, tuple, "UDP_WORKER_CAPACITY", true)
	l.RecordDrop(id, tuple, "POLICY_BLOCK", true)
	f := l.Snapshot(1).Flows[0]
	if f.Route != "BLOCK" || !f.RequiredBlocked || f.FailureCause != "UDP_WORKER_CAPACITY" || f.Counters.Direct != 0 {
		t.Fatal(f)
	}
}

func TestUDPReplyTemplateBound(t *testing.T) {
	// Valid full-size packet, no payload retained in capture state.
	p := make([]byte, 1500)
	p[0] = 0x45
	p[9] = 17
	binary.BigEndian.PutUint16(p[2:], uint16(len(p)))
	binary.BigEndian.PutUint16(p[24:], 1480)
	copy(p[12:16], []byte{192, 0, 2, 1})
	copy(p[16:20], []byte{203, 0, 113, 2})
	binary.BigEndian.PutUint16(p[20:], 1234)
	binary.BigEndian.PutUint16(p[22:], 53)
	template := udpReplyTemplate(p)
	if len(template) != 28 {
		t.Fatal("payload retained", len(template))
	}
	reply, err := ReplyUDP(template, []byte("response"))
	if err != nil {
		t.Fatal(err)
	}
	tuple, payload, err := ParseUDP(reply)
	if err != nil || string(payload) != "response" || tuple.Source.Port() != 53 || tuple.Destination.Port() != 1234 {
		t.Fatal(tuple, err)
	}
}

func TestTCPAuthorizationEndIsNotGenericTransportFailure(t *testing.T) {
	for _, tc := range []struct {
		code quic.ApplicationErrorCode
		want string
	}{{protocol.LeaseExpiredCode, "TCP_AUTHORIZATION_LEASE_EXPIRED"}, {protocol.RevokedCode, "TCP_DEVICE_REVOKED"}} {
		err := &quic.ApplicationError{ErrorCode: tc.code}
		if got := tcpCopyFailure("reply", err, nil, false); got != tc.want {
			t.Fatal(got)
		}
	}
}
