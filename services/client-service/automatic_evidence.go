package clientservice

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"time"
)

// Additive, passive observations shared by automatic and browser diagnostics.
// These fields never drive routing, mark a page successful, or infer why an
// encrypted application rejected a request. In TLS1.3 even handshake records
// use type23: an encrypted record is not evidence of an application response.
type connectionEvidence struct {
	ObservedAt  time.Time `json:"observed_at"`
	Connection  string    `json:"connection_state"`
	Transport   string    `json:"transport_state"`
	TLS         string    `json:"tls_state"`
	Application string    `json:"application_state"`
	Failure     string    `json:"failure_class"`
	Cause       string    `json:"failure_cause"`
}

type connectionIO struct {
	At        time.Time `json:"at"`
	Operation string    `json:"operation"`
	Outcome   string    `json:"outcome"`
}

func snapshotConnectionEvidence(r nativeBrowserRecord) nativeBrowserRecord {
	if r.LastIO != nil {
		v := *r.LastIO
		r.LastIO = &v
	}
	if r.planReporter != nil {
		p := r.planReporter.CurrentPlan()
		r.Policy, r.Upstream, r.Probe = p.Policy, p.Destination.String(), p.Probe
	}
	if r.originReporter != nil {
		v := r.originReporter.OriginAttempts()
		r.Origin = &v
		// First-flight route steppers have no initial IP. Their placeholder
		// "invalid AddrPort" must not overwrite a real plan destination.
		if dst, err := netip.ParseAddrPort(v.Selected); err == nil && dst.IsValid() {
			r.Upstream = dst.String()
		}
	}
	if r.tlsWire != nil {
		v := r.tlsWire.Snapshot()
		r.TLS = &v
	}
	e := &connectionEvidence{ObservedAt: time.Now().UTC(), Connection: "OPEN", Transport: "NO_DATA", TLS: "NOT_OBSERVED", Application: "NOT_VERIFIED", Failure: "NONE_OBSERVED", Cause: "UNKNOWN"}
	switch {
	case r.Result == "PLANNING":
		e.Connection = "PLANNING"
	case r.Failure != "":
		e.Connection, e.Failure = "FAILED", "CONNECTION_FAILURE"
	case !r.Active:
		e.Connection = "CLOSED"
	}
	switch {
	case r.Sent > 0 && r.Received > 0:
		e.Transport = "BIDIRECTIONAL_BYTES"
	case r.Received > 0:
		e.Transport = "ORIGIN_BYTES"
	case r.Sent > 0:
		e.Transport = "SENT_NO_ORIGIN_BYTES"
	}
	// A caller's polling deadline can expire on a healthy socket. Keep that
	// historical observation in LastIO, never promote it to a route failure.
	if r.LastIO != nil && r.LastIO.Outcome == "IO_ERROR" {
		e.Failure = r.LastIO.Outcome
	}
	// Unlike a caller polling deadline, these are terminal states of our own
	// bounded first-flight guard. Closing the socket must not hide that verdict.
	if r.Origin != nil {
		switch r.Origin.State {
		case "RECOVERY_BUDGET_EXPIRED", "EARLY_TLS_REPLY_TIMEOUT_NO_REPLAY":
			e.Connection, e.Failure = "FAILED", "FIRST_FLIGHT_TIMEOUT"
		case "UNSAFE_FIRST_FLIGHT_NO_REPLAY":
			e.Connection, e.Failure = "FAILED", "RETRY_NOT_SAFE"
		}
	}
	if r.TLS != nil {
		o := r.TLS.Origin
		switch {
		case o.State == "TLS_PLAINTEXT_ALERT_COMPLETE":
			e.TLS, e.Failure = "PLAINTEXT_ALERT_OBSERVED", "TLS_ALERT"
		case o.State == "NON_TLS_OR_INVALID_HEADER":
			e.TLS = "NON_TLS_OR_INVALID_HEADER"
		case o.ServerHelloComplete && o.ApplicationRecords > 0:
			e.TLS = "ENCRYPTED_RECORDS_OBSERVED"
		case o.ServerHelloComplete:
			e.TLS = "SERVER_HELLO_OBSERVED"
		case o.Bytes > 0:
			e.TLS = "ORIGIN_TLS_INCOMPLETE"
		case r.TLS.Client.ClientHelloBytes > 0:
			e.TLS = "CLIENT_HELLO_HEADER_OBSERVED"
		}
	}
	r.Evidence = e
	return r
}

func (n *nativeBrowserRuntime) observeIOEnd(id uint64, operation string, err error) {
	if err == nil {
		return
	}
	// Never retain Error(): it can include destinations or application text.
	outcome := "IO_ERROR"
	var ne net.Error
	switch {
	case errors.Is(err, context.Canceled):
		outcome = "CANCELED"
	case errors.Is(err, net.ErrClosed):
		outcome = "SOCKET_CLOSED"
	case errors.Is(err, io.EOF):
		outcome = "PEER_EOF"
	case errors.Is(err, context.DeadlineExceeded), errors.As(err, &ne) && ne.Timeout():
		outcome = "IO_TIMEOUT"
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	r, ok := n.records[id]
	if !ok {
		return
	}
	// An EOF/timeout on the other half or cleanup must not erase an observed
	// transport error. LastIO is the last significant end event, not an error log.
	if r.LastIO != nil && ((r.LastIO.Outcome == "IO_ERROR" && outcome != "IO_ERROR") || outcome == "CANCELED" || outcome == "SOCKET_CLOSED") {
		return
	}
	r.LastIO = &connectionIO{At: time.Now().UTC(), Operation: operation, Outcome: outcome}
	n.records[id] = r
	n.notifyLocked()
}
