package browserproxy

import (
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
)

// Observe the first directional I/O termination BEFORE our own teardown. A
// cleanup-induced net.ErrClosed must not overwrite the actual upstream failure.
// EOF is only observed input shutdown; it is not proof of a browser preconnect.
// Optional TLS instrumentation keeps bounded framing metadata only; application
// payload is never inspected, retained or replayed.
type tunnelCloseEvidence struct {
	tlsWire    *TLSWireObserver
	ctx        context.Context
	forcing    atomic.Bool
	clientData atomic.Bool
	originData atomic.Bool
	mu         sync.Mutex
	reason     string
}

func (t *tunnelCloseEvidence) terminal(side string, err error) {
	if err == nil || t.forcing.Load() {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.reason != "" || t.forcing.Load() {
		return
	}
	switch {
	case t.ctx != nil && t.ctx.Err() != nil:
		t.reason = "SERVICE_STOP"
	case isTimeout(err) || errors.Is(err, context.DeadlineExceeded):
		t.reason = "TIMEOUT"
	case errors.Is(err, net.ErrClosed) || errors.Is(err, context.Canceled):
		t.reason = "LOCAL_CANCELLED_OR_CLOSED"
	case side == "client-read" && errors.Is(err, io.EOF):
		t.reason = "CLIENT_CLOSED_BEFORE_REPLY"
		if !t.clientData.Load() {
			t.reason = "CLIENT_CLOSED_BEFORE_REQUEST"
		}
	case side == "client-read":
		t.reason = "CLIENT_INPUT_ERROR"
	case side == "client-write":
		t.reason = "CLIENT_DELIVERY_ERROR"
	case side == "upstream-read" && errors.Is(err, io.EOF):
		t.reason = "UPSTREAM_EOF"
		if !t.clientData.Load() {
			t.reason = "UPSTREAM_EOF_WITHOUT_REQUEST"
		}
	default:
		t.reason = "UPSTREAM_ERROR"
	}
}
func (t *tunnelCloseEvidence) cause() string {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.reason != "" {
		return t.reason
	}
	if t.ctx != nil && t.ctx.Err() != nil {
		return "SERVICE_STOP"
	}
	return "UNCLASSIFIED"
}

type closeReader struct {
	io.Reader
	evidence *tunnelCloseEvidence
	client   bool
}

func (r closeReader) Read(p []byte) (int, error) {
	n, e := r.Reader.Read(p)
	side := "upstream-read"
	if r.client {
		side = "client-read"
		if n > 0 {
			r.evidence.clientData.Store(true)
		}
	} else if n > 0 {
		r.evidence.originData.Store(true)
		if r.evidence.tlsWire != nil {
			r.evidence.tlsWire.ObserveOrigin(p[:n])
		}
	}
	r.evidence.terminal(side, e)
	return n, e
}

type closeWriter struct {
	io.Writer
	evidence *tunnelCloseEvidence
	client   bool
}

func (w closeWriter) Write(p []byte) (int, error) {
	n, e := w.Writer.Write(p)
	side := "upstream-write"
	if n > 0 && !w.client && w.evidence.tlsWire != nil {
		w.evidence.tlsWire.ObserveClient(p[:n])
	}
	if w.client {
		side = "client-write"
	}
	w.evidence.terminal(side, e)
	return n, e
}
func noReplyFailure(err error) string {
	var capacity interface{ FailureReason() string }
	if errors.As(err, &capacity) && capacity.FailureReason() == "OPAQUE_GOOGLE_RELAY_ADMISSION_CAPACITY" {
		return "OPAQUE_GOOGLE_ADMISSION"
	}
	if errors.Is(err, ErrVideoRelayAdmission) {
		return "GOOGLEVIDEO_ADMISSION"
	}
	code := openFailure(err)
	if isTimeout(err) || errors.Is(err, context.DeadlineExceeded) || strings.Contains(code, "TIMEOUT") {
		return "TIMEOUT"
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, net.ErrClosed) {
		return "LOCAL_CANCELLED_OR_CLOSED"
	}
	return "UPSTREAM_ERROR"
}
