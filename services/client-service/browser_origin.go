package clientservice

import (
	"net"
	"sync"

	"github.com/buzzmean/neexitlag/core/browserproxy"
	"github.com/buzzmean/neexitlag/core/flowpolicy"
)

// The TCP socket returned by WinDivert delegation hides the QUIC error type.
// Observe/retry at the REAL relay stream; expose metadata across that handoff.
// An authorization/session reset must not quarantine an otherwise healthy IP.
type originReportRef struct {
	mu       sync.Mutex
	reporter browserproxy.OriginReporter
}

func (r *originReportRef) set(conn net.Conn) {
	if v, ok := conn.(browserproxy.OriginReporter); ok {
		r.mu.Lock()
		r.reporter = v
		r.mu.Unlock()
	}
}
func (r *originReportRef) OriginAttempts() browserproxy.OriginReport {
	r.mu.Lock()
	v := r.reporter
	r.mu.Unlock()
	if v != nil {
		return v.OriginAttempts()
	}
	return browserproxy.OriginReport{State: "NATIVE_ORIGIN_NOT_INSTRUMENTED", Attempts: []browserproxy.OriginAttempt{}}
}

type originPACConn struct {
	net.Conn
	report *originReportRef
}

func (c *originPACConn) OriginAttempts() browserproxy.OriginReport { return c.report.OriginAttempts() }
func (c *originPACConn) CloseWrite() error {
	if w, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return w.CloseWrite()
	}
	return nil
}
func relayOriginEligible(q browserproxy.Request, p browserproxy.Plan) bool {
	return q.Secure && q.Port != 53 && p.Enabled && p.Policy.Action == flowpolicy.RelayRequired && p.Policy.Fallback == flowpolicy.Required && browserproxy.ValidPublicDNSName(q.Host)
}
