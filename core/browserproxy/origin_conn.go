package browserproxy

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"sync"
	"syscall"
	"time"
)

const OriginAttemptsLimit = 3
const OriginSilenceTimeout = 900 * time.Millisecond
const OriginRecoveryBudget = 4 * time.Second

var ErrOriginCandidatePolicy = errors.New("ORIGIN_CANDIDATE_POLICY_BLOCK")
var ErrOriginRecovery = errors.New("ORIGIN_ADDRESSES_EXHAUSTED")
var ErrOriginReplayUnsafe = errors.New("ORIGIN_FIRST_FLIGHT_NOT_REPLAYABLE")
var ErrOriginScopeChanged = errors.New("ORIGIN_SCOPE_CHANGED")

type OriginAttempt struct {
	Destination string `json:"destination"`
	Reason      string `json:"reason"`
}
type OriginReport struct {
	Attempts        []OriginAttempt `json:"attempts"`
	Selected        string          `json:"selected"`
	AddressAttempts int             `json:"addresses_tried"`
	ReplayedBytes   uint64          `json:"client_hello_replayed_bytes"`
	NegativeSkipped int             `json:"negative_cache_skips"`
	DNS             string          `json:"dns"`
	State           string          `json:"state"`
}
type OriginReporter interface{ OriginAttempts() OriginReport }
type OriginConfig struct {
	// Optional finite first-flight route stepper. It is separate from IP recovery,
	// uses its own health scope, and is never entered after ANY origin byte.
	NextFlow  func(context.Context, string) (net.Conn, error)
	OnFailure func(string)
	Silence   time.Duration

	Prior      []OriginAttempt
	Skipped    int
	Context    context.Context
	Health     *OriginHealth
	Scope      string
	Initial    netip.AddrPort
	Candidates []netip.AddrPort
	Resolve    func(context.Context) (DNSAnswer, error)
	Open       func(context.Context, netip.AddrPort) (net.Conn, error)
	// Destination OPEN failures only. Auth/session errors never poison an IP.
	RetryOpen func(error) bool
	// Optional immutable owner/policy scope guard. Recheck before learning or
	// first-flight recovery; it never moves or closes an established stream.
	ScopeCurrent func() bool
}
type originConn struct {
	net.Conn
	cfg                                                         OriginConfig
	readGate                                                    sync.Mutex
	writeGate                                                   sync.Mutex
	stateEvent                                                  chan struct{}
	replayed                                                    net.Conn
	firstWrite, done                                            chan struct{}
	gate                                                        sync.RWMutex // serialize first-flight replay with ALL concurrent writes
	mu                                                          sync.Mutex
	cur                                                         net.Conn
	report                                                      OriginReport
	tried                                                       map[netip.AddrPort]bool
	destination                                                 netip.AddrPort
	first, attemptAt, readDeadline, writeDeadline               time.Time
	timer                                                       *time.Timer
	stopContext                                                 func() bool
	closed, responded, progressed, overflow, halfClosed, failed bool
	flight                                                      []byte
	wire                                                        TLSWireObserver
}

func WatchRelayOrigin(conn net.Conn, cfg OriginConfig) net.Conn {
	x := &originConn{Conn: conn, cur: conn, stateEvent: make(chan struct{}, 1), firstWrite: make(chan struct{}), done: make(chan struct{}), cfg: cfg, destination: cfg.Initial, tried: map[netip.AddrPort]bool{cfg.Initial: true}, report: OriginReport{Selected: cfg.Initial.String(), AddressAttempts: 1, State: "WAITING_CLIENT_HELLO", NegativeSkipped: cfg.Skipped, Attempts: []OriginAttempt{{Destination: cfg.Initial.String(), Reason: "OPEN"}}}}
	if len(cfg.Prior) > 0 {
		x.report.Attempts = append(append([]OriginAttempt(nil), cfg.Prior...), x.report.Attempts...)
		x.report.AddressAttempts = len(x.report.Attempts)
		for _, a := range cfg.Prior {
			if ip, e := netip.ParseAddrPort(a.Destination); e == nil {
				x.tried[ip] = true
			}
		}
	}
	stop := context.AfterFunc(cfg.Context, func() { x.Close() })
	x.mu.Lock()
	x.stopContext = stop
	closed := x.closed
	x.mu.Unlock()
	if closed {
		stop()
	}
	return x
}
func (x *originConn) silence() time.Duration {
	if x.cfg.Silence > 0 {
		return x.cfg.Silence
	}
	return OriginSilenceTimeout
}
func (x *originConn) scopeCurrent() bool {
	return x.cfg.ScopeCurrent == nil || x.cfg.ScopeCurrent()
}
func (x *originConn) checkScope() error {
	if x.scopeCurrent() {
		return nil
	}
	x.mu.Lock()
	x.report.State = "ORIGIN_SCOPE_CHANGED"
	x.mu.Unlock()
	return ErrOriginScopeChanged
}
func (x *originConn) OriginAttempts() OriginReport {
	x.mu.Lock()
	defer x.mu.Unlock()
	r := x.report
	r.Attempts = append([]OriginAttempt(nil), r.Attempts...)
	return r
}
func (x *originConn) Write(p []byte) (int, error) {
	x.writeGate.Lock()
	defer x.writeGate.Unlock()
	x.gate.RLock()
	x.mu.Lock()
	if x.closed {
		x.mu.Unlock()
		x.gate.RUnlock()
		return 0, net.ErrClosed
	}
	if len(p) > 0 && x.first.IsZero() {
		x.first = time.Now()
		x.attemptAt = x.first
		x.report.State = "WAITING_ORIGIN"
		x.timer = time.AfterFunc(OriginRecoveryBudget, func() { x.closeWithReason("RECOVERY_BUDGET_EXPIRED", true) })
		close(x.firstWrite)
	}
	cur := x.cur
	deadline := x.writeDeadline
	if !x.responded && !x.overflow {
		if len(x.flight)+len(p) > maxReplay {
			x.flight = nil
			x.overflow = true
		} else {
			x.flight = append(x.flight, p...)
		}
	}
	if !x.responded && !x.first.IsZero() {
		hard := x.first.Add(OriginRecoveryBudget)
		if deadline.IsZero() || hard.Before(deadline) {
			deadline = hard
		}
	}
	x.mu.Unlock()
	cur.SetWriteDeadline(deadline)
	n, err := cur.Write(p)
	x.gate.RUnlock()
	if err != nil && (errors.Is(err, io.EOF) || errors.Is(err, syscall.EPIPE) || errors.Is(err, syscall.ECONNRESET)) {
		if retry := x.retry(cur, "ORIGIN_EARLY_WRITE_CLOSED", false); retry == nil {
			return len(p), nil
		}
	}
	return n, err
}
func (x *originConn) Read(p []byte) (int, error) {
	x.readGate.Lock()
	defer func() { x.readGate.Unlock(); x.notifyState() }()
	if len(p) == 0 {
		return 0, nil
	}
	for {
		x.mu.Lock()
		cur, first, at, responded, deadline, closed := x.cur, x.first, x.attemptAt, x.responded, x.readDeadline, x.closed
		x.mu.Unlock()
		if closed {
			return 0, net.ErrClosed
		}
		if !responded {
			wake := time.Now().Add(100 * time.Millisecond)
			if !first.IsZero() && at.Add(x.silence()).Before(wake) {
				wake = at.Add(x.silence())
			}
			if deadline.IsZero() || wake.Before(deadline) {
				cur.SetReadDeadline(wake)
			} else {
				cur.SetReadDeadline(deadline)
			}
		} else {
			cur.SetReadDeadline(deadline)
		}
		n, err := cur.Read(p)
		if n > 0 {
			x.wire.ObserveOrigin(p[:n])
			reply := x.wire.Snapshot().Origin
			completeHello := reply.ServerHelloComplete
			x.mu.Lock()
			x.responded = true
			x.flight = nil
			if !x.failed {
				x.report.State = "ORIGIN_BYTES_NO_REPLAY"
			}
			if completeHello {
				x.progressed = true
				if x.timer != nil {
					x.timer.Stop()
				}
			}
			x.mu.Unlock()
			x.observeEarlyFailure(err)
			return n, err // NEVER discard, consume or replay even a single origin byte.
		}
		if err == nil {
			continue
		}
		if responded {
			x.observeEarlyFailure(err)
			return 0, err
		}
		if !deadline.IsZero() && !time.Now().Before(deadline) {
			return 0, err
		}
		if errors.Is(err, os.ErrDeadlineExceeded) && (first.IsZero() || time.Since(at) < x.silence()) {
			continue
		}
		if first.IsZero() && (errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF)) {
			timer := time.NewTimer(x.silence())
			select {
			case <-x.firstWrite:
				timer.Stop()
				x.mu.Lock()
				first = x.first
				x.mu.Unlock()
			case <-x.done:
				timer.Stop()
				return 0, net.ErrClosed
			case <-timer.C:
				return 0, err
			}
		}
		if first.IsZero() || !(errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, syscall.ECONNRESET) || errors.Is(err, os.ErrDeadlineExceeded)) {
			return 0, err
		}
		reason := "ORIGIN_EOF_NO_BYTES"
		if errors.Is(err, os.ErrDeadlineExceeded) {
			reason = "ORIGIN_SILENT"
		}
		if err = x.retry(cur, reason, true); err != nil {
			return 0, err
		}
	}
}
func (x *originConn) observeEarlyFailure(err error) {
	s := x.wire.Snapshot().Origin
	reason := ""
	switch {
	case s.State == "TLS_PLAINTEXT_ALERT_COMPLETE":
		reason = "EARLY_TLS_ALERT_NO_REPLAY"
	case s.State == "NON_TLS_OR_INVALID_HEADER":
		reason = "INVALID_TLS_HEADER_NO_REPLAY"
	case errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF):
		if !s.ServerHelloComplete {
			reason = "EARLY_TLS_EOF_NO_REPLAY"
		}
	}
	if reason != "" {
		x.fail(reason)
	}
}
func (x *originConn) fail(reason string) {
	if x.checkScope() != nil {
		return
	}
	x.mu.Lock()
	if x.failed {
		x.mu.Unlock()
		return
	}
	x.failed = true
	ip := x.destination
	x.report.State = reason
	if len(x.report.Attempts) > 0 {
		x.report.Attempts[len(x.report.Attempts)-1].Reason = reason
	}
	x.mu.Unlock()
	x.cfg.Health.Failed(x.cfg.Scope, ip, time.Now())
	if x.cfg.OnFailure != nil {
		x.cfg.OnFailure(reason)
	}
}
func (x *originConn) retry(expected net.Conn, reason string, fromRead bool) (retErr error) {
	// A writer cannot replay while another reader has observed bytes but has not
	// yet published responded. Read-triggered retry already owns this mutex.
	if !fromRead {
		for {
			x.mu.Lock()
			closed, responded, changed, committed := x.closed, x.responded, x.cur != expected, x.replayed == x.cur
			x.mu.Unlock()
			if closed {
				return net.ErrClosed
			}
			if changed && committed {
				return nil
			}
			if responded {
				return net.ErrClosed
			}
			if x.readGate.TryLock() {
				break
			}
			select {
			case <-x.stateEvent:
			case <-x.done:
				return net.ErrClosed
			case <-x.cfg.Context.Done():
				return net.ErrClosed
			}
		}
		defer x.readGate.Unlock()
	}
	x.gate.Lock()
	defer x.gate.Unlock()
	defer func() {
		if retErr != nil && !errors.Is(retErr, net.ErrClosed) {
			x.Close()
		}
	}()
	x.mu.Lock()
	if x.closed {
		x.mu.Unlock()
		return net.ErrClosed
	}
	if x.cur != expected {
		x.mu.Unlock()
		return nil
	}
	if x.responded {
		x.mu.Unlock()
		return net.ErrClosed
	}
	if x.overflow || !clientHelloFlight(x.flight) {
		x.report.State = "UNSAFE_FIRST_FLIGHT_NO_REPLAY"
		x.mu.Unlock()
		return ErrOriginReplayUnsafe
	}
	flight := append([]byte(nil), x.flight...)
	hard := x.first.Add(OriginRecoveryBudget)
	callerDeadline := x.writeDeadline
	if fromRead {
		callerDeadline = x.readDeadline
	}
	if !callerDeadline.IsZero() && callerDeadline.Before(hard) {
		hard = callerDeadline
	}
	old := x.cur
	x.mu.Unlock()
	if err := x.checkScope(); err != nil {
		return err
	}
	x.fail(reason)
	old.Close() // free exact old Engine reservation; established traffic is not moved
	if err := x.checkScope(); err != nil {
		return err
	}
	ctx, stop := context.WithDeadline(x.cfg.Context, hard)
	defer stop()
	if x.cfg.NextFlow != nil {
		next, err := x.cfg.NextFlow(ctx, reason)
		if stale := x.checkScope(); stale != nil {
			if next != nil {
				next.Close()
			}
			return stale
		}
		if err != nil {
			return err
		}
		x.mu.Lock()
		if x.closed {
			x.mu.Unlock()
			next.Close()
			return net.ErrClosed
		}
		x.cur = next
		x.failed = false
		deadline := x.writeDeadline
		x.mu.Unlock()
		if deadline.IsZero() || hard.Before(deadline) {
			deadline = hard
		}
		next.SetWriteDeadline(deadline)
		for len(flight) > 0 {
			n, e := next.Write(flight)
			if n < 0 || n > len(flight) {
				next.Close()
				return io.ErrShortWrite
			}
			flight = flight[n:]
			if e != nil {
				next.Close()
				return e
			}
			if n == 0 {
				next.Close()
				return io.ErrShortWrite
			}
		}
		x.mu.Lock()
		x.replayed = next
		x.attemptAt = time.Now()
		half := x.halfClosed
		x.report.State = "ROUTE_FIRST_FLIGHT_RETRY"
		// The finite child owns all further retries. The parent must not race its
		// own shorter silence deadline against that child's LOCAL/RELAY step.
		x.responded = true
		x.progressed = true
		x.flight = nil
		if x.timer != nil {
			x.timer.Stop()
		}
		x.mu.Unlock()
		x.notifyState()
		if half {
			if c, ok := next.(interface{ CloseWrite() error }); ok {
				c.CloseWrite()
			}
		}
		return nil
	}
	candidates := append([]netip.AddrPort(nil), x.cfg.Candidates...)
	queried := false
	for {
		if err := x.checkScope(); err != nil {
			return err
		}
		x.mu.Lock()
		attempts := x.report.AddressAttempts
		x.mu.Unlock()
		if attempts >= OriginAttemptsLimit || ctx.Err() != nil {
			return ErrOriginRecovery
		}
		ip, skipped := x.cfg.Health.Pick(x.cfg.Scope, candidates, x.tried, time.Now())
		x.mu.Lock()
		x.report.NegativeSkipped += skipped
		x.mu.Unlock()
		if !ip.IsValid() {
			if queried || x.cfg.Resolve == nil {
				return ErrOriginRecovery
			}
			queried = true
			q, cancel := context.WithTimeout(ctx, 750*time.Millisecond)
			answer, err := x.cfg.Resolve(q)
			cancel()
			if stale := x.checkScope(); stale != nil {
				return stale
			}
			x.mu.Lock()
			x.report.DNS = "RELAY_DOH_FAILED"
			if err == nil {
				x.report.DNS = "RELAY_DOH"
			}
			x.mu.Unlock()
			if err != nil {
				return ErrOriginRecovery
			}
			for _, a := range answer.Addresses {
				candidates = append(candidates, netip.AddrPortFrom(a, x.cfg.Initial.Port()))
			}
			continue
		}
		x.tried[ip] = true
		x.mu.Lock()
		x.report.AddressAttempts++
		x.report.Attempts = append(x.report.Attempts, OriginAttempt{Destination: ip.String(), Reason: "OPEN_PENDING"})
		x.mu.Unlock()
		open, cancel := context.WithTimeout(ctx, 900*time.Millisecond)
		next, err := x.cfg.Open(open, ip)
		cancel()
		if stale := x.checkScope(); stale != nil {
			if next != nil {
				next.Close()
			}
			return stale
		}
		if err != nil {
			x.mu.Lock()
			x.report.Attempts[len(x.report.Attempts)-1].Reason = openFailure(err)
			x.mu.Unlock()
			if x.cfg.RetryOpen == nil || !x.cfg.RetryOpen(err) {
				return err
			}
			x.cfg.Health.Failed(x.cfg.Scope, ip, time.Now())
			continue
		}
		x.mu.Lock()
		if x.closed {
			x.mu.Unlock()
			next.Close()
			return net.ErrClosed
		}
		x.cur = next
		x.destination = ip
		x.failed = false
		x.report.Selected = ip.String()
		x.report.Attempts[len(x.report.Attempts)-1].Reason = "CLIENT_HELLO_RETRY"
		deadline := x.writeDeadline
		x.mu.Unlock()
		if deadline.IsZero() || hard.Before(deadline) {
			deadline = hard
		}
		next.SetWriteDeadline(deadline)
		for len(flight) > 0 {
			n, e := next.Write(flight)
			x.mu.Lock()
			x.report.ReplayedBytes += uint64(n)
			x.mu.Unlock()
			flight = flight[n:]
			if e != nil {
				return e
			}
			if n == 0 {
				return io.ErrShortWrite
			}
		}
		x.mu.Lock()
		x.attemptAt = time.Now()
		half := x.halfClosed
		x.mu.Unlock()
		x.mu.Lock()
		x.replayed = next
		x.report.State = "WAITING_ORIGIN_RETRY"
		x.mu.Unlock()
		x.notifyState()
		if half {
			if c, ok := next.(interface{ CloseWrite() error }); ok {
				c.CloseWrite()
			}
		}
		return nil
	}
}
func (x *originConn) Close() error { return x.closeWithReason("", false) }
func (x *originConn) closeWithReason(reason string, beforeReply bool) error {
	x.mu.Lock()
	if x.closed || beforeReply && x.progressed {
		x.mu.Unlock()
		return nil
	}
	quarantine := beforeReply && x.responded
	if quarantine {
		reason = "EARLY_TLS_REPLY_TIMEOUT_NO_REPLAY"
	}
	ip := x.destination
	x.closed = true
	close(x.done)
	x.flight = nil
	cur := x.cur
	if reason != "" {
		x.failed = true
		x.report.State = reason
		if len(x.report.Attempts) > 0 {
			x.report.Attempts[len(x.report.Attempts)-1].Reason = reason
		}
	}
	if x.timer != nil {
		x.timer.Stop()
	}
	stop := x.stopContext
	x.mu.Unlock()
	if stop != nil {
		stop()
	}
	current := x.scopeCurrent()
	if quarantine && current {
		x.cfg.Health.Failed(x.cfg.Scope, ip, time.Now())
	}
	if reason != "" && current && x.cfg.OnFailure != nil {
		x.cfg.OnFailure(reason)
	}
	return cur.Close()
}
func (x *originConn) CloseWrite() error {
	x.gate.RLock()
	defer x.gate.RUnlock()
	x.mu.Lock()
	x.halfClosed = true
	cur := x.cur
	x.mu.Unlock()
	if c, ok := cur.(interface{ CloseWrite() error }); ok {
		return c.CloseWrite()
	}
	return nil
}
func (x *originConn) SetDeadline(t time.Time) error {
	x.mu.Lock()
	x.readDeadline = t
	x.writeDeadline = t
	cur := x.cur
	x.mu.Unlock()
	return cur.SetDeadline(t)
}
func (x *originConn) SetReadDeadline(t time.Time) error {
	x.mu.Lock()
	x.readDeadline = t
	cur := x.cur
	x.mu.Unlock()
	return cur.SetReadDeadline(t)
}
func (x *originConn) SetWriteDeadline(t time.Time) error {
	x.mu.Lock()
	x.writeDeadline = t
	cur := x.cur
	x.mu.Unlock()
	return cur.SetWriteDeadline(t)
}

// RetargetOrigin never transfers HTTP/TLS proof from one IP to another. Routing
// action/relay/fallback are immutable; only destination and probe evidence change.
func RetargetOrigin(p Plan, dst netip.AddrPort) Plan {
	if dst != p.Destination {
		p.Destination = dst
		p.Probe = "ORIGIN_IP_SELECTED_TLS_UNVERIFIED"
		p.HTTPStatus = 0
		p.DNSRecovery = nil
		if p.Policy.Source == "browser_dns_recovered" {
			p.Policy.Source = "browser_origin_ip_health"
			p.Policy.Reason = "alternative IP before origin response; browser retains TLS/certificate verification"
		}
	}
	return p
}

func (x *originConn) notifyState() {
	select {
	case x.stateEvent <- struct{}{}:
	default:
	}
}
