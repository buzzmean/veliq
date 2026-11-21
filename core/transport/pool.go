package transport

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/buzzmean/neexitlag/core/routing"
	"github.com/buzzmean/neexitlag/core/telemetry"
	"github.com/quic-go/quic-go"
)

const PoolMaxSessions = 8
const PoolSessionFlows = 48 // retain headroom below the unchanged server's 64 streams/flows
var ErrCapacity = telemetry.ErrCapacity

type OpenError struct {
	Reason string
	Cause  error
}

func (e *OpenError) Error() string {
	if e.Cause == nil {
		return "relay open: " + e.Reason
	}
	return "relay open: " + e.Reason + ": " + e.Cause.Error()
}
func (e *OpenError) Unwrap() error         { return e.Cause }
func (e *OpenError) FailureReason() string { return e.Reason }
func FailureReason(err error) string {
	if err == nil {
		return ""
	}
	var e *OpenError
	if errors.As(err, &e) {
		return e.Reason
	}
	if errors.Is(err, ErrCapacity) {
		return "stream_capacity"
	}
	if errors.Is(err, context.Canceled) {
		return "caller_cancelled"
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return "open_timeout"
	}
	if errors.Is(err, ErrRelayRejected) {
		return "relay_rejected"
	}
	return openIOReason(err, "")
}

type SessionFactory func(context.Context) (*Client, error)
type PoolConfig struct {
	MaxSessions, SessionFlows, MaxWaiters   int
	ProbeReserve                            int
	CreateTimeout, RotateAfter, IdleTimeout time.Duration
}

func DefaultPoolConfig() PoolConfig {
	return PoolConfig{MaxSessions: PoolMaxSessions, SessionFlows: PoolSessionFlows, MaxWaiters: 256, ProbeReserve: 1, CreateTimeout: 3 * time.Second, RotateAfter: 25 * time.Minute, IdleTimeout: 2 * time.Minute}
}

type PoolSession struct {
	ID             uint64        `json:"id"`
	Healthy        bool          `json:"healthy"`
	Draining       bool          `json:"draining"`
	ActiveFlows    int           `json:"active_flows"`
	Capacity       int           `json:"capacity"`
	CreatedAt      time.Time     `json:"created_at"`
	CreationReason string        `json:"creation_reason"`
	Lease          LeaseSnapshot `json:"lease"`
	EndReason      string        `json:"end_reason,omitempty"`
}
type PoolOpenEvent struct {
	AcquireMS     float64   `json:"acquire_ms"`
	StreamOpenMS  float64   `json:"stream_open_ms"`
	SessionAgeMS  float64   `json:"session_age_ms"`
	At            time.Time `json:"at"`
	SessionID     uint64    `json:"session_id"`
	Protocol      string    `json:"protocol"`
	Destination   string    `json:"destination"`
	DurationMS    float64   `json:"duration_ms"`
	FailureReason string    `json:"failure_reason,omitempty"`
	Detail        string    `json:"detail,omitempty"`
}
type PoolSessionEnd struct {
	At     time.Time     `json:"at"`
	ID     uint64        `json:"session_id"`
	Reason string        `json:"reason"`
	Lease  LeaseSnapshot `json:"lease"`
}
type PoolSnapshot struct {
	SessionCreationMetrics     CreationMetrics   `json:"session_creation"`
	RecentSessionEnds          []PoolSessionEnd  `json:"recent_session_ends"`
	ApplicationMaximumCapacity int               `json:"application_maximum_capacity"`
	ProbeReservePerSession     int               `json:"probe_reserve_per_session"`
	AvailableCapacity          int               `json:"available_capacity"`
	Sessions                   []PoolSession     `json:"sessions"`
	ActiveSessions             int               `json:"active_sessions"`
	HealthySessions            int               `json:"healthy_sessions"`
	CreatingSessions           int               `json:"creating_sessions"`
	ActiveFlows                int               `json:"active_flows"`
	Capacity                   int               `json:"capacity"`
	MaximumCapacity            int               `json:"maximum_capacity"`
	SessionLimit               int               `json:"session_limit"`
	SessionFlowLimit           int               `json:"session_flow_limit"`
	WaitingOpens               int               `json:"waiting_opens"`
	SaturationEvents           uint64            `json:"saturation_events"`
	StreamCapacityEvents       uint64            `json:"stream_capacity_events"`
	SessionFailures            uint64            `json:"session_failures"`
	CreationFailures           uint64            `json:"creation_failures"`
	OpenCount                  uint64            `json:"open_count"`
	OpenFailures               uint64            `json:"open_failures"`
	OpenLatencySumMS           float64           `json:"open_latency_sum_ms"`
	OpenLatencyMaxMS           float64           `json:"open_latency_max_ms"`
	FailureReasons             map[string]uint64 `json:"failure_reasons"`
	RecentOpens                []PoolOpenEvent   `json:"recent_opens"`
}
type poolSession struct {
	failed                       bool
	client                       *Client
	id                           uint64
	active                       int
	born, lastUsed, blockedUntil time.Time
	draining                     bool
	reason                       string
}

// Pool is one relay identity/address and a fixed number of independent mTLS +
// fresh-ticket sessions. Leases never move between sessions. Credit exhaustion
// or setup on a dead session can retry before returning an application handle;
// established stream contents and sent application datagrams are never replayed.
type Pool struct {
	mu               sync.Mutex
	ctx              context.Context
	cancel           context.CancelFunc
	cfg              PoolConfig
	factory          SessionFactory
	sessions         []*poolSession
	changed          chan struct{}
	done             chan struct{}
	closed, creating bool
	waiters          int
	nextID           uint64
	retryAfter       time.Time
	createError      error
	onFailure        func(string)
	wg               sync.WaitGroup
	stats            PoolSnapshot
	creation         creationTelemetry
	retiredDrops     map[string]telemetry.Metric
}

func NewPool(ctx context.Context, cfg PoolConfig, factory SessionFactory) (*Pool, error) {
	if factory == nil || cfg.MaxSessions < 1 || cfg.MaxSessions > PoolMaxSessions || cfg.SessionFlows < 1 || cfg.SessionFlows > PoolSessionFlows || cfg.ProbeReserve < 0 || cfg.ProbeReserve > 1 || cfg.ProbeReserve >= cfg.SessionFlows || cfg.MaxWaiters < 1 || cfg.MaxWaiters > 256 || cfg.CreateTimeout <= 0 || cfg.CreateTimeout > 3*time.Second || cfg.RotateAfter <= 0 || cfg.RotateAfter > 25*time.Minute || cfg.IdleTimeout <= 0 {
		return nil, errors.New("invalid bounded relay pool configuration")
	}
	ctx, cancel := context.WithCancel(ctx)
	p := &Pool{ctx: ctx, cancel: cancel, cfg: cfg, factory: factory, changed: make(chan struct{}), done: make(chan struct{}), retiredDrops: map[string]telemetry.Metric{}}
	p.stats.FailureReasons = map[string]uint64{}
	p.wg.Add(1)
	go p.maintain()
	return p, nil
}
func (p *Pool) signalLocked()                     { close(p.changed); p.changed = make(chan struct{}) }
func (p *Pool) Done() <-chan struct{}             { return p.done }
func (p *Pool) Healthy() bool                     { return p.Snapshot().HealthySessions > 0 }
func (p *Pool) SetFailureHandler(fn func(string)) { p.mu.Lock(); p.onFailure = fn; p.mu.Unlock() }
func alive(c *Client) bool {
	select {
	case <-c.Done():
		return false
	default:
		return true
	}
}
func mergeDrops(out, next map[string]telemetry.Metric) {
	for k, v := range next {
		a := out[k]
		a.Count += v.Count
		a.Attempts += v.Attempts
		a.Available = v.Available
		a.Unit = v.Unit
		a.Fraction = nil
		if a.Attempts > 0 && a.Count <= a.Attempts {
			r := float64(a.Count) / float64(a.Attempts)
			a.Fraction = &r
		}
		out[k] = a
	}
}

// reapLocked never closes a busy healthy session. Dead sessions no longer own
// live QUIC resources, so replacing them does not consume an extra live slot.
func (p *Pool) reapLocked(now time.Time) {
	keep := p.sessions[:0]
	remaining := len(p.sessions)
	for _, s := range p.sessions {
		live := alive(s.client)
		if !live || s.active == 0 && (s.draining || remaining > 1 && now.Sub(s.lastUsed) > p.cfg.IdleTimeout) {
			s.failed = !live
			remaining--
			mergeDrops(p.retiredDrops, s.client.LocalDrops.Snapshot())
			s.client.Close()
			if !live {
				if len(p.stats.RecentSessionEnds) == 16 {
					p.stats.RecentSessionEnds = append([]PoolSessionEnd(nil), p.stats.RecentSessionEnds[1:]...)
				}
				p.stats.RecentSessionEnds = append(p.stats.RecentSessionEnds, PoolSessionEnd{now.UTC(), s.id, s.client.SessionEndReason(), s.client.Lease()})
				if reason := s.client.SessionEndReason(); reason == "authorization_lease_expired" || reason == "device_revoked" {
					p.stats.FailureReasons[reason]++
				} else {
					p.stats.SessionFailures++
				}
			}
			continue
		}
		if !s.client.Renewable() && now.Sub(s.born) >= p.cfg.RotateAfter {
			s.draining = true
		}
		keep = append(keep, s)
	}
	if len(keep) != len(p.sessions) {
		p.sessions = keep
		p.signalLocked()
	} else {
		p.sessions = keep
	}
}
func (p *Pool) maintain() {
	defer p.wg.Done()
	t := time.NewTicker(time.Second)
	defer t.Stop()
	for {
		select {
		case <-p.ctx.Done():
			return
		case now := <-t.C:
			p.mu.Lock()
			p.reapLocked(now)
			p.mu.Unlock()
		}
	}
}
func (p *Pool) create(reason string, factory SessionFactory) {
	defer p.wg.Done()
	start := time.Now()
	p.mu.Lock()
	p.creation.begin(start, reason)
	p.mu.Unlock()
	ctx, cancel := context.WithTimeout(p.ctx, p.cfg.CreateTimeout)
	c, err := factory(ctx)
	cancel()
	p.mu.Lock()
	p.creating = false
	p.creation.finish(time.Now(), start, reason, c, err)
	if p.closed || p.ctx.Err() != nil {
		if c != nil {
			c.Close()
		}
		p.signalLocked()
		p.mu.Unlock()
		return
	}
	if err == nil && c == nil {
		err = errors.New("nil relay session")
	}
	if err != nil {
		if c != nil {
			c.Close()
		}
		p.stats.CreationFailures++
		p.createError = err
		p.retryAfter = time.Now().Add(time.Second)
		p.signalLocked()
		fn := p.onFailure
		none := len(p.sessions) == 0
		p.mu.Unlock()
		if none && fn != nil {
			fn("relay_pool_unavailable")
		}
		return
	}
	p.nextID++
	s := &poolSession{client: c, id: p.nextID, born: time.Now(), lastUsed: time.Now(), reason: reason}
	p.sessions = append(p.sessions, s)
	p.retryAfter = time.Time{}
	p.createError = nil
	p.signalLocked()
	p.wg.Add(1)
	p.mu.Unlock()
	go func() {
		defer p.wg.Done()
		select {
		case <-c.Done():
		case <-p.ctx.Done():
			return
		}
		p.mu.Lock()
		p.reapLocked(time.Now())
		fn := p.onFailure
		none := s.failed && len(p.sessions) == 0 && !p.closed
		p.mu.Unlock()
		if end := c.SessionEndReason(); none && fn != nil && end != "authorization_lease_expired" && end != "device_revoked" {
			fn("relay_pool_sessions_closed")
		}
	}()
}
func (p *Pool) acquire(ctx context.Context, probe bool) (*poolSession, error) {
	waiting := false
	defer func() {
		if waiting {
			p.mu.Lock()
			p.waiters--
			p.mu.Unlock()
		}
	}()
	for {
		if err := ctx.Err(); err != nil {
			if waiting {
				return nil, p.admissionError(err)
			}
			return nil, err
		}
		p.mu.Lock()
		if p.closed || p.ctx.Err() != nil {
			p.mu.Unlock()
			return nil, ErrClosed
		}
		now := time.Now()
		p.reapLocked(now)
		var best *poolSession
		blocked := false
		for _, s := range p.sessions {
			if s.client.conn.Context().Err() != nil {
				blocked = true
				continue
			}
			limit := p.cfg.SessionFlows
			if !probe {
				limit -= p.cfg.ProbeReserve
			}
			if s.draining || s.active >= limit {
				continue
			}
			if now.Before(s.blockedUntil) {
				blocked = true
				continue
			}
			if best == nil || s.active < best.active {
				best = s
			}
		}
		if best != nil {
			best.active++
			best.lastUsed = now
			p.mu.Unlock()
			return best, nil
		}
		if !waiting && len(p.sessions) > 0 {
			p.stats.SaturationEvents++
		}
		if !p.creating && len(p.sessions) < p.cfg.MaxSessions {
			if now.Before(p.retryAfter) {
				err := p.createError
				if len(p.sessions) > 0 {
					err = errors.Join(ErrCapacity, err)
				}
				p.mu.Unlock()
				return nil, err
			}
			reason := "capacity"
			if len(p.sessions) == 0 {
				reason = "initial_bootstrap"
				if p.nextID > 0 {
					reason = "session_replacement"
				}
			}
			for _, s := range p.sessions {
				if s.draining {
					reason = "lease_rotation"
					break
				}
			}
			p.creating = true
			p.wg.Add(1)
			go p.create(reason, p.factory)
		}
		if !p.creating && !blocked {
			p.mu.Unlock()
			return nil, &OpenError{"pool_capacity", ErrCapacity}
		}
		if !waiting {
			if p.waiters >= p.cfg.MaxWaiters {
				p.mu.Unlock()
				return nil, &OpenError{"waiter_capacity", ErrCapacity}
			}
			p.waiters++
			waiting = true
		}
		ch := p.changed
		p.mu.Unlock()
		// Stream close credit can lag the local lease close. Never wait behind
		// OpenStreamSync; poll only that transient blocked session while selecting peers.
		timer := time.NewTimer(100 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil, p.admissionError(ctx.Err())
		case <-p.ctx.Done():
			timer.Stop()
			return nil, ErrClosed
		case <-ch:
			timer.Stop()
		case <-timer.C:
		}
	}
}
func (p *Pool) release(s *poolSession) {
	p.mu.Lock()
	s.active--
	s.lastUsed = time.Now()
	p.signalLocked()
	p.mu.Unlock()
}
func (p *Pool) Warm(ctx context.Context) error {
	s, err := p.acquire(ctx, false)
	if err == nil {
		p.release(s)
	}
	return err
}
func (p *Pool) record(start time.Time, sid uint64, kind string, dst netip.AddrPort, err error, acquire, stream time.Duration, age float64) {
	p.mu.Lock()
	defer p.mu.Unlock()
	ms := float64(time.Since(start)) / float64(time.Millisecond)
	p.stats.OpenCount++
	p.stats.OpenLatencySumMS += ms
	if ms > p.stats.OpenLatencyMaxMS {
		p.stats.OpenLatencyMaxMS = ms
	}
	reason := FailureReason(err)
	if err != nil {
		p.stats.OpenFailures++
		p.stats.FailureReasons[reason]++
	}
	detail := ""
	if err != nil {
		detail = err.Error()
		if len(detail) > 256 {
			detail = detail[:256]
		}
	}
	event := PoolOpenEvent{At: time.Now().UTC(), SessionID: sid, Protocol: kind, Destination: dst.String(), DurationMS: ms, FailureReason: reason, Detail: detail, AcquireMS: float64(acquire) / float64(time.Millisecond), StreamOpenMS: float64(stream) / float64(time.Millisecond), SessionAgeMS: age}
	if len(p.stats.RecentOpens) == 32 {
		copy(p.stats.RecentOpens, p.stats.RecentOpens[1:])
		p.stats.RecentOpens = p.stats.RecentOpens[:31]
	}
	p.stats.RecentOpens = append(p.stats.RecentOpens, event)
}
func (p *Pool) open(ctx context.Context, dst netip.AddrPort, tcp, probe bool) (net.Conn, routing.Datagram, error) {
	start := time.Now()
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	var sid uint64
	var acquireTime, streamTime time.Duration
	age := -1.0
	var final error
	kind := "udp"
	if tcp {
		kind = "tcp"
	}
	defer func() { p.record(start, sid, kind, dst, final, acquireTime, streamTime, age) }()
	for {
		acquireStart := time.Now()
		s, err := p.acquire(ctx, probe)
		acquireTime += time.Since(acquireStart)
		if err != nil {
			final = &OpenError{FailureReason(err), err}
			return nil, nil, final
		}
		sid = s.id
		age = float64(time.Since(s.born)) / float64(time.Millisecond)
		streamStart := time.Now()
		var conn net.Conn
		var dg *UDPFlow
		if tcp {
			conn, err = s.client.OpenTCP(ctx, dst)
		} else {
			dg, err = s.client.OpenUDP(ctx, dst)
		}
		streamTime += time.Since(streamStart)
		if err == nil {
			if tcp {
				return &pooledConn{Conn: conn, release: func() { p.release(s) }}, nil, nil
			}
			return nil, &pooledDatagram{Datagram: dg, session: s.client, release: func() { p.release(s) }}, nil
		}
		p.release(s)
		if errors.Is(err, ErrCapacity) {
			p.mu.Lock()
			p.stats.StreamCapacityEvents++
			s.blockedUntil = time.Now().Add(100 * time.Millisecond)
			p.mu.Unlock()
			continue
		}
		if s.client.conn.Context().Err() != nil {
			if ctx.Err() == nil {
				continue
			} // setup only: no application handle or bytes have been returned
			if p.Healthy() {
				err = errors.Join(telemetry.ErrIsolatedSession, err)
			}
			reason := s.client.SessionEndReason()
			if reason == "" {
				reason = "session_closed"
			}
			final = &OpenError{reason, err}
			return nil, nil, final
		}
		// No retry after a live-session OPEN rejection or a successful upstream.

		final = &OpenError{FailureReason(err), err}
		return nil, nil, final
	}
}
func (p *Pool) OpenTCP(ctx context.Context, dst netip.AddrPort) (net.Conn, error) {
	c, _, e := p.open(ctx, dst, true, false)
	return c, e
}
func (p *Pool) OpenDatagram(ctx context.Context, dst netip.AddrPort) (routing.Datagram, error) {
	_, d, e := p.open(ctx, dst, false, false)
	return d, e
}
func (p *Pool) Snapshot() PoolSnapshot {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := p.stats
	out.SessionCreationMetrics = p.creation.snapshot(time.Now())
	out.Sessions = []PoolSession{}
	out.RecentSessionEnds = append([]PoolSessionEnd(nil), p.stats.RecentSessionEnds...)
	out.RecentOpens = append([]PoolOpenEvent(nil), p.stats.RecentOpens...)
	out.FailureReasons = map[string]uint64{}
	for k, v := range p.stats.FailureReasons {
		out.FailureReasons[k] = v
	}
	out.SessionLimit = p.cfg.MaxSessions
	out.SessionFlowLimit = p.cfg.SessionFlows
	out.MaximumCapacity = p.cfg.MaxSessions * p.cfg.SessionFlows
	out.ApplicationMaximumCapacity = p.cfg.MaxSessions * (p.cfg.SessionFlows - p.cfg.ProbeReserve)
	out.ProbeReservePerSession = p.cfg.ProbeReserve
	out.WaitingOpens = p.waiters
	if p.creating {
		out.CreatingSessions = 1
	}
	for _, s := range p.sessions {
		healthy := !p.closed && s.client.conn.Context().Err() == nil && alive(s.client)
		out.ActiveSessions++
		if healthy {
			out.HealthySessions++
			out.ActiveFlows += s.active
			if !s.draining {
				out.Capacity += p.cfg.SessionFlows
				if !time.Now().Before(s.blockedUntil) {
					out.AvailableCapacity += max(0, p.cfg.SessionFlows-p.cfg.ProbeReserve-s.active)
				}
			}
		}
		out.Sessions = append(out.Sessions, PoolSession{s.id, healthy, s.draining, s.active, p.cfg.SessionFlows, s.born.UTC(), s.reason, s.client.Lease(), s.client.SessionEndReason()})
	}
	return out
}
func (p *Pool) DropSnapshot() map[string]telemetry.Metric {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := map[string]telemetry.Metric{}
	mergeDrops(out, p.retiredDrops)
	for _, s := range p.sessions {
		mergeDrops(out, s.client.LocalDrops.Snapshot())
	}
	return out
}
func (p *Pool) Close() error {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		<-p.done
		return nil
	}
	p.closed = true
	p.cancel()
	p.signalLocked()
	all := append([]*poolSession(nil), p.sessions...)
	p.mu.Unlock()
	for _, s := range all {
		s.client.Close()
	}
	p.wg.Wait()
	close(p.done)
	return nil
}

type pooledConn struct {
	net.Conn
	once    sync.Once
	release func()
}

func (c *pooledConn) Close() error { err := c.Conn.Close(); c.once.Do(c.release); return err }
func (c *pooledConn) CloseWrite() error {
	if s, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return s.CloseWrite()
	}
	return errors.New("half-close unsupported")
}

type pooledDatagram struct {
	session *Client
	routing.Datagram
	once    sync.Once
	release func()
}

func (d *pooledDatagram) Close() error { err := d.Datagram.Close(); d.once.Do(d.release); return err }

// Classify nonblocking QUIC credit exhaustion before any OPEN frame is sent.
func streamCapacity(err error) error {
	var limit *quic.StreamLimitReachedError
	if errors.As(err, &limit) {
		return fmt.Errorf("%w: QUIC stream credit", ErrCapacity)
	}
	return err
}

// UpdateFactory changes only future authenticated sessions. Existing leases stay
// on their original session; endpoint changes drain instead of migrating them.
func (p *Pool) UpdateFactory(factory SessionFactory, drain bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.factory = factory
	if drain {
		for _, s := range p.sessions {
			s.draining = true
		}
	}
	p.signalLocked()
}

// Probe failures are scoped to the actual session. A dead session must not poison
// healthy peers; real missing replies on a live session retain normal loss rules.
func (p *Pool) OpenProbeDatagram(ctx context.Context, dst netip.AddrPort) (routing.Datagram, error) {
	_, d, err := p.open(ctx, dst, false, true)
	if err != nil {
		return nil, err
	}
	return &poolProbe{Datagram: d, pool: p, session: d.(*pooledDatagram).session}, nil
}

type poolProbe struct {
	routing.Datagram
	pool    *Pool
	session *Client
}

func (d *poolProbe) scoped(err error) error {
	if err != nil && (d.session.conn.Context().Err() != nil || !alive(d.session)) && d.pool.Healthy() {
		return errors.Join(telemetry.ErrIsolatedSession, err)
	}
	return err
}
func (d *poolProbe) Send(b []byte) error { return d.scoped(d.Datagram.Send(b)) }
func (d *poolProbe) Receive(ctx context.Context) ([]byte, error) {
	b, err := d.Datagram.Receive(ctx)
	return b, d.scoped(err)
}

func (p *Pool) admissionError(err error) error {
	if errors.Is(err, context.Canceled) {
		return err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, s := range p.sessions {
		if s.client.conn.Context().Err() == nil && alive(s.client) {
			return &OpenError{"admission_timeout", errors.Join(ErrCapacity, err)}
		}
	}
	return err
}
