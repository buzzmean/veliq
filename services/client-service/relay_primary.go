package clientservice

import (
	"context"
	"net"
	"net/netip"
	"sort"
	"sync"
	"time"

	"github.com/buzzmean/neexitlag/core/optimizer"
	"github.com/buzzmean/neexitlag/core/routing"
	"github.com/buzzmean/neexitlag/core/transport"
)

// A signed, well-known P0 primary node has its OWN ticket audience/replay cache.
// VPS-01 is only the local policy/provider name; its tickets are NEVER reused for
// VPS-PRIMARY. Existing opened sockets retain their original provider.
const primaryRelayID = "VPS-PRIMARY"

type primaryRelayPool interface {
	routing.Relay
	Healthy() bool
}
type primaryUsage struct {
	ID                    string `json:"authenticated_relay_id"`
	Address               string `json:"configured_address"`
	Endpoint              string `json:"observed_tcp_session_endpoint"`
	Opens, Active, TX, RX uint64
	Healthy               bool      `json:"pool_healthy"`
	Health                string    `json:"health"`
	RTTMS                 float64   `json:"probe_rtt_ms"`
	ProbeObserved         time.Time `json:"probe_observed_at"`
	Failures              uint64    `json:"new_open_failures"`
	LastFailure           string    `json:"last_failure_class"`
}
type relayPrimaryRuntime struct {
	mu               sync.Mutex
	rows             map[string]primaryUsage
	primary, standby string
	standbyID        string
	last, reason     string
	provider         *primaryRelayProvider
	preferStandby    bool
	holdUntil        time.Time
	healthySince     time.Time
	selectionReason  string
	switches         uint64
}

func newRelayPrimary() *relayPrimaryRuntime {
	return &relayPrimaryRuntime{rows: map[string]primaryUsage{}}
}
func (r *relayPrimaryRuntime) snapshot() map[string]any {
	r.mu.Lock()
	p := r.provider
	r.mu.Unlock()
	if p != nil {
		p.order() // Refresh health/return hysteresis even when no application opens.
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	rows := []primaryUsage{}
	for _, v := range r.rows {
		rows = append(rows, v)
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].ID < rows[j].ID })
	preferred := primaryRelayID
	if r.preferStandby {
		preferred = r.standbyID
	}
	if r.provider == nil {
		preferred = "PRIMARY_PROVIDER_NOT_CONFIGURED"
	}
	return map[string]any{"policy_relay_id": "VPS-01", "configured_primary": r.primary, "configured_standby": r.standby, "configured_standby_id": r.standbyID, "last_opened_authenticated_relay": r.last, "reason": r.reason, "connections": rows, "preferred_for_new_opens": preferred, "selection_reason": r.selectionReason, "standby_hold_until": r.holdUntil, "primary_healthy_since": r.healthySince, "selection_switches": r.switches, "hysteresis_seconds": 30, "existing_tcp": "PINNED; no replay/migration; configured primary alone is not traffic proof", "ticket_audiences": "unique server IDs; fresh ticket per session; no shared logical audience on two servers"}
}

type primaryRelayProvider struct {
	primary, standby               primaryRelayPool
	primaryAddress, standbyAddress string
	standbyID                      string
	runtime                        *relayPrimaryRuntime
	quality                        func(time.Time) map[string]optimizer.Quality
	now                            func() time.Time
}

const primaryRecoveryHold = 30 * time.Second

func (p *primaryRelayProvider) standbyIdentity() string {
	if p.standbyID != "" {
		return p.standbyID
	}
	return "VPS-01"
}

// Keep the current standby while registered; a future replacement has its own
// signed ID/ticket audience. Deterministic choice, not a load balancer.
func standbyCandidate(nodes []optimizer.RelayCandidate) string {
	ids := []string{}
	for _, n := range nodes {
		if n.ID == "VPS-01" {
			return n.ID
		}
		if n.ID != "" && n.ID != primaryRelayID && n.ID != optimizer.Direct {
			ids = append(ids, n.ID)
		}
	}
	sort.Strings(ids)
	if len(ids) > 0 {
		return ids[0]
	}
	return ""
}

func (p *primaryRelayProvider) clock() time.Time {
	if p.now != nil {
		return p.now()
	}
	return time.Now()
}

// Shared across signed-config polls; an unrelated config refresh must not erase
// a hold-down. No pool lock is held while the runtime lock or a transport opens.
func (r *relayPrimaryRuntime) configure(p *primaryRelayProvider, primary, standby string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	standbyID := ""
	if p != nil {
		standbyID = p.standbyIdentity()
	}
	if r.primary != primary || r.standby != standby || r.standbyID != standbyID {
		r.preferStandby = false
		r.holdUntil, r.healthySince = time.Time{}, time.Time{}
	}
	r.provider, r.primary, r.standby, r.standbyID = p, primary, standby, standbyID
	for id, row := range r.rows {
		if id != primaryRelayID && id != standbyID {
			if row.Active == 0 {
				delete(r.rows, id)
				continue
			}
			row.Healthy, row.Health = false, "RETIRED_PROVIDER; EXISTING_STREAMS_ONLY"
			r.rows[id] = row
		}
	}
	if p == nil {
		r.selectionReason = "PRIMARY_PROVIDER_NOT_CONFIGURED; SEE_LEGACY_POOL"
		for id, row := range r.rows {
			row.Healthy = false
			row.Health = "NOT_CONFIGURED"
			r.rows[id] = row
		}
	}
}

func relayPoolAvailable(pool primaryRelayPool, q optimizer.Quality, now time.Time) (bool, bool, string) {
	alive := pool != nil && pool.Healthy()
	if !alive {
		return false, false, "NO_HEALTHY_SESSION"
	}
	// The existing authenticated echo quality detector already ignores admission
	// saturation and isolated session failures. Do not reinterpret a single origin
	// timeout/stream-capacity error as a failed VPS or invent a throughput estimate.
	if !q.ObservedAt.IsZero() && !q.ObservedAt.After(now) && now.Sub(q.ObservedAt) <= optimizer.QualityWindow {
		if q.Health == "unhealthy" || q.Health == "recovering" {
			return false, true, "AUTHENTICATED_PROBE_" + q.Health
		}
		return true, true, "SESSION_ALIVE; PROBE_" + q.Health
	}
	return true, true, "SESSION_ALIVE; PROBE_UNKNOWN_OR_STALE"
}

func (p *primaryRelayProvider) order() (primaryRelayPool, string, string, primaryRelayPool, string, string) {
	now := p.clock()
	qs := map[string]optimizer.Quality{}
	if p.quality != nil {
		qs = p.quality(now)
	}
	pgood, palive, ph := relayPoolAvailable(p.primary, qs[primaryRelayID], now)
	sgood, salive, sh := relayPoolAvailable(p.standby, qs[p.standbyIdentity()], now)
	r := p.runtime
	r.mu.Lock()
	if r.provider != nil && r.provider != p {
		r.mu.Unlock()
		// An already selected provider may finish its open, but cannot overwrite
		// selection state of a newer signed config/endpoint generation.
		return p.primary, primaryRelayID, p.primaryAddress, p.standby, p.standbyIdentity(), p.standbyAddress
	}
	for _, v := range []struct {
		id, address, health string
		alive               bool
	}{{primaryRelayID, p.primaryAddress, ph, palive}, {p.standbyIdentity(), p.standbyAddress, sh, salive}} {
		row := r.rows[v.id]
		row.ID, row.Address, row.Healthy, row.Health = v.id, v.address, v.alive, v.health
		q := qs[v.id]
		row.RTTMS, row.ProbeObserved = float64(q.LatestRTT)/float64(time.Millisecond), q.ObservedAt
		r.rows[v.id] = row
	}
	before := r.preferStandby
	switch {
	case !pgood && sgood:
		if !r.preferStandby {
			r.holdUntil = now.Add(primaryRecoveryHold)
		}
		r.preferStandby, r.healthySince, r.selectionReason = true, time.Time{}, "PRIMARY_UNAVAILABLE_STANDBY"
	case pgood && !sgood:
		r.preferStandby, r.healthySince, r.selectionReason = false, now, "STANDBY_UNAVAILABLE_PRIMARY"
	case pgood && sgood && r.preferStandby:
		q := qs[primaryRelayID]
		verified := p.quality == nil || q.Health == "healthy" && q.ReplyCount > 0 && !q.ObservedAt.After(now) && now.Sub(q.ObservedAt) <= optimizer.QualityWindow
		if !verified {
			r.healthySince, r.selectionReason = time.Time{}, "STANDBY_HELD_WAITING_AUTHENTICATED_RECOVERY"
		} else {
			if r.healthySince.IsZero() {
				r.healthySince = now
			}
			r.selectionReason = "STANDBY_HELD_PRIMARY_RECOVERING"
			newProof := p.quality == nil || q.ObservedAt.After(r.healthySince)
			if newProof && !now.Before(r.holdUntil) && now.Sub(r.healthySince) >= primaryRecoveryHold {
				r.preferStandby, r.selectionReason = false, "PRIMARY_SUSTAINED_RECOVERY"
			}
		}
	case !pgood && !sgood:
		r.healthySince, r.selectionReason = time.Time{}, "BOTH_UNAVAILABLE_AUTHENTICATED_OPENS_ONLY"
	default:
		r.selectionReason = "SIGNED_PRIMARY_HEALTHY"
	}
	if before != r.preferStandby {
		r.switches++
	}
	standby := r.preferStandby && p.standby != nil
	r.mu.Unlock()
	if standby {
		return p.standby, p.standbyIdentity(), p.standbyAddress, p.primary, primaryRelayID, p.primaryAddress
	}
	return p.primary, primaryRelayID, p.primaryAddress, p.standby, p.standbyIdentity(), p.standbyAddress
}

func providerFailure(reason string) bool {
	switch reason {
	case "caller_cancelled", "stream_capacity", "pool_capacity", "admission_timeout", "device_revoked", "authorization_lease_expired", "upstream_dial_timeout", "upstream_connection_refused", "upstream_dial_failed":
		return false
	default:
		return true
	}
}

func (p *primaryRelayProvider) failed(id string, pool primaryRelayPool, err error) {
	if err == nil {
		return
	}
	reason := transport.FailureReason(err)
	// An error string can contain remote data. Only the bounded classification is
	// published; it never grants DIRECT and never closes unrelated live sessions.
	switch reason {
	case "stream_capacity", "pool_capacity", "admission_timeout", "caller_cancelled", "open_timeout", "open_ack_timeout", "upstream_dial_timeout", "upstream_connection_refused", "upstream_dial_failed", "relay_rejected", "open_io_failed", "open_stream_reset", "open_ack_eof", "device_revoked", "authorization_lease_expired", "ticket_request_failed", "session_auth_or_dial_failed":
	default:
		reason = "transport_open_failed"
	}
	alive := pool != nil && pool.Healthy()
	r := p.runtime
	r.mu.Lock()
	row := r.rows[id]
	row.Failures++
	row.LastFailure = reason
	r.rows[id] = row
	if p.standby != nil && (r.provider == nil || r.provider == p) && id == primaryRelayID && !alive && providerFailure(reason) {
		if !r.preferStandby {
			r.switches++
			r.holdUntil = p.clock().Add(primaryRecoveryHold)
		}
		r.preferStandby, r.healthySince, r.selectionReason = true, time.Time{}, "PRIMARY_OPEN_FAILED_NO_HEALTHY_SESSION"
	}
	r.mu.Unlock()
}
func (p *primaryRelayProvider) opened(id, address, endpoint, reason string) func() {
	r := p.runtime
	r.mu.Lock()
	v := r.rows[id]
	v.ID = id
	v.Address = address
	if endpoint != "UDP_ENDPOINT_NOT_EXPOSED_BY_POOL" {
		v.Endpoint = endpoint
	}
	v.Opens++
	v.Active++
	r.rows[id] = v
	r.last = id
	r.reason = reason
	r.mu.Unlock()
	var once sync.Once
	return func() {
		once.Do(func() {
			r.mu.Lock()
			v := r.rows[id]
			if v.Active > 0 {
				v.Active--
			}
			r.rows[id] = v
			r.mu.Unlock()
		})
	}
}
func (p *primaryRelayProvider) OpenTCP(ctx context.Context, dst netip.AddrPort) (net.Conn, error) {
	first, id, address, second, other, otherAddress := p.order()
	attempt, stop := context.WithTimeout(ctx, 1500*time.Millisecond)
	conn, err := first.OpenTCP(attempt, dst)
	stop()
	p.failed(id, first, err)
	reason := "SIGNED_PRIMARY_HEALTHY"
	if id != "VPS-PRIMARY" {
		reason = "STANDBY_SELECTED_FOR_NEW_OPEN"
	}
	if err != nil && ctx.Err() == nil && second != nil {
		conn, err = second.OpenTCP(ctx, dst)
		id, address = other, otherAddress
		p.failed(id, second, err)
		reason = "NEW_OPEN_FAILED_OTHER_AUTHENTICATED_RELAY"
	}
	if err != nil {
		return nil, err
	}
	closeCount := p.opened(id, address, conn.RemoteAddr().String(), reason)
	return &primaryMeter{Conn: conn, runtime: p.runtime, id: id, release: closeCount}, nil
}
func (p *primaryRelayProvider) OpenDatagram(ctx context.Context, dst netip.AddrPort) (routing.Datagram, error) {
	first, id, address, second, other, otherAddress := p.order()
	attempt, stop := context.WithTimeout(ctx, 1500*time.Millisecond)
	flow, err := first.OpenDatagram(attempt, dst)
	stop()
	p.failed(id, first, err)
	reason := "SIGNED_PRIMARY_HEALTHY"
	if id != primaryRelayID {
		reason = "STANDBY_SELECTED_FOR_NEW_OPEN"
	}
	if err != nil && ctx.Err() == nil && second != nil {
		flow, err = second.OpenDatagram(ctx, dst)
		id, address = other, otherAddress
		p.failed(id, second, err)
		reason = "NEW_OPEN_FAILED_OTHER_AUTHENTICATED_RELAY"
	}
	if err != nil {
		return nil, err
	}
	return &primaryDatagram{Datagram: flow, runtime: p.runtime, id: id, release: p.opened(id, address, "UDP_ENDPOINT_NOT_EXPOSED_BY_POOL", reason)}, nil
}

type primaryMeter struct {
	net.Conn
	runtime *relayPrimaryRuntime
	id      string
	release func()
}

func (m *primaryMeter) Read(b []byte) (int, error) {
	n, e := m.Conn.Read(b)
	m.runtime.add(m.id, 0, uint64(n))
	return n, e
}
func (m *primaryMeter) Write(b []byte) (int, error) {
	n, e := m.Conn.Write(b)
	m.runtime.add(m.id, uint64(n), 0)
	return n, e
}
func (m *primaryMeter) Close() error { e := m.Conn.Close(); m.release(); return e }
func (m *primaryMeter) CloseWrite() error {
	if v, ok := m.Conn.(interface{ CloseWrite() error }); ok {
		return v.CloseWrite()
	}
	return nil
}
func (r *relayPrimaryRuntime) add(id string, tx, rx uint64) {
	r.mu.Lock()
	v := r.rows[id]
	v.TX += tx
	v.RX += rx
	r.rows[id] = v
	r.mu.Unlock()
}

type primaryDatagram struct {
	routing.Datagram
	runtime *relayPrimaryRuntime
	id      string
	release func()
}

func (d *primaryDatagram) Send(b []byte) error {
	e := d.Datagram.Send(b)
	if e == nil {
		d.runtime.add(d.id, uint64(len(b)), 0)
	}
	return e
}
func (d *primaryDatagram) Receive(ctx context.Context) ([]byte, error) {
	b, e := d.Datagram.Receive(ctx)
	d.runtime.add(d.id, 0, uint64(len(b)))
	return b, e
}
func (d *primaryDatagram) Close() error { e := d.Datagram.Close(); d.release(); return e }

// These are routing providers only. They cannot return DIRECT, even when both
// authenticated relays fail. Explicit flowpolicy fail-closed is unchanged.
