package clientservice

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"math"
	"net"
	"net/netip"
	"sort"
	"sync"
	"time"

	"github.com/buzzmean/veliq/core/optimizer"
	"github.com/buzzmean/veliq/core/routing"
	"github.com/buzzmean/veliq/core/transport"
)

const (
	fleetCandidateLimit = 2
	fleetLoadTTL        = 45 * time.Second
	fleetSwitchHold     = 30 * time.Second
)

type fleetPool interface {
	OpenFleetTCP(context.Context, netip.AddrPort) (net.Conn, error)
	OpenFleetDatagram(context.Context, netip.AddrPort) (routing.Datagram, error)
}

type fleetNode struct {
	id, address string
	weight      float64
	canary      bool
	observed    time.Time
	pool        fleetPool
}

type fleetAffinity struct {
	node            fleetNode
	pending, active int
}

type fleetFailureKey struct {
	node        string
	destination netip.AddrPort
}

type fleetFailure struct {
	until   time.Time
	repeats uint
	reason  string
}

type relayFleet struct {
	mu                                sync.Mutex
	budget                            transport.FleetBudget
	network                           func() string
	now                               func() time.Time
	device                            string
	epoch                             uint64
	expires                           time.Time
	nodes                             []fleetNode
	affinity                          map[string]*fleetAffinity
	failures                          map[fleetFailureKey]fleetFailure
	detectors                         map[string]*optimizer.RouteSelector
	observedNetwork                   string
	shortlistNetwork                  string
	preferred, challenger             string
	challengerSince, challengerSample time.Time
	samples                           int
	lastNode, reason                  string
	emptyReason                       string
	scopeApplication                  string
}

func newRelayFleet(network func() string) *relayFleet {
	return &relayFleet{
		network: network, now: time.Now,
		affinity:  make(map[string]*fleetAffinity),
		failures:  make(map[fleetFailureKey]fleetFailure),
		detectors: make(map[string]*optimizer.RouteSelector),
		reason:    "disabled",
	}
}

func (f *relayFleet) Enabled() bool { return f.budget.Enabled() }

// A scoped canary keeps unrelated implicit relay applications on their
// existing provider. The empty scope retains the normal device-wide policy.
func (f *relayFleet) ManagesFlow(flow routing.Flow) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.scopeApplication == "" || flow.ApplicationID == f.scopeApplication
}

func (f *relayFleet) setScope(application string) {
	f.mu.Lock()
	f.scopeApplication = application
	f.mu.Unlock()
}

// arm runs before a configured client's pools can Warm. Until verified policy
// arrives, the fleet provider rejects new implicit relay opens.
func (f *relayFleet) arm(device string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.device != device {
		f.affinity = make(map[string]*fleetAffinity)
	}
	f.device, f.epoch, f.expires = device, 0, time.Time{}
	f.nodes = nil
	f.shortlistNetwork = ""
	f.resetQualityLocked("")
	f.budget.SetEnabled(true)
	f.reason = "fleet_policy_unavailable"
}

// configure consumes authenticated policy, including explicit rollback.
func (f *relayFleet) configure(epoch uint64, expires time.Time, enabled bool, nodes []fleetNode, emptyReason string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(nodes) > fleetCandidateLimit || epoch < f.epoch || !expires.After(f.now()) {
		return
	}
	if !enabled && f.budget.Enabled() && epoch <= f.epoch {
		return
	}
	for _, old := range f.nodes {
		if !f.probeNodeIn(nodes, old.id, old.address, f.now()) {
			delete(f.detectors, old.id)
			if f.preferred == old.id {
				f.preferred = ""
			}
		}
	}
	f.epoch, f.expires, f.nodes = epoch, expires, append([]fleetNode(nil), nodes...)
	f.budget.SetEnabled(enabled)
	f.reason, f.emptyReason = "policy_ready", emptyReason
	if enabled && len(nodes) == 0 {
		f.reason = emptyReason
	}
	if !enabled {
		f.reason = "signed_rollback"
	}
}

func (f *relayFleet) resetQualityLocked(network string) {
	f.observedNetwork = network
	f.detectors = make(map[string]*optimizer.RouteSelector)
	f.failures = make(map[fleetFailureKey]fleetFailure)
	f.preferred, f.challenger, f.samples = "", "", 0
}

func (f *relayFleet) suspend() {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.budget.Enabled() {
		f.expires = time.Time{}
		f.reason = "fleet_policy_unavailable"
	}
}

func (f *relayFleet) probeAllowed(id, address string, now time.Time) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.budget.Enabled() && now.Before(f.expires) && f.probeNodeIn(f.nodes, id, address, now)
}

func (*relayFleet) probeNodeIn(nodes []fleetNode, id, address string, now time.Time) bool {
	for _, node := range nodes {
		if node.id == id && node.address == address && node.observed.Add(fleetLoadTTL).After(now) {
			return true
		}
	}
	return false
}

func (f *relayFleet) observe(m optimizer.RouteMeasurement) {
	if !m.AuthenticatedTarget || m.Network == "" || m.Network != f.network() {
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	now := f.now()
	if !f.budget.Enabled() || !now.Before(f.expires) || !f.probeNodeIn(f.nodes, m.RouteID, m.RouteAddress, now) {
		return
	}
	if f.observedNetwork != m.Network {
		f.resetQualityLocked(m.Network)
	}
	if f.detectors[m.RouteID] == nil {
		f.detectors[m.RouteID] = optimizer.New(optimizer.DefaultParameters())
	}
	f.detectors[m.RouteID].Observe(m)
}

// A deterministic exponential race yields weighted rendezvous assignment.
// Neither network identity nor destinations are included in IPC.
func fleetRank(device, network, node string, weight float64) float64 {
	sum := sha256.Sum256([]byte(device + "\x00" + network + "\x00" + node))
	n := binary.BigEndian.Uint64(sum[:8]) >> 11
	u := (float64(n) + 1) / (float64(1<<53) + 2)
	return -math.Log(u) / weight
}

func (f *relayFleet) shortlist(nodes []fleetNode, network string) []fleetNode {
	f.mu.Lock()
	defer f.mu.Unlock()
	previous := make(map[string]string, len(f.nodes))
	if f.shortlistNetwork == network {
		for _, node := range f.nodes {
			previous[node.id] = node.address
		}
	}
	f.shortlistNetwork = network
	bound := f.affinity[network]
	priority := func(node fleetNode) int {
		switch {
		case bound != nil && bound.node.id == node.id && bound.node.address == node.address:
			return 0
		case node.canary:
			return 1
		case previous[node.id] == node.address:
			return 2
		default:
			return 3
		}
	}
	out := append([]fleetNode(nil), nodes...)
	sort.SliceStable(out, func(i, j int) bool {
		if a, b := priority(out[i]), priority(out[j]); a != b {
			return a < b
		}
		a := fleetRank(f.device, network, out[i].id, out[i].weight)
		b := fleetRank(f.device, network, out[j].id, out[j].weight)
		if a == b {
			return out[i].id < out[j].id
		}
		return a < b
	})
	return out[:min(len(out), fleetCandidateLimit)]
}

type fleetAttempt struct {
	scope string
	group *fleetAffinity
}

func (f *relayFleet) reserve(flow routing.Flow, excluded string) (fleetAttempt, error) {
	network, now := f.network(), f.now()
	f.mu.Lock()
	defer f.mu.Unlock()
	reject := func(reason string) (fleetAttempt, error) {
		f.reason = reason
		return fleetAttempt{}, &transport.OpenError{Reason: reason}
	}
	if !f.budget.Enabled() || !f.expires.After(now) {
		return reject("fleet_policy_unavailable")
	}
	if network == "" || flow.Network != "" && flow.Network != network {
		return reject("fleet_network_unverified")
	}
	if f.observedNetwork != network {
		f.resetQualityLocked(network)
	}
	quality := make(map[string]optimizer.Quality, len(f.nodes))
	var candidates []fleetNode
	reason := f.emptyReason
	for _, node := range f.nodes {
		if node.id == excluded || node.pool == nil {
			continue
		}
		q, blocked := f.eligibleQuality(node, flow.Destination, now)
		if blocked != "" {
			reason = blocked
			continue
		}
		quality[node.id] = q
		candidates = append(candidates, node)
	}
	if current := f.affinity[network]; current != nil {
		for _, node := range candidates {
			if node.id == current.node.id && node.address == current.node.address {
				current.pending++
				return fleetAttempt{network, current}, nil
			}
		}
		return reject("fleet_affinity_unavailable")
	}
	if len(candidates) == 0 {
		if reason == "" {
			reason = "fleet_capacity_exhausted"
		}
		return reject(reason)
	}
	if len(f.affinity) >= 16 {
		return reject("fleet_affinity_capacity")
	}
	selected := f.chooseLocked(candidates, quality, network, now, excluded != "")
	current := &fleetAffinity{node: selected, pending: 1}
	f.affinity[network] = current
	return fleetAttempt{network, current}, nil
}

func (f *relayFleet) eligibleQuality(node fleetNode, destination netip.AddrPort, now time.Time) (optimizer.Quality, string) {
	if !node.observed.Add(fleetLoadTTL).After(now) {
		return optimizer.Quality{}, "fleet_load_stale"
	}
	if node.weight <= 0 {
		return optimizer.Quality{}, "fleet_capacity_exhausted"
	}
	if now.Before(f.failures[fleetFailureKey{node: node.id, destination: destination}].until) {
		return optimizer.Quality{}, "fleet_destination_failure"
	}
	if failure := f.failures[fleetFailureKey{node: node.id}]; now.Before(failure.until) {
		if failure.reason == "fleet_capacity_exhausted" {
			return optimizer.Quality{}, failure.reason
		}
		return optimizer.Quality{}, "fleet_circuit_open"
	}
	detector := f.detectors[node.id]
	if detector == nil {
		return optimizer.Quality{}, "fleet_quality_unverified"
	}
	q := detector.Qualities(now)[node.id]
	if q.Health == "unhealthy" || q.Health == "recovering" {
		return q, "fleet_circuit_open"
	}
	if math.IsInf(optimizer.QualityScore(q, 0), 1) {
		return q, "fleet_quality_unverified"
	}
	return q, ""
}

func (f *relayFleet) chooseLocked(nodes []fleetNode, qualities map[string]optimizer.Quality, network string, now time.Time, retry bool) fleetNode {
	sort.SliceStable(nodes, func(i, j int) bool {
		return optimizer.QualityScore(qualities[nodes[i].id], 0) < optimizer.QualityScore(qualities[nodes[j].id], 0)
	})
	best := nodes[0]
	top := qualities[best.id]
	topRank := fleetRank(f.device, network, best.id, best.weight)
	for _, candidate := range nodes[1:] {
		q := qualities[candidate.id]
		if q.MedianRTT > top.MedianRTT+10*time.Millisecond || top.MedianRTT > q.MedianRTT+10*time.Millisecond ||
			optimizer.QualityScore(q, 0) > optimizer.QualityScore(top, 0)+10 {
			continue
		}
		rank := fleetRank(f.device, network, candidate.id, candidate.weight)
		if rank < topRank {
			best, topRank = candidate, rank
		}
	}
	if retry {
		return best
	}
	for _, node := range nodes {
		if node.id != f.preferred {
			continue
		}
		if node.id == best.id {
			f.challenger, f.samples = "", 0
			return best
		}
		if f.challenger != best.id {
			f.challenger, f.challengerSince, f.challengerSample, f.samples = best.id, now, best.observed, 1
		} else if best.observed.After(f.challengerSample) {
			f.challengerSample, f.samples = best.observed, f.samples+1
		}
		if now.Sub(f.challengerSince) < fleetSwitchHold || f.samples < 2 {
			return node
		}
	}
	f.preferred, f.challenger, f.samples = best.id, "", 0
	return best
}

func (f *relayFleet) finish(attempt fleetAttempt, flow routing.Flow, err error) (func(), bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	group := attempt.group
	group.pending--
	if err == nil {
		f.lastNode, f.reason = group.node.id, "authenticated_open"
		group.active++
		var once sync.Once
		return func() {
			once.Do(func() {
				f.mu.Lock()
				defer f.mu.Unlock()
				group.active--
				f.clearIdle(attempt)
			})
		}, false
	}
	reason, retry, origin := fleetOpenFailure(err)
	f.reason = reason
	if retry {
		key := fleetFailureKey{node: group.node.id}
		if origin {
			key.destination = flow.Destination
		}
		f.backoffLocked(key, reason)
	}
	return nil, f.clearIdle(attempt) && retry
}

func (f *relayFleet) clearIdle(attempt fleetAttempt) bool {
	if attempt.group.active != 0 || attempt.group.pending != 0 || f.affinity[attempt.scope] != attempt.group {
		return false
	}
	delete(f.affinity, attempt.scope)
	return true
}

func (f *relayFleet) backoffLocked(key fleetFailureKey, reason string) {
	now := f.now()
	for k, entry := range f.failures {
		if now.Sub(entry.until) > time.Minute {
			delete(f.failures, k)
		}
	}
	if _, known := f.failures[key]; !known && len(f.failures) >= 64 {
		return
	}
	entry := f.failures[key]
	delay := time.Second << min(entry.repeats, 5)
	sum := sha256.Sum256([]byte(f.device + key.node))
	jitter := time.Duration(binary.BigEndian.Uint16(sum[:2])%250) * time.Millisecond
	entry.until = now.Add(min(30*time.Second, delay+jitter))
	entry.repeats++
	entry.reason = reason
	f.failures[key] = entry
}

func fleetOpenFailure(err error) (reason string, retry, origin bool) {
	switch transport.FailureReason(err) {
	case "fleet_session_capacity", "fleet_stream_capacity", "fleet_waiter_capacity", "pool_capacity", "waiter_capacity",
		"stream_capacity", "admission_timeout", "relay_flow_capacity", "relay_draining":
		return "fleet_capacity_exhausted", true, false
	case "upstream_dial_timeout", "upstream_connection_refused", "upstream_dial_failed":
		return "fleet_destination_failure", true, true
	case "relay_destination_denied":
		return "fleet_destination_denied", false, true
	case "session_closed", "session_transport_closed", "session_network_unavailable",
		"open_ack_timeout", "open_ack_eof", "open_stream_reset", "open_request_write_timeout":
		return "fleet_transport_failure", true, false
	case "ticket_request_failed", "session_auth_or_dial_failed", "device_revoked", "authorization_lease_expired", "authorization_expired_or_revoked":
		return "fleet_auth_or_handshake_failed", false, false
	case "caller_cancelled", "open_timeout":
		return "fleet_cancelled", false, false
	default:
		return "fleet_open_failed", false, false
	}
}

func openFleet[T interface{ Close() error }](f *relayFleet, ctx context.Context, flow routing.Flow, open func(fleetPool, context.Context, netip.AddrPort) (T, error)) (T, string, func(), error) {
	var none T
	ctx, end := context.WithTimeout(ctx, 3*time.Second)
	defer end()
	var excluded string
	var last error
	for i := 0; i < fleetCandidateLimit; i++ {
		if err := ctx.Err(); err != nil {
			return none, "", nil, err
		}
		attempt, err := f.reserve(flow, excluded)
		if err != nil {
			if last != nil {
				return none, "", nil, last
			}
			return none, "", nil, err
		}
		node := attempt.group.node
		dial, stop := context.WithTimeout(ctx, 1500*time.Millisecond)
		conn, err := open(node.pool, dial, flow.Destination)
		stop()
		if err == nil && ctx.Err() != nil {
			_ = conn.Close()
			err = ctx.Err()
		}
		release, retry := f.finish(attempt, flow, err)
		if err == nil {
			return conn, node.id, release, nil
		}
		last, excluded = err, node.id
		if !retry {
			break
		}
	}
	return none, "", nil, last
}

type fleetStream struct {
	net.Conn
	release func()
}

func (s *fleetStream) Close() error {
	e := s.Conn.Close()
	s.release()
	return e
}

func (s *fleetStream) CloseWrite() error {
	if conn, ok := s.Conn.(interface{ CloseWrite() error }); ok {
		return conn.CloseWrite()
	}
	return errors.New("half-close unsupported")
}

type fleetDatagram struct {
	routing.Datagram
	release func()
}

func (d *fleetDatagram) Close() error {
	e := d.Datagram.Close()
	d.release()
	return e
}

func (f *relayFleet) OpenTCP(ctx context.Context, flow routing.Flow) (net.Conn, string, error) {
	conn, id, release, err := openFleet(f, ctx, flow, fleetPool.OpenFleetTCP)
	if err != nil {
		return nil, "", err
	}
	return &fleetStream{conn, release}, id, nil
}

func (f *relayFleet) OpenDatagram(ctx context.Context, flow routing.Flow) (routing.Datagram, string, error) {
	datagram, id, release, err := openFleet(f, ctx, flow, fleetPool.OpenFleetDatagram)
	if err != nil {
		return nil, "", err
	}
	return &fleetDatagram{datagram, release}, id, nil
}

func (f *relayFleet) snapshot(now time.Time) map[string]any {
	f.mu.Lock()
	defer f.mu.Unlock()
	ids := make([]string, 0, len(f.nodes))
	for _, node := range f.nodes {
		ids = append(ids, node.id)
	}
	reason := f.reason
	if f.budget.Enabled() && !f.expires.After(now) {
		reason = "fleet_policy_unavailable"
	}
	return map[string]any{"budget": f.budget.Snapshot(), "candidates": ids, "version": f.epoch,
		"lease_expires_at": f.expires, "last_authenticated_relay": f.lastNode, "reason": reason}
}
