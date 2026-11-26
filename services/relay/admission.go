package relay

import (
	"crypto/ed25519"
	"errors"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/buzzmean/veliq/core/protocol"
	"github.com/buzzmean/veliq/core/security"
)

var errFleetAdmission = errors.New("new fleet admission unavailable")

type fleetBucket struct {
	at     time.Time
	credit float64
}

func (b *fleetBucket) take(now time.Time, rate, burst uint64) bool {
	if b.at.IsZero() {
		b.credit = float64(burst)
	}
	b.credit = min(float64(burst), b.credit+max(0, now.Sub(b.at).Seconds())*float64(rate))
	b.at = now
	if b.credit < 1 {
		return false
	}
	b.credit--
	return true
}

type fleetDevice struct{ sessions, flows uint64 }

// FleetAdmission is optional. Its lock linearizes admission against a verified
// phase update; existing lease renewals use the ticket verifier independently.
type FleetAdmission struct {
	mu                            sync.Mutex
	node                          string
	keys                          map[string]ed25519.PublicKey
	policy                        security.FleetNodePolicy
	maxSessions, maxFlows         uint64
	devices                       map[string]fleetDevice
	sessions, flows               uint64
	handshakes, newOpens, packets fleetBucket
	used                          security.FleetResources
	earlyRejected                 atomic.Uint64
}

func NewFleetAdmission(node string, keys map[string]ed25519.PublicKey) (*FleetAdmission, error) {
	if !security.FleetNodeID(node) || len(keys) == 0 {
		return nil, errFleetAdmission
	}
	trust := make(map[string]ed25519.PublicKey, len(keys))
	for id, key := range keys {
		trust[id] = append(ed25519.PublicKey(nil), key...)
	}
	return &FleetAdmission{node: node, keys: trust, devices: make(map[string]fleetDevice)}, nil
}

func (g *FleetAdmission) bind(sessions, perSession int) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.maxSessions, g.maxFlows = uint64(sessions), uint64(sessions*perSession)
}

func (g *FleetAdmission) Apply(raw []byte, now time.Time) error {
	p, err := security.VerifyFleetNode(g.keys, raw, g.node, now)
	if err != nil {
		return err
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	old := g.policy
	if p.Limits.Sessions > g.maxSessions || p.Limits.Flows > g.maxFlows ||
		p.Version < old.Version || p.Version == old.Version &&
		(!p.IssuedAt.After(old.IssuedAt) || p.Phase != old.Phase || p.Limits != old.Limits ||
			p.ProbeDevice != old.ProbeDevice || p.ProbeTarget != old.ProbeTarget || p.CanaryDevice != old.CanaryDevice) {
		return errFleetAdmission
	}
	g.policy = p
	return nil
}

func (g *FleetAdmission) Version() uint64 {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.policy.Version
}

func (g *FleetAdmission) admittingLocked(now time.Time) bool {
	return g.policy.AdmitUntil.After(now) && g.policy.Phase != security.FleetDrain
}

func (g *FleetAdmission) admitting(now time.Time) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.admittingLocked(now)
}

func (g *FleetAdmission) belowRateLocked() bool {
	return g.used.Bits < g.policy.Limits.Bits && g.used.Packets < g.policy.Limits.Packets
}

func (g *FleetAdmission) permitHandshake(now time.Time) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	l := g.policy.Limits
	return g.admittingLocked(now) && g.belowRateLocked() && g.sessions < l.Sessions &&
		g.handshakes.take(now, min(l.Opens, 16), min(l.Sessions, 8))
}

func (g *FleetAdmission) deviceAllowedLocked(id string) bool {
	switch g.policy.Phase {
	case security.FleetActive:
		return id != ""
	case security.FleetStaged:
		return id == g.policy.ProbeDevice
	case security.FleetCanary:
		return id == g.policy.CanaryDevice
	}
	return false
}

func (g *FleetAdmission) reserveSession(id string, now time.Time) (func(), error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	current := g.devices[id]
	total, perDevice := g.policy.Limits.Sessions, uint64(2)
	if g.policy.Phase == security.FleetStaged {
		total, perDevice = 1, 1
	}
	if !g.admittingLocked(now) || !g.deviceAllowedLocked(id) || !g.belowRateLocked() ||
		g.sessions >= total || current.sessions >= perDevice {
		return nil, errFleetAdmission
	}
	g.sessions++
	current.sessions++
	g.devices[id] = current
	return func() {
		g.mu.Lock()
		defer g.mu.Unlock()
		current := g.devices[id]
		g.sessions--
		current.sessions--
		g.putDevice(id, current)
	}, nil
}

func (g *FleetAdmission) putDevice(id string, d fleetDevice) {
	if d.sessions == 0 && d.flows == 0 {
		delete(g.devices, id)
	} else {
		g.devices[id] = d
	}
}

func (g *FleetAdmission) flowPermissionLocked(id string, dst netip.AddrPort, kind byte, now time.Time) byte {
	if !g.admittingLocked(now) {
		return 3
	}
	if !g.deviceAllowedLocked(id) {
		return 7
	}
	if g.policy.Phase == security.FleetStaged {
		target, err := netip.ParseAddrPort(g.policy.ProbeTarget)
		if err != nil || kind != protocol.UDP || dst != target {
			return 2
		}
	}
	return 0
}

func (g *FleetAdmission) flowPermission(id string, dst netip.AddrPort, kind byte, now time.Time) byte {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.flowPermissionLocked(id, dst, kind, now)
}

func (g *FleetAdmission) reserveFlow(id string, dst netip.AddrPort, kind byte, now time.Time) (func(), byte) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if code := g.flowPermissionLocked(id, dst, kind, now); code != 0 {
		return nil, code
	}
	current := g.devices[id]
	l := g.policy.Limits
	capacity, perDevice := l.Flows, uint64(48)
	if g.policy.Phase == security.FleetStaged {
		capacity, perDevice = 1, 1
	}
	if !g.belowRateLocked() || g.flows >= capacity || current.flows >= perDevice ||
		!g.newOpens.take(now, l.Opens, min(l.Flows, 32)) {
		return nil, 3
	}
	g.flows++
	current.flows++
	g.devices[id] = current
	return func() {
		g.mu.Lock()
		defer g.mu.Unlock()
		current := g.devices[id]
		g.flows--
		current.flows--
		g.putDevice(id, current)
	}, 0
}

func (g *FleetAdmission) permitPacket(now time.Time) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	pps := g.policy.Limits.Packets
	// Keep the existing packet limit on established flows during drain and
	// through a stale policy. Lease-control frames take a separate path.
	return pps > 0 && g.packets.take(now, pps, max(1, pps/4))
}

type fleetSampler struct {
	mu                      sync.Mutex
	at                      time.Time
	payload, packets, opens uint64
}

func (s *Server) FleetSample(now time.Time) (security.FleetResources, bool) {
	var r security.FleetResources
	if s.config.Fleet == nil && !s.config.FleetObserve {
		return r, false
	}
	f := &s.fleetSample
	f.mu.Lock()
	defer f.mu.Unlock()
	payload := s.Metrics.RXBytes.Load() + s.Metrics.TXBytes.Load()
	packets, opens := s.Metrics.FleetPackets.Load(), s.Metrics.FleetOpenAttempts.Load()
	elapsed := now.Sub(f.at).Seconds()
	haveSample := !f.at.IsZero() && elapsed >= 0.25 && payload >= f.payload && packets >= f.packets && opens >= f.opens
	r.Sessions = uint64(max(0, s.Metrics.Sessions.Load()))
	r.Flows = uint64(max(0, s.Metrics.Flows.Load()))
	if haveSample {
		r.Bits = uint64(float64(payload-f.payload) * 8 / elapsed)
		r.Packets = uint64(float64(packets-f.packets) / elapsed)
		r.Opens = uint64(float64(opens-f.opens) / elapsed)
	}
	f.at, f.payload, f.packets, f.opens = now, payload, packets, opens
	if gate := s.config.Fleet; haveSample && gate != nil {
		gate.mu.Lock()
		gate.used = r
		gate.mu.Unlock()
	}
	return r, haveSample
}
