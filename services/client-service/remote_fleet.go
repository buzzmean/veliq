package clientservice

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/buzzmean/veliq/core/controlclient"
	"github.com/buzzmean/veliq/core/measurement"
	"github.com/buzzmean/veliq/core/optimizer"
	"github.com/buzzmean/veliq/core/security"
	"github.com/buzzmean/veliq/core/transport"
	"github.com/buzzmean/veliq/internal/e2eprobe"
)

const fleetOptInFile = "fleet-opt-in.json"
const fleetCacheFile = "fleet-policy.json"

// Empty and malformed markers cannot opt an entire machine into fleet.
// The all-app scope is explicit for a later, separately approved rollout.
func parseFleetOptIn(raw []byte) (string, error) {
	var marker struct {
		Scope         string `json:"scope"`
		ApplicationID string `json:"application_id,omitempty"`
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&marker); err != nil {
		return "", err
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return "", errors.New("fleet opt-in has trailing data")
	}
	switch marker.Scope {
	case "all":
		if marker.ApplicationID == "" {
			return "", nil
		}
	case "application":
		id := marker.ApplicationID
		if len(id) > 0 && len(id) <= 128 && strings.TrimSpace(id) == id && !strings.ContainsAny(id, " \t\r\n") {
			return id, nil
		}
	}
	return "", errors.New("invalid fleet opt-in scope")
}

type remoteFleetPool struct {
	address string
	pool    *transport.Pool
	owned   bool
}

type remoteFleet struct {
	cache        *security.FleetCache
	floorUnknown bool
	device       string
	failures     uint
	pools        map[string]remoteFleetPool
	retired      []*transport.Pool
	probes       []measurement.Candidate
}

// Use separate state files so a 715 binary still parses the installed service
// manifest. A previous enrollment or unreadable opt-in state arms fail-closed.
func (s *remoteState) initFleet(keys map[string]ed25519.PublicKey, device, stateDir string) {
	if stateDir == "" {
		return
	}
	marker, markerErr := os.ReadFile(filepath.Join(stateDir, fleetOptInFile))
	cache := security.NewFleetCache(keys, device, filepath.Join(stateDir, fleetCacheFile))
	_, cacheErr := cache.Load(time.Now())
	if errors.Is(markerErr, os.ErrNotExist) && errors.Is(cacheErr, os.ErrNotExist) && !s.controller.fleet.Enabled() {
		return
	}
	application := ""
	invalidMarker := markerErr != nil
	if !invalidMarker {
		var err error
		application, err = parseFleetOptIn(marker)
		invalidMarker = err != nil
	}
	s.fleet = &remoteFleet{cache: cache, floorUnknown: invalidMarker || cacheErr != nil && !errors.Is(cacheErr, os.ErrNotExist),
		device: device, pools: make(map[string]remoteFleetPool)}
	s.controller.fleet.setScope(application)
	s.controller.fleet.arm(device)
	s.controller.fleet.suspend()
}

func (s *remoteState) fleetDelay(bound time.Duration) time.Duration {
	sum := sha256.Sum256([]byte(s.fleet.device + time.Now().UTC().Truncate(time.Second).String()))
	return time.Duration(binary.BigEndian.Uint64(sum[:8]) % uint64(bound))
}

func (s *remoteState) refreshFleet(ctx context.Context) time.Duration {
	if s.fleet.floorUnknown {
		// A corrupted persisted floor cannot be treated as a first enrollment.
		s.controller.fleet.suspend()
		return 30 * time.Second
	}
	now := time.Now()
	raw, err := s.cp.FleetConfig(ctx)
	if err == nil {
		var policy security.FleetPolicy
		policy, err = s.fleet.cache.Apply(raw, time.Now())
		if err == nil {
			err = s.applyFleetPolicy(policy, time.Now())
		}
	}
	s.sweepFleetPools()
	if err != nil {
		s.controller.fleet.suspend()
		s.fleet.failures++
		delay := time.Second << min(s.fleet.failures-1, 5)
		delay = min(30*time.Second, delay+s.fleetDelay(delay/2))
		var throttle *controlclient.FleetRateLimit
		if errors.As(err, &throttle) {
			delay = max(delay, throttle.RetryAfter)
		}
		return delay
	}
	s.fleet.failures = 0
	// Leave margin for CP request latency and the 45-second authorization TTL.
	return max(time.Second, 25*time.Second+s.fleetDelay(5*time.Second)-time.Since(now))
}

func (s *remoteState) applyFleetPolicy(policy security.FleetPolicy, now time.Time) error {
	ctx := s.controller.ctx
	f := s.controller.fleet
	chosen := make(map[string]remoteFleetPool)
	var candidates []fleetNode
	emptyReason := "fleet_registry_empty"
	if len(policy.Candidates) > 0 {
		emptyReason = "fleet_load_stale"
	}
	network := s.controller.gameMeasurementNetwork()
	fresh := make(map[string]security.FleetCandidate)
	for _, node := range policy.Candidates {
		if !policy.Enabled || node.Phase != security.FleetCanary && node.Phase != security.FleetActive || !node.LoadAvailable || node.ObservedAt.IsZero() ||
			!node.ObservedAt.Add(security.FleetFreshness).After(now) {
			continue
		}
		fresh[node.ID] = node
		emptyReason = "fleet_capacity_exhausted"
		entry := s.knownFleetPool(node.ID, node.Address)
		weight := node.Limits.SpareWeight(node.Used)
		if entry.pool != nil {
			// Capacity affects new admission, not the lifetime of authenticated
			// leases. Keep the exact pool even if another resource is full.
			chosen[node.ID] = entry
			if entry.pool.HasAdmittingSession() {
				weight = fleetReusableWeight(node.Limits, node.Used)
			}
		}
		if weight > 0 {
			candidates = append(candidates, fleetNode{id: node.ID, address: node.Address, weight: weight,
				canary: node.Phase == security.FleetCanary, observed: node.ObservedAt, pool: entry.pool})
		}
	}
	candidates = f.shortlist(candidates, network)
	probes := make([]measurement.Candidate, 0, len(candidates))
	var created []*transport.Pool
	for i := range candidates {
		node := &candidates[i]
		entry := chosen[node.id]
		if entry.pool == nil {
			cfg := transport.DefaultPoolConfig()
			cfg.FleetBudget = &f.budget
			pool, err := transport.NewPool(ctx, cfg, s.relayFactory(node.id, node.address))
			if err != nil {
				for _, p := range created {
					_ = p.Close()
				}
				return err
			}
			created = append(created, pool)
			entry = remoteFleetPool{address: node.address, pool: pool, owned: true}
		}
		node.pool = entry.pool
		chosen[node.id] = entry
		id, address := node.id, node.address
		if len(s.echoKey) > 0 {
			probes = append(probes, measurement.Candidate{
				Metadata: optimizer.RelayCandidate{ID: id, Address: address}, Target: s.target,
				Open:          e2eprobe.ProbeOpener(entry.pool.OpenFleetProbeDatagram, s.echoKey),
				Authenticated: true, SerialRelay: true,
				Eligible: func() bool { return f.probeAllowed(id, address, time.Now()) },
			})
		}
	}
	bindings := make([]fleetSessionCreation, 0, len(chosen))
	for id, entry := range chosen {
		node := fresh[id]
		bindings = append(bindings, fleetSessionCreation{id: id, pool: entry.pool, owned: entry.owned, network: network,
			reuse: network != "" && fleetReusableWeight(node.Limits, node.Used) > 0,
			allow: network != "" && node.Limits.SpareWeight(node.Used) > 0,
			until: minFleetTime(policy.ExpiresAt, node.ObservedAt.Add(security.FleetFreshness))})
	}
	f.setSessionCreations(bindings)
	for id, old := range s.fleet.pools {
		if old.owned && chosen[id].pool != old.pool {
			s.retireFleetPool(old.pool)
		}
	}
	s.fleet.pools, s.fleet.probes = chosen, probes
	s.updateFleetAdmissionSources()
	f.configure(policy.Version, policy.ExpiresAt, policy.Enabled, candidates, emptyReason)
	s.syncFleetMeasurements()
	return nil
}

// Only this remote generation's owned pool, or an exact known legacy alias,
// proves that a reusable session belongs to this relay identity and address.
func (s *remoteState) knownFleetPool(id, address string) remoteFleetPool {
	if legacy := s.clients[id]; legacy != nil && s.addresses[id] == address {
		return remoteFleetPool{address: address, pool: legacy}
	}
	entry := s.fleet.pools[id]
	if entry.owned && entry.pool != nil && entry.address == address {
		return entry
	}
	return remoteFleetPool{}
}

// An authenticated session is already charged to the relay's session count.
// Reusing it still requires spare flow, packet, bit and OPEN budgets. No local
// count is subtracted from the signed aggregate load.
func fleetReusableWeight(limits, used security.FleetResources) float64 {
	if !limits.ValidLimit() || !used.Valid() {
		return 0
	}
	spare := func(capacity, occupied uint64) float64 {
		if occupied >= capacity {
			return 0
		}
		return float64(capacity-occupied) / float64(capacity)
	}
	return min(spare(limits.Flows, used.Flows), spare(limits.Packets, used.Packets), spare(limits.Bits, used.Bits), spare(limits.Opens, used.Opens))
}

func (s *remoteState) updateFleetAdmissionSources() {
	ids := make([]string, 0, len(s.clients))
	for id := range s.clients {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	donors := make([]*transport.Pool, 0, len(ids))
	for _, id := range ids {
		donors = append(donors, s.clients[id])
	}
	s.controller.fleet.setAdmissionSources(donors)
}

func (s *remoteState) syncFleetMeasurements() {
	if !s.controller.fleet.Enabled() {
		s.controller.Measurements.SetCandidates(s.legacyCandidates)
		return
	}
	var candidates []measurement.Candidate
	if len(s.legacyCandidates) > 0 && s.legacyCandidates[0].Metadata.ID == optimizer.Direct {
		candidates = append(candidates, s.legacyCandidates[0])
	}
	if s.fleet != nil {
		candidates = append(candidates, s.fleet.probes...)
	}
	s.controller.Measurements.SetCandidates(candidates)
}

func (s *remoteState) retireFleetPool(pool *transport.Pool) {
	pool.SetDraining(true)
	s.fleet.retired = append(s.fleet.retired, pool)
}

func (s *remoteState) sweepFleetPools() {
	retired := s.fleet.retired[:0]
	for _, pool := range s.fleet.retired {
		state := pool.Snapshot()
		if state.ActiveSessions == 0 && state.CreatingSessions == 0 {
			_ = pool.Close()
		} else {
			retired = append(retired, pool)
		}
	}
	s.fleet.retired = retired
}

func (s *remoteState) closeFleetPools() {
	if s.fleet == nil {
		return
	}
	s.controller.fleet.suspend()
	for _, entry := range s.fleet.pools {
		if entry.owned {
			_ = entry.pool.Close()
		}
	}
	for _, pool := range s.fleet.retired {
		_ = pool.Close()
	}
}
