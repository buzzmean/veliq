package security

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const (
	FleetProofAudience = "cp-fleet-config"
	FleetConfigDomain  = "fleet-config"
	FleetNodeDomain    = "fleet-node"
	FleetSchema        = 1
	FleetMaxCandidates = 4
	FleetMaxDevices    = 10
	FleetFreshness     = 45 * time.Second
)

var ErrFleetPolicy = errors.New("invalid or stale fleet policy")

type FleetPhase string

const (
	FleetStaged FleetPhase = "staged"
	FleetCanary FleetPhase = "canary"
	FleetActive FleetPhase = "active"
	FleetDrain  FleetPhase = "drain"
)

func (p FleetPhase) Valid() bool {
	switch p {
	case FleetStaged, FleetCanary, FleetActive, FleetDrain:
		return true
	}
	return false
}

func FleetNodeID(id string) bool {
	if len(id) == 0 || len(id) > 64 || strings.EqualFold(id, FleetProofAudience) || strings.EqualFold(id, "DIRECT") {
		return false
	}
	for _, r := range id {
		if (r < 'A' || r > 'Z') && (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '_' && r != '-' {
			return false
		}
	}
	return true
}

func FleetAddress(address string) bool {
	if len(address) > 255 {
		return false
	}
	host, port, err := net.SplitHostPort(address)
	if err != nil || host == "" || strings.ContainsAny(host, " /\\%@#?\t\r\n") {
		return false
	}
	n, err := strconv.ParseUint(port, 10, 16)
	return err == nil && n != 0
}

type FleetResources struct {
	Sessions uint64 `json:"sessions"`
	Flows    uint64 `json:"flows"`
	Packets  uint64 `json:"packets_per_second"`
	Bits     uint64 `json:"bits_per_second"`
	Opens    uint64 `json:"opens_per_second"`
}

func (r FleetResources) Valid() bool {
	return r.Sessions <= 65536 && r.Flows <= 1048576 && r.Packets <= 1000000000 && r.Bits <= 1000000000000 && r.Opens <= 1048576
}

func (r FleetResources) ValidLimit() bool {
	return r.Valid() && r.Sessions > 0 && r.Flows > 0 && r.Packets > 0 && r.Bits > 0 && r.Opens > 0
}

// SpareWeight is based on the scarcest measured resource. The relay remains
// authoritative when a previously fresh snapshot changes before an OPEN.
func (r FleetResources) SpareWeight(used FleetResources) float64 {
	if !r.ValidLimit() || !used.Valid() {
		return 0
	}
	spare := func(capacity, occupied uint64) float64 {
		if occupied >= capacity {
			return 0
		}
		return float64(capacity-occupied) / float64(capacity)
	}
	return min(spare(r.Sessions, used.Sessions), spare(r.Flows, used.Flows), spare(r.Packets, used.Packets), spare(r.Bits, used.Bits), spare(r.Opens, used.Opens))
}

type FleetCandidate struct {
	ID            string         `json:"relay_id"`
	Address       string         `json:"address"`
	Phase         FleetPhase     `json:"phase"`
	Limits        FleetResources `json:"measured_safe_limits"`
	Used          FleetResources `json:"load"`
	ObservedAt    time.Time      `json:"observed_at"`
	LoadAvailable bool           `json:"load_sample_available"`
}

type FleetPolicy struct {
	Schema     int              `json:"schema_version"`
	Version    uint64           `json:"registry_version"`
	IssuedAt   time.Time        `json:"issued_at"`
	ExpiresAt  time.Time        `json:"expires_at"`
	Device     string           `json:"device_scope"`
	Enabled    bool             `json:"enabled"`
	Candidates []FleetCandidate `json:"candidates"`
}

func fleetWindow(issued, expires time.Time) bool {
	return !issued.IsZero() && expires.After(issued) && expires.Sub(issued) <= FleetFreshness
}

func (p FleetPolicy) ValidAt(now time.Time) bool {
	return !p.IssuedAt.After(now.Add(3*time.Second)) && p.ExpiresAt.After(now)
}

func (p FleetPolicy) validShape(device string) bool {
	if p.Schema != FleetSchema || p.Version == 0 || p.Device != device || device == "" || len(device) > 128 ||
		!fleetWindow(p.IssuedAt, p.ExpiresAt) || len(p.Candidates) > FleetMaxCandidates || !p.Enabled && len(p.Candidates) > 0 {
		return false
	}
	ids := make(map[string]bool, len(p.Candidates))
	for _, c := range p.Candidates {
		if !FleetNodeID(c.ID) || ids[c.ID] || !FleetAddress(c.Address) || !c.Phase.Valid() ||
			!c.Limits.ValidLimit() || !c.Used.Valid() || c.LoadAvailable && c.ObservedAt.IsZero() ||
			c.ObservedAt.After(p.IssuedAt.Add(3*time.Second)) {
			return false
		}
		ids[c.ID] = true
	}
	return true
}

type FleetNodePolicy struct {
	Schema       int            `json:"schema_version"`
	Version      uint64         `json:"registry_version"`
	NodeID       string         `json:"node_scope"`
	Phase        FleetPhase     `json:"phase"`
	IssuedAt     time.Time      `json:"issued_at"`
	AdmitUntil   time.Time      `json:"admit_new_until"`
	Limits       FleetResources `json:"limits"`
	ProbeDevice  string         `json:"probe_device_ref,omitempty"`
	ProbeTarget  string         `json:"probe_target,omitempty"`
	CanaryDevice string         `json:"canary_device_ref,omitempty"`
}

func (p FleetNodePolicy) Validate(node string, now time.Time) error {
	if p.Schema != FleetSchema || p.Version == 0 || p.NodeID != node || !FleetNodeID(node) || !p.Phase.Valid() ||
		!p.Limits.ValidLimit() || !fleetWindow(p.IssuedAt, p.AdmitUntil) || !p.AdmitUntil.After(now) || p.IssuedAt.After(now.Add(3*time.Second)) {
		return ErrFleetPolicy
	}
	switch p.Phase {
	case FleetStaged:
		if target, err := netip.ParseAddrPort(p.ProbeTarget); err != nil || target.Port() == 0 || p.ProbeDevice == "" || len(p.ProbeDevice) > 128 || p.CanaryDevice != "" {
			return ErrFleetPolicy
		}
	case FleetCanary:
		if p.CanaryDevice == "" || len(p.CanaryDevice) > 128 || p.ProbeDevice != "" || p.ProbeTarget != "" {
			return ErrFleetPolicy
		}
	default:
		if p.ProbeDevice != "" || p.ProbeTarget != "" || p.CanaryDevice != "" {
			return ErrFleetPolicy
		}
	}
	return nil
}

func VerifyFleetNode(keys map[string]ed25519.PublicKey, raw []byte, node string, now time.Time) (FleetNodePolicy, error) {
	var p FleetNodePolicy
	if err := Verify(FleetNodeDomain, keys, raw, &p); err != nil {
		return FleetNodePolicy{}, err
	}
	return p, p.Validate(node, now)
}

type FleetHeartbeat struct {
	ID             string         `json:"relay_id"`
	Sequence       uint64         `json:"sequence"`
	AppliedVersion uint64         `json:"applied_version"`
	ObserveOnly    bool           `json:"observe_only,omitempty"`
	Sampled        bool           `json:"sampled"`
	Used           FleetResources `json:"load"`
}

// FleetCache owns the per-device anti-rollback floor. Load remembers an expired
// signed document as a floor, without authorizing new opens from that document.
type FleetCache struct {
	keys         map[string]ed25519.PublicKey
	device, path string
	last         FleetPolicy
	raw          []byte
}

func NewFleetCache(keys map[string]ed25519.PublicKey, device, path string) *FleetCache {
	return &FleetCache{keys: copyKeys(keys), device: device, path: path}
}

func (c *FleetCache) Load(now time.Time) (FleetPolicy, error) {
	f, err := os.Open(c.path)
	if err != nil {
		return FleetPolicy{}, err
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, MaxDocument+1))
	if err != nil {
		return FleetPolicy{}, err
	}
	p, err := c.decode(raw)
	if err != nil {
		return FleetPolicy{}, err
	}
	if !p.validShape(c.device) || p.IssuedAt.After(now.Add(3*time.Second)) {
		return FleetPolicy{}, ErrFleetPolicy
	}
	c.last, c.raw = p, raw
	return p, nil
}

func (c *FleetCache) decode(raw []byte) (FleetPolicy, error) {
	var policy FleetPolicy
	if err := Verify(FleetConfigDomain, c.keys, raw, &policy); err != nil {
		return FleetPolicy{}, err
	}
	var env Envelope
	if err := Parse(raw, &env); err != nil {
		return FleetPolicy{}, err
	}
	// An omitted enabled field must not decode to an authorized rollback.
	var mode struct {
		Enabled *bool `json:"enabled"`
	}
	if err := json.Unmarshal(env.Payload, &mode); err != nil || mode.Enabled == nil {
		return FleetPolicy{}, ErrFleetPolicy
	}
	return policy, nil
}

func (c *FleetCache) Apply(raw []byte, now time.Time) (FleetPolicy, error) {
	p, err := c.decode(raw)
	if err != nil {
		return FleetPolicy{}, err
	}
	if !p.validShape(c.device) || !p.ValidAt(now) || p.Version < c.last.Version {
		return FleetPolicy{}, ErrFleetPolicy
	}
	if p.Version == c.last.Version {
		if bytes.Equal(c.raw, raw) {
			return p, nil
		}
		if !p.IssuedAt.After(c.last.IssuedAt) || !sameFleetPolicy(c.last, p) {
			return FleetPolicy{}, ErrFleetPolicy
		}
	}
	if c.path != "" {
		if err := persistFleet(c.path, raw); err != nil {
			return FleetPolicy{}, err
		}
	}
	c.last, c.raw = p, append([]byte(nil), raw...)
	return p, nil
}

func sameFleetPolicy(old, next FleetPolicy) bool {
	if old.Enabled != next.Enabled || len(old.Candidates) != len(next.Candidates) {
		return false
	}
	for _, l := range old.Candidates {
		ok := false
		for _, r := range next.Candidates {
			if l.ID != r.ID || l.Address != r.Address || l.Phase != r.Phase || l.Limits != r.Limits || r.ObservedAt.Before(l.ObservedAt) {
				continue
			}
			if r.ObservedAt.Equal(l.ObservedAt) && (r.Used != l.Used || r.LoadAvailable && !l.LoadAvailable) {
				return false
			}
			ok = true
			break
		}
		if !ok {
			return false
		}
	}
	return true
}

func persistFleet(path string, raw []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".fleet-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name)
	if _, err = tmp.Write(raw); err == nil {
		err = tmp.Sync()
	}
	closeErr := tmp.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	return os.Rename(name, path)
}
