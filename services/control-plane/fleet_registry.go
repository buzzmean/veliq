package controlplane

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/buzzmean/veliq/core/security"
	"github.com/jackc/pgx/v5"
)

const legacyRelayFilter = "lower(id) <> 'cp-fleet-config' AND COALESCE(metadata #>> '{fleet,managed}','false') <> 'true'"

var ErrFleetRegistryConflict = errors.New("fleet registry conflict")
var ErrFleetUnavailable = errors.New("fleet registry unavailable")

type FleetCohort struct {
	Enabled bool     `json:"enabled"`
	Devices []string `json:"devices"`
}

type FleetRegistryNode struct {
	ID              string                  `json:"relay_id"`
	Address         string                  `json:"address"`
	Legacy          bool                    `json:"legacy,omitempty"`
	Phase           security.FleetPhase     `json:"phase"`
	Limits          security.FleetResources `json:"limits"`
	ProbeDevice     string                  `json:"probe_device_ref,omitempty"`
	ProbeTarget     string                  `json:"probe_target,omitempty"`
	CanaryDevice    string                  `json:"canary_device_ref,omitempty"`
	HeartbeatSHA256 string                  `json:"heartbeat_sha256,omitempty"`
	ProofSHA256     string                  `json:"proof_sha256,omitempty"`
	FleetArtifact
}

// Managed relay identity includes the reviewed artifact in every CAS scope.
type FleetArtifact struct {
	SourceCommit string `json:"source_commit,omitempty"`
	SHA256       string `json:"artifact_sha256,omitempty"`
	Bytes        uint64 `json:"artifact_bytes,omitempty"`
}

type FleetRegistryChange struct {
	Operation       string             `json:"operation_id"`
	ExpectedVersion uint64             `json:"expected_version"`
	Cohort          *FleetCohort       `json:"cohort,omitempty"`
	Node            *FleetRegistryNode `json:"node,omitempty"`
}

type fleetRegistryMeta struct {
	Managed         bool                    `json:"managed"`
	RegistryVersion uint64                  `json:"registry_version,omitempty"`
	Cohort          *FleetCohort            `json:"cohort,omitempty"`
	Phase           security.FleetPhase     `json:"phase,omitempty"`
	Limits          security.FleetResources `json:"limits"`
	Load            security.FleetResources `json:"observed_load"`
	Observed        time.Time               `json:"observed_at"`
	Sampled         bool                    `json:"load_sample_available,omitempty"`
	Sequence        uint64                  `json:"sequence,omitempty"`
	AppliedVersion  uint64                  `json:"applied_version,omitempty"`
	ProbeDevice     string                  `json:"probe_device_ref,omitempty"`
	ProbeTarget     string                  `json:"probe_target,omitempty"`
	CanaryDevice    string                  `json:"canary_device_ref,omitempty"`
	DrainDevices    []string                `json:"drain_devices,omitempty"`
	FleetArtifact
}

// The typed metadata is additive. For legacy rows, mutations preserve all
// unrelated metadata, including the existing relay identity and heartbeat hash.
type fleetRegistryRow struct {
	ID      string             `json:"id"`
	Address string             `json:"address,omitempty"`
	Fleet   *fleetRegistryMeta `json:"fleet,omitempty"`
}

type fleetQuery interface {
	Query(context.Context, string, ...any) (pgx.Rows, error)
	QueryRow(context.Context, string, ...any) pgx.Row
}

func decodeFleetRow(raw []byte) (fleetRegistryRow, error) {
	var row fleetRegistryRow
	err := json.Unmarshal(raw, &row)
	return row, err
}

func readFleetRow(ctx context.Context, q fleetQuery, id string, lock bool) (fleetRegistryRow, error) {
	sql := "SELECT metadata FROM relay_nodes WHERE id=$1"
	if lock {
		sql += " FOR UPDATE"
	}
	var raw []byte
	if err := q.QueryRow(ctx, sql, id).Scan(&raw); err != nil {
		return fleetRegistryRow{}, err
	}
	return decodeFleetRow(raw)
}

func readFleetVersion(ctx context.Context, q fleetQuery) (uint64, error) {
	row, err := readFleetRow(ctx, q, security.FleetProofAudience, false)
	if errors.Is(err, pgx.ErrNoRows) {
		return 1, nil // Unconfigured fleet registry.
	}
	if err != nil {
		return 0, err
	}
	if row.Fleet == nil || row.Fleet.RegistryVersion < 2 {
		return 0, ErrFleetUnavailable
	}
	return row.Fleet.RegistryVersion, nil
}

func writeFleetVersion(ctx context.Context, tx pgx.Tx, version uint64) error {
	seed, err := json.Marshal(fleetRegistryRow{ID: security.FleetProofAudience,
		Fleet: &fleetRegistryMeta{Managed: true, RegistryVersion: version}})
	if err != nil {
		return err
	}
	// Retain the latest fleet epoch in additive metadata. A legacy publish
	// can allocate a sequence number without changing this CAS snapshot.
	_, err = tx.Exec(ctx, `INSERT INTO relay_nodes(id,metadata) VALUES($1,$2)
		ON CONFLICT(id) DO UPDATE SET metadata=jsonb_set(relay_nodes.metadata,
		'{fleet,registry_version}',to_jsonb($3::bigint))`, security.FleetProofAudience, seed, int64(version))
	return err
}

func readFleetCohort(ctx context.Context, q fleetQuery) (FleetCohort, error) {
	row, err := readFleetRow(ctx, q, security.FleetProofAudience, false)
	if errors.Is(err, pgx.ErrNoRows) {
		return FleetCohort{}, ErrFleetUnavailable
	}
	if err != nil {
		return FleetCohort{}, err
	}
	if row.Fleet == nil || row.Fleet.Cohort == nil || !row.Fleet.Cohort.valid() {
		return FleetCohort{}, ErrFleetUnavailable
	}
	return *row.Fleet.Cohort, nil
}

func (c FleetCohort) valid() bool {
	if len(c.Devices) > security.FleetMaxDevices || c.Enabled && len(c.Devices) == 0 {
		return false
	}
	seen := make(map[string]bool, len(c.Devices))
	for _, id := range c.Devices {
		if id == "" || len(id) > 128 || seen[id] {
			return false
		}
		seen[id] = true
	}
	return true
}

func (m fleetRegistryMeta) admitsDevice(device string, cohort FleetCohort) bool {
	switch m.Phase {
	case security.FleetStaged:
		return m.ProbeDevice != "" && device == m.ProbeDevice
	case security.FleetCanary:
		return cohort.Enabled && m.CanaryDevice != "" && device == m.CanaryDevice && slices.Contains(cohort.Devices, device)
	case security.FleetActive:
		return cohort.Enabled && slices.Contains(cohort.Devices, device)
	case security.FleetDrain:
		return slices.Contains(m.DrainDevices, device)
	}
	return false
}

func readFleetNodes(ctx context.Context, q fleetQuery, lock bool) ([]fleetRegistryRow, error) {
	sql := "SELECT metadata FROM relay_nodes WHERE id<>$1 AND metadata ? 'fleet' ORDER BY id LIMIT 5"
	if lock {
		sql += " FOR UPDATE"
	}
	rows, err := q.Query(ctx, sql, security.FleetProofAudience)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var nodes []fleetRegistryRow
	for rows.Next() {
		var raw []byte
		if err := rows.Scan(&raw); err != nil {
			return nil, err
		}
		row, err := decodeFleetRow(raw)
		if err != nil || row.Fleet == nil || !row.Fleet.Phase.Valid() {
			return nil, ErrFleetUnavailable
		}
		nodes = append(nodes, row)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(nodes) > security.FleetMaxCandidates {
		return nil, ErrFleetRegistryConflict
	}
	return nodes, nil
}

func (s *Store) fleetPolicy(ctx context.Context, device string, now time.Time) (security.FleetPolicy, error) {
	tx, err := s.DB.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return security.FleetPolicy{}, err
	}
	defer tx.Rollback(ctx)
	cohort, err := readFleetCohort(ctx, tx)
	if err != nil {
		return security.FleetPolicy{}, err
	}
	if !slices.Contains(cohort.Devices, device) {
		return security.FleetPolicy{}, ErrFleetUnavailable
	}
	nodes, err := readFleetNodes(ctx, tx, false)
	if err != nil {
		return security.FleetPolicy{}, err
	}
	version, err := readFleetVersion(ctx, tx)
	if err != nil || version == 0 {
		return security.FleetPolicy{}, ErrFleetUnavailable
	}
	p := security.FleetPolicy{Schema: security.FleetSchema, Version: version, IssuedAt: now, ExpiresAt: now.Add(security.FleetFreshness), Device: device, Enabled: cohort.Enabled, Candidates: []security.FleetCandidate{}}
	for _, node := range nodes {
		meta := node.Fleet
		if meta.Phase == security.FleetStaged || meta.Phase == security.FleetDrain || !meta.admitsDevice(device, cohort) {
			continue
		}
		p.Candidates = append(p.Candidates, security.FleetCandidate{ID: node.ID, Address: node.Address, Phase: meta.Phase, Limits: meta.Limits, Used: meta.Load, ObservedAt: meta.Observed, LoadAvailable: meta.Sampled})
	}
	return p, tx.Commit(ctx)
}

func (s *Store) fleetTicket(ctx context.Context, relay, device string) (allowed bool, err error) {
	tx, err := s.DB.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return false, err
	}
	defer tx.Rollback(ctx)
	row, err := readFleetRow(ctx, tx, relay, false)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if row.Fleet == nil || !row.Fleet.Managed || !row.Fleet.Phase.Valid() {
		return false, nil
	}
	cohort, err := readFleetCohort(ctx, tx)
	if err != nil && !errors.Is(err, ErrFleetUnavailable) {
		return false, err
	}
	if !row.Fleet.admitsDevice(device, cohort) {
		return false, nil
	}
	return true, tx.Commit(ctx)
}

func (s *Store) changeFleetRegistry(ctx context.Context, req FleetRegistryChange) (uint64, error) {
	if !security.FleetNodeID(req.Operation) || req.ExpectedVersion == 0 || (req.Cohort == nil) == (req.Node == nil) {
		return 0, ErrFleetRegistryConflict
	}
	encoded, err := json.Marshal(req)
	if err != nil {
		return 0, err
	}
	digest := sha256.Sum256(encoded)
	fingerprint := hex.EncodeToString(digest[:])
	tx, err := s.DB.Begin(ctx)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback(ctx)
	if _, err = tx.Exec(ctx, "SELECT pg_advisory_xact_lock(724220)"); err != nil {
		return 0, err
	}
	var receipt string
	err = tx.QueryRow(ctx, `SELECT entity_id FROM audit_log WHERE action='fleet.change'
		AND split_part(entity_id,':',1)=$1 ORDER BY id DESC LIMIT 1`, req.Operation).Scan(&receipt)
	if err == nil {
		parts := strings.Split(receipt, ":")
		if len(parts) != 3 || parts[1] != fingerprint {
			return 0, ErrFleetRegistryConflict
		}
		return strconv.ParseUint(parts[2], 10, 64)
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return 0, err
	}
	version, err := readFleetVersion(ctx, tx)
	if err != nil {
		return 0, err
	}
	if version != req.ExpectedVersion || version >= 1<<63-1 {
		return 0, ErrFleetRegistryConflict
	}
	cohort, err := readFleetCohort(ctx, tx)
	if err != nil && !errors.Is(err, ErrFleetUnavailable) {
		return 0, err
	}
	nodes, err := readFleetNodes(ctx, tx, true)
	if err != nil {
		return 0, err
	}
	if req.Cohort != nil {
		if err = changeFleetCohort(ctx, tx, *req.Cohort, cohort, nodes); err != nil {
			return 0, err
		}
	} else if err = changeFleetNode(ctx, tx, *req.Node, cohort, nodes); err != nil {
		return 0, err
	}
	var nextVersion uint64
	if err = tx.QueryRow(ctx, "SELECT nextval(pg_get_serial_sequence('config_versions','version'))").Scan(&nextVersion); err != nil {
		return 0, err
	}
	if nextVersion <= version {
		return 0, ErrFleetRegistryConflict
	}
	version = nextVersion
	if err = writeFleetVersion(ctx, tx, version); err != nil {
		return 0, err
	}
	entity := req.Operation + ":" + fingerprint + ":" + strconv.FormatUint(version, 10)
	if _, err = tx.Exec(ctx, "INSERT INTO audit_log(actor,action,entity_id) VALUES('owner','fleet.change',$1)", entity); err != nil {
		return 0, err
	}
	return version, tx.Commit(ctx)
}

func changeFleetCohort(ctx context.Context, tx pgx.Tx, next, old FleetCohort, nodes []fleetRegistryRow) error {
	if !next.valid() {
		return ErrFleetRegistryConflict
	}
	if next.Enabled {
		for _, node := range nodes {
			if node.Fleet.Phase == security.FleetStaged && slices.Contains(next.Devices, node.Fleet.ProbeDevice) {
				return ErrFleetRegistryConflict
			}
		}
		for _, device := range old.Devices {
			if !slices.Contains(next.Devices, device) {
				return ErrFleetRegistryConflict
			}
		}
	} else {
		// A disabled policy must be deliverable to every previously enabled
		// device. Keep the audience and admission for draining leases.
		next.Devices = append([]string(nil), old.Devices...)
		for _, node := range nodes {
			m := node.Fleet
			if !m.Managed || m.Phase == security.FleetDrain {
				continue
			}
			moveFleetToDrain(m, old)
			if err := writeFleetMeta(ctx, tx, node.ID, m); err != nil {
				return err
			}
		}
	}
	raw, err := json.Marshal(fleetRegistryRow{ID: security.FleetProofAudience, Fleet: &fleetRegistryMeta{Managed: true, Cohort: &next}})
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, "INSERT INTO relay_nodes(id,metadata) VALUES($1,$2) ON CONFLICT(id) DO UPDATE SET metadata=excluded.metadata", security.FleetProofAudience, raw)
	return err
}

func moveFleetToDrain(m *fleetRegistryMeta, cohort FleetCohort) {
	switch m.Phase {
	case security.FleetCanary:
		m.DrainDevices = []string{m.CanaryDevice}
	case security.FleetStaged:
		m.DrainDevices = []string{m.ProbeDevice}
	default:
		m.DrainDevices = append([]string(nil), cohort.Devices...)
	}
	m.Phase = security.FleetDrain
	m.CanaryDevice, m.ProbeDevice, m.ProbeTarget = "", "", ""
}

func writeFleetMeta(ctx context.Context, tx pgx.Tx, id string, m *fleetRegistryMeta) error {
	raw, err := json.Marshal(m)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, "UPDATE relay_nodes SET metadata=jsonb_set(metadata,'{fleet}',$2::jsonb) WHERE id=$1", id, raw)
	return err
}

func (artifact FleetArtifact) valid() bool {
	commit, err := hex.DecodeString(artifact.SourceCommit)
	if err != nil || len(commit) != 20 || strings.ToLower(artifact.SourceCommit) != artifact.SourceCommit {
		return false
	}
	hash, err := hex.DecodeString(artifact.SHA256)
	return err == nil && len(hash) == sha256.Size && strings.ToLower(artifact.SHA256) == artifact.SHA256 &&
		artifact.Bytes > 0 && artifact.Bytes <= 32*1024*1024
}

func changeFleetNode(ctx context.Context, tx pgx.Tx, n FleetRegistryNode, cohort FleetCohort, nodes []fleetRegistryRow) error {
	if !security.FleetNodeID(n.ID) || !security.FleetAddress(n.Address) || !n.Phase.Valid() || !n.Limits.ValidLimit() ||
		n.Limits.Sessions > 128 || n.Limits.Flows > 8192 {
		return ErrFleetRegistryConflict
	}
	if n.Legacy && n.FleetArtifact != (FleetArtifact{}) || !n.Legacy && !n.FleetArtifact.valid() {
		return ErrFleetRegistryConflict
	}
	if n.Phase == security.FleetStaged {
		target, err := netip.ParseAddrPort(n.ProbeTarget)
		if err != nil || target.Port() == 0 || target.Port() == 53 || target.Addr().IsUnspecified() ||
			target.Addr().IsMulticast() || target.Addr().Zone() != "" || n.ProbeDevice == "" ||
			slices.Contains(cohort.Devices, n.ProbeDevice) || len(n.ProbeDevice) > 128 || n.Legacy || n.CanaryDevice != "" {
			return ErrFleetRegistryConflict
		}
	} else if n.ProbeDevice != "" || n.ProbeTarget != "" {
		return ErrFleetRegistryConflict
	}
	if n.Phase == security.FleetCanary {
		proof, err := hex.DecodeString(n.ProofSHA256)
		if err != nil || len(proof) != sha256.Size || !cohort.Enabled || !slices.Contains(cohort.Devices, n.CanaryDevice) {
			return ErrFleetRegistryConflict
		}
		for _, other := range nodes {
			if other.ID != n.ID && other.Fleet.Phase == security.FleetCanary {
				return ErrFleetRegistryConflict
			}
		}
	} else if n.CanaryDevice != "" || n.ProofSHA256 != "" {
		return ErrFleetRegistryConflict
	}
	current, err := readFleetRow(ctx, tx, n.ID, true)
	missing := errors.Is(err, pgx.ErrNoRows)
	if err != nil && !missing {
		return err
	}
	if missing || current.Fleet == nil {
		if len(nodes) >= security.FleetMaxCandidates {
			return ErrFleetRegistryConflict
		}
		meta := &fleetRegistryMeta{Managed: !n.Legacy, Phase: n.Phase, Limits: n.Limits, ProbeDevice: n.ProbeDevice, ProbeTarget: n.ProbeTarget, CanaryDevice: n.CanaryDevice, FleetArtifact: n.FleetArtifact}
		if n.Legacy {
			if missing || n.Address != current.Address || n.HeartbeatSHA256 != "" || n.Phase != security.FleetActive {
				return ErrFleetRegistryConflict
			}
			return writeFleetMeta(ctx, tx, n.ID, meta)
		}
		hash, e := hex.DecodeString(n.HeartbeatSHA256)
		if !missing || n.Phase != security.FleetStaged || e != nil || len(hash) != sha256.Size {
			return ErrFleetRegistryConflict
		}
		raw, e := json.Marshal(fleetRegistryRow{ID: n.ID, Address: n.Address, Fleet: meta})
		if e != nil {
			return e
		}
		_, e = tx.Exec(ctx, "INSERT INTO relay_nodes(id,metadata,heartbeat_token_hash) VALUES($1,$2,$3)", n.ID, raw, hash)
		return e
	}
	meta := current.Fleet
	if current.Address != n.Address || meta.Managed == n.Legacy || n.HeartbeatSHA256 != "" || meta.Limits != n.Limits || meta.FleetArtifact != n.FleetArtifact {
		return ErrFleetRegistryConflict
	}
	switch {
	case meta.Managed && meta.Phase == security.FleetStaged && n.Phase == security.FleetCanary && meta.Sampled && meta.Observed.Add(security.FleetFreshness).After(time.Now()):
		meta.Phase, meta.ProbeDevice, meta.ProbeTarget, meta.CanaryDevice = n.Phase, "", "", n.CanaryDevice
	case meta.Managed && meta.Phase == security.FleetCanary && n.Phase == security.FleetActive && cohort.Enabled:
		meta.Phase, meta.CanaryDevice = n.Phase, ""
	case meta.Managed && n.Phase == security.FleetDrain:
		if meta.Phase != security.FleetDrain {
			moveFleetToDrain(meta, cohort)
		}
	default:
		return ErrFleetRegistryConflict
	}
	return writeFleetMeta(ctx, tx, n.ID, meta)
}
