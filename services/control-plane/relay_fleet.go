package controlplane

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/buzzmean/veliq/core/security"
	"github.com/jackc/pgx/v5"
)

func (a *API) fleetConfig(w http.ResponseWriter, r *http.Request) {
	var proof security.Proof
	if body(r, &proof) != nil || proof.RelayID != security.FleetProofAudience {
		a.fail(w, 400, "invalid fleet device proof")
		return
	}
	ctx := r.Context()
	device, err := a.Store.Device(ctx, proof.DeviceID)
	if err != nil || device.Revoked {
		a.fail(w, 401, "fleet device unavailable")
		return
	}
	pub, err := security.DecodePublicKey(device.PublicKey)
	now := time.Now().UTC()
	if err != nil || proof.Verify(pub, now) != nil {
		a.fail(w, 401, "invalid fleet device proof")
		return
	}
	ent, err := a.Store.DeviceEntitlement(ctx, device.ID)
	if err != nil {
		a.fail(w, 503, "fleet entitlement unavailable")
		return
	}
	if !ent.Active(now) {
		a.fail(w, 402, "SUBSCRIPTION_EXPIRED")
		return
	}
	policy, err := a.Store.fleetPolicy(ctx, device.ID, now)
	if errors.Is(err, ErrFleetUnavailable) {
		a.fail(w, 404, "fleet cohort unavailable")
		return
	}
	if err != nil {
		a.fail(w, 503, "fleet policy unavailable")
		return
	}
	if err = a.Store.ConsumeProof(ctx, proof); err != nil {
		a.fail(w, 401, "invalid, replayed or revoked fleet proof")
		return
	}
	a.sendFleetSigned(w, security.FleetConfigDomain, policy)
}

func (a *API) sendFleetSigned(w http.ResponseWriter, domain string, value any) {
	raw, err := security.Sign(domain, a.Settings.KeyID, a.Settings.SigningKey, value)
	if err != nil {
		a.fail(w, 503, "fleet signing unavailable")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(raw)
}

func (a *API) fleetRegistry(w http.ResponseWriter, r *http.Request) {
	token, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if want := a.Settings.FleetRegistryToken; !ok || len(want) < 24 ||
		subtle.ConstantTimeCompare([]byte(token), []byte(want)) != 1 {
		a.fail(w, 401, "fleet registry authorization required")
		return
	}
	if r.Method == http.MethodGet {
		ctx := r.Context()
		tx, err := a.Store.DB.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
		if err != nil {
			a.fail(w, 503, "fleet registry unavailable")
			return
		}
		defer tx.Rollback(ctx)
		version, err := readFleetVersion(ctx, tx)
		if err != nil {
			a.fail(w, 503, "fleet registry unavailable")
			return
		}
		id := r.URL.Query().Get("node")
		if id == "" {
			cohort, err := readFleetCohort(ctx, tx)
			if err != nil && !errors.Is(err, ErrFleetUnavailable) {
				a.fail(w, 503, "fleet cohort unavailable")
				return
			}
			respond(w, 200, map[string]any{"registry_version": version, "cohort_enabled": cohort.Enabled})
			return
		}
		if !security.FleetNodeID(id) {
			a.fail(w, 400, "invalid fleet relay id")
			return
		}
		row, err := readFleetRow(ctx, tx, id, false)
		if err != nil || row.Fleet == nil {
			a.fail(w, 404, "fleet node unavailable")
			return
		}
		meta := row.Fleet
		respond(w, 200, map[string]any{"registry_version": version, "relay_id": row.ID, "address": row.Address,
			"phase": meta.Phase, "applied_version": meta.AppliedVersion, "observed_at": meta.Observed, "load": meta.Load,
			"source_commit": meta.SourceCommit, "artifact_sha256": meta.SHA256, "artifact_bytes": meta.Bytes})
		return
	}
	var req FleetRegistryChange
	if body(r, &req) != nil {
		a.fail(w, 400, "invalid fleet operation")
		return
	}
	version, err := a.Store.changeFleetRegistry(r.Context(), req)
	if errors.Is(err, ErrFleetRegistryConflict) {
		a.fail(w, 409, "fleet registry compare and publish rejected")
		return
	}
	if err != nil {
		a.fail(w, 503, "fleet registry unavailable")
		return
	}
	respond(w, 200, map[string]uint64{"registry_version": version})
}

func (a *API) fleetHeartbeat(w http.ResponseWriter, r *http.Request) {
	var hb security.FleetHeartbeat
	now := time.Now().UTC()
	if body(r, &hb) != nil || !security.FleetNodeID(hb.ID) || !hb.Used.Valid() ||
		hb.Sequence < uint64(now.Add(-security.FleetFreshness).UnixNano()) || hb.Sequence > uint64(now.Add(3*time.Second).UnixNano()) {
		a.fail(w, 400, "invalid fleet heartbeat")
		return
	}
	token, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok || len(token) != 32 {
		a.fail(w, 401, "fleet node authorization required")
		return
	}
	hash := sha256.Sum256([]byte(token))
	policy, err := a.Store.recordFleetHeartbeat(r.Context(), hb, hash[:], now)
	if errors.Is(err, ErrFleetUnavailable) || errors.Is(err, pgx.ErrNoRows) {
		a.fail(w, 401, "fleet heartbeat rejected")
		return
	}
	if err != nil {
		a.fail(w, 503, "fleet node policy unavailable")
		return
	}
	a.sendFleetSigned(w, security.FleetNodeDomain, policy)
}

func (s *Store) recordFleetHeartbeat(ctx context.Context, hb security.FleetHeartbeat, hash []byte, now time.Time) (security.FleetNodePolicy, error) {
	tx, err := s.DB.Begin(ctx)
	if err != nil {
		return security.FleetNodePolicy{}, err
	}
	defer tx.Rollback(ctx)
	// Match the existing per-node credential and its one-way stored hash.
	var raw []byte
	err = tx.QueryRow(ctx, "SELECT metadata FROM relay_nodes WHERE id=$1 AND heartbeat_token_hash=$2 FOR UPDATE", hb.ID, hash).Scan(&raw)
	if err != nil {
		return security.FleetNodePolicy{}, err
	}
	row, err := decodeFleetRow(raw)
	if err != nil || row.Fleet == nil || row.ID != hb.ID || !row.Fleet.Phase.Valid() ||
		hb.Sequence <= row.Fleet.Sequence || row.Fleet.Managed == hb.ObserveOnly || hb.ObserveOnly && hb.AppliedVersion != 0 {
		return security.FleetNodePolicy{}, ErrFleetUnavailable
	}
	meta := row.Fleet
	meta.Sequence, meta.AppliedVersion = hb.Sequence, hb.AppliedVersion
	meta.Sampled = hb.Sampled
	if hb.Sampled {
		meta.Observed, meta.Load = now, hb.Used
	}
	version, err := readFleetVersion(ctx, tx)
	if err != nil {
		return security.FleetNodePolicy{}, err
	}
	if hb.AppliedVersion > version {
		return security.FleetNodePolicy{}, ErrFleetUnavailable
	}
	p := security.FleetNodePolicy{Schema: security.FleetSchema, Version: version, NodeID: hb.ID, Phase: meta.Phase,
		IssuedAt: now, AdmitUntil: now.Add(security.FleetFreshness), Limits: meta.Limits,
		ProbeDevice: meta.ProbeDevice, ProbeTarget: meta.ProbeTarget, CanaryDevice: meta.CanaryDevice}
	if err = p.Validate(hb.ID, now); err != nil {
		return security.FleetNodePolicy{}, err
	}
	if err = writeFleetMeta(ctx, tx, hb.ID, meta); err != nil {
		return security.FleetNodePolicy{}, err
	}
	return p, tx.Commit(ctx)
}
