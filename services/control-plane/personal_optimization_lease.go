package controlplane

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/buzzmean/veliq/core/security"
	"github.com/jackc/pgx/v5"
)

type OptimizationLeasePolicy struct {
	Supported         bool `json:"supported"`
	Required          bool `json:"required"`
	TTLSeconds        int  `json:"ttl_seconds"`
	RenewAfterSeconds int  `json:"renew_after_seconds"`
}
type OptimizationLeaseReply struct {
	OptimizationLeasePolicy
	Granted    bool       `json:"granted"`
	ID         string     `json:"lease_id,omitempty"`
	Expires    *time.Time `json:"expires_at,omitempty"`
	ServerTime time.Time  `json:"server_time"`
	Reason     string     `json:"reason,omitempty"`
}

const optimizationLeaseAudience = security.PersonalOptimizationLeaseAudience

func (a *API) currentOptimizationLease(ctx context.Context, device string) (*time.Time, error) {
	policy, err := a.optimizationLeasePolicy(ctx, device)
	if err != nil || !policy.Required {
		return nil, err
	}
	if !policy.Supported {
		return nil, errors.New("LEASE_UNSUPPORTED")
	}
	var until time.Time
	err = a.Store.DB.QueryRow(ctx, `SELECT l.expires_at FROM personal_optimization_leases l
 JOIN subscriptions s ON s.account_id=l.account_id JOIN account_device_bindings b ON b.subscription_id=s.id
 WHERE b.device_id=$1 AND l.device_id=$1 AND l.expires_at>clock_timestamp()`, device).Scan(&until)
	return &until, err
}

func (a *API) optimizationLeasePolicy(ctx context.Context, device string) (OptimizationLeasePolicy, error) {
	o := OptimizationLeasePolicy{Supported: a.Settings.PersonalOptimizationLeases, TTLSeconds: 60, RenewAfterSeconds: 20}
	if !o.Supported {
		// Old schemas/devices keep their existing path; a staged identity cannot downgrade on flag OFF.
		var modern bool
		if e := a.Store.DB.QueryRow(ctx, "SELECT coalesce((to_jsonb(d)->>'personal_optimization_lease_v1')::boolean,false) FROM devices d WHERE id=$1", device).Scan(&modern); e != nil {
			return o, e
		}
		if !modern {
			return o, nil
		}
	}

	err := a.Store.DB.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM devices d JOIN account_device_bindings b ON b.device_id=d.id
 JOIN subscriptions s ON s.id=b.subscription_id JOIN accounts a ON a.id=s.account_id
 WHERE d.id=$1 AND NOT d.revoked AND NOT a.disabled
 AND s.kind='player' AND s.seats=1 AND NOT s.lifetime AND s.personal_optimization_lease_stage)`, device).Scan(&o.Required)
	return o, err
}

func (s *Store) changeOptimizationLease(ctx context.Context, device, action, id string) (OptimizationLeaseReply, error) {
	o := OptimizationLeaseReply{OptimizationLeasePolicy: OptimizationLeasePolicy{Supported: true, Required: true, TTLSeconds: 60, RenewAfterSeconds: 20}}
	tx, err := s.DB.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return o, err
	}
	defer tx.Rollback(ctx)
	var account string
	err = tx.QueryRow(ctx, `SELECT s.account_id FROM devices d JOIN account_device_bindings b ON b.device_id=d.id
 JOIN subscriptions s ON s.id=b.subscription_id WHERE d.id=$1 AND NOT d.revoked AND d.personal_optimization_lease_v1
 AND s.kind='player' AND s.seats=1 AND NOT s.lifetime AND s.personal_optimization_lease_stage`, device).Scan(&account)
	if errors.Is(err, pgx.ErrNoRows) {
		o.Reason = "LEASE_UNSUPPORTED"
		return o, nil
	}
	if err != nil {
		return o, err
	}
	var disabled bool
	if err = tx.QueryRow(ctx, "SELECT disabled FROM accounts WHERE id=$1 FOR NO KEY UPDATE", account).Scan(&disabled); err != nil {
		return o, err
	}
	// Use server time after serializing the account. Never extend past entitlement.
	var until time.Time
	err = tx.QueryRow(ctx, `SELECT clock_timestamp(),greatest(coalesce(s.paid_until+interval '3 days','epoch'::timestamptz),coalesce(s.trial_until,'epoch'::timestamptz))
 FROM subscriptions s JOIN account_device_bindings b ON b.subscription_id=s.id JOIN devices d ON d.id=b.device_id
 WHERE d.id=$1 AND NOT d.revoked AND d.personal_optimization_lease_v1 AND s.account_id=$2 AND s.kind='player' AND NOT s.lifetime`, device, account).Scan(&o.ServerTime, &until)
	if err != nil {
		return o, err
	}
	if disabled || !until.After(o.ServerTime) {
		o.Reason = "SUBSCRIPTION_EXPIRED"
		return o, nil
	}
	var holder, lease string
	var expires time.Time
	err = tx.QueryRow(ctx, "SELECT device_id,lease_id,expires_at FROM personal_optimization_leases WHERE account_id=$1 FOR UPDATE", account).Scan(&holder, &lease, &expires)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return o, err
	}
	exists := err == nil
	active := exists && expires.After(o.ServerTime)
	if action == "release" {
		if exists && holder == device && lease == id {
			if _, err = tx.Exec(ctx, "DELETE FROM personal_optimization_leases WHERE account_id=$1", account); err != nil {
				return o, err
			}
			o.Granted = true
		} else {
			o.Reason = "LEASE_MISMATCH"
		}
		return o, tx.Commit(ctx)
	}
	if action == "renew" && (!active || holder != device || lease != id) {
		o.Reason = "LEASE_EXPIRED"
		if active {
			o.Reason = "LEASE_MISMATCH"
		}
		return o, tx.Commit(ctx)
	}
	if action == "acquire" && active && holder != device {
		o.Reason = "ACTIVE_ON_OTHER_DEVICE"
		return o, tx.Commit(ctx)
	}
	if !active {
		lease, err = security.NewID()
		if err != nil {
			return o, err
		}
	}
	expires = o.ServerTime.Add(60 * time.Second)
	if expires.After(until) {
		expires = until
	}
	if _, err = tx.Exec(ctx, `INSERT INTO personal_optimization_leases(account_id,device_id,lease_id,expires_at) VALUES($1,$2,$3,$4)
 ON CONFLICT(account_id) DO UPDATE SET device_id=excluded.device_id,lease_id=excluded.lease_id,expires_at=excluded.expires_at`, account, device, lease, expires); err != nil {
		return o, err
	}
	if _, err = tx.Exec(ctx, "INSERT INTO audit_log(actor,action,entity_id) VALUES($1,$2,$3)", "device:"+device, "optimization-lease."+action, account); err != nil {
		return o, err
	}
	o.Granted = true
	o.ID = lease
	o.Expires = &expires
	return o, tx.Commit(ctx)
}

func (a *API) optimizationLease(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	var q struct {
		Proof  security.Proof `json:"proof"`
		Action string         `json:"action"`
		ID     string         `json:"lease_id"`
	}
	if body(r, &q) != nil {
		a.fail(w, 400, "LEASE_REQUEST_INVALID")
		return
	}
	audience, audienceErr := security.PersonalOptimizationLeaseProofAudience(q.Action, q.ID)
	if audienceErr != nil || q.Proof.RelayID != audience {
		a.fail(w, 400, "LEASE_REQUEST_INVALID")
		return
	}
	d, err := a.Store.Device(r.Context(), q.Proof.DeviceID)
	if err != nil || d.Revoked {
		a.fail(w, 401, "LEASE_PROOF_INVALID")
		return
	}
	pub, err := security.DecodePublicKey(d.PublicKey)
	if err != nil || q.Proof.Verify(pub, time.Now()) != nil || a.Store.ConsumeProof(r.Context(), q.Proof) != nil {
		a.fail(w, 401, "LEASE_PROOF_INVALID")
		return
	}
	policy, err := a.optimizationLeasePolicy(r.Context(), d.ID)
	if err != nil {
		a.fail(w, 503, "LEASE_UNAVAILABLE")
		return
	}
	if !policy.Supported || !policy.Required {
		respond(w, 409, OptimizationLeaseReply{OptimizationLeasePolicy: policy, ServerTime: time.Now().UTC(), Reason: "LEASE_UNSUPPORTED"})
		return
	}
	o, err := a.Store.changeOptimizationLease(r.Context(), d.ID, q.Action, q.ID)
	if err != nil {
		a.fail(w, 503, "LEASE_UNAVAILABLE")
		return
	}
	status := 200
	if !o.Granted {
		status = 409
	}
	respond(w, status, o)
}
