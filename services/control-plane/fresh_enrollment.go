package controlplane

import (
	"context"
	"errors"
	"github.com/jackc/pgx/v5"
	"regexp"
)

// EnrollFreshDevice is root-SSH tooling, not a public HTTP endpoint. The caller
// MUST validate CSR possession and authenticate the operator before this method.
// One active device per hardware slot; same CSR retry is idempotent. Replacement,
// revocation and COMPLETE signed config publication commit together or not at all.
func (s *Store) EnrollFreshDevice(ctx context.Context, machine string, d Device, kid string, key []byte, public map[string]string) error {
	if !regexp.MustCompile(`^[a-f0-9]{64}$`).MatchString(machine) || d.ID == "" || d.PublicKey == "" {
		return errors.New("invalid machine enrollment")
	}
	tx, e := s.DB.Begin(ctx)
	if e != nil {
		return e
	}
	defer tx.Rollback(ctx)
	if _, e = tx.Exec(ctx, "SELECT pg_advisory_xact_lock(724220)"); e != nil {
		return e
	}
	if _, e = tx.Exec(ctx, `CREATE TABLE IF NOT EXISTS fresh_machine_slots(machine_hash text PRIMARY KEY, device_id text NOT NULL REFERENCES devices(id), updated_at timestamptz NOT NULL DEFAULT now())`); e != nil {
		return e
	}
	var old string
	e = tx.QueryRow(ctx, "SELECT device_id FROM fresh_machine_slots WHERE machine_hash=$1 FOR UPDATE", machine).Scan(&old)
	if e != nil && !errors.Is(e, pgx.ErrNoRows) {
		return e
	}
	var pub string
	var revoked bool
	e = tx.QueryRow(ctx, "SELECT public_key,revoked FROM devices WHERE id=$1 FOR UPDATE", d.ID).Scan(&pub, &revoked)
	if e == nil {
		if old != d.ID || pub != d.PublicKey || revoked {
			return errors.New("device already bound or revoked; new identity required")
		}
	} else if errors.Is(e, pgx.ErrNoRows) {
		if _, e = tx.Exec(ctx, "INSERT INTO devices(id,user_id,name,public_key) VALUES($1,'owner',$2,$3)", d.ID, d.Name, d.PublicKey); e != nil {
			return e
		}
	} else {
		return e
	}
	if old != "" && old != d.ID {
		if _, e = tx.Exec(ctx, "UPDATE devices SET revoked=true WHERE id=$1", old); e != nil {
			return e
		}
		if _, e = tx.Exec(ctx, "INSERT INTO audit_log(actor,action,entity_id) VALUES('fresh-pc-ssh','device.replaced',$1)", old); e != nil {
			return e
		}
	}
	if _, e = tx.Exec(ctx, "INSERT INTO fresh_machine_slots(machine_hash,device_id) VALUES($1,$2) ON CONFLICT(machine_hash) DO UPDATE SET device_id=excluded.device_id,updated_at=now()", machine, d.ID); e != nil {
		return e
	}
	if _, e = tx.Exec(ctx, "INSERT INTO audit_log(actor,action,entity_id) VALUES('fresh-pc-ssh','device.enroll',$1)", d.ID); e != nil {
		return e
	}
	if _, e = publishConfigTx(ctx, tx, kid, key, public); e != nil {
		return e
	}
	return tx.Commit(ctx)
}
