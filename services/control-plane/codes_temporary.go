package controlplane

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/buzzmean/veliq/core/enrollment"
	"github.com/buzzmean/veliq/core/security"
)

// TEMPORARY OWNER TEST ONLY. Ordinary CreateCode cannot create short codes.
// The authenticated administrative action is the explicit opt-in; no default
// code exists, and knowing the source code alone grants no enrollment access.
func (s *Store) CreateTestCode(ctx context.Context, value, name string) (ActivationCode, error) {
	c := ActivationCode{Kind: "test", Limit: 2, Name: "[TEST] " + name, Expires: time.Now().UTC().Add(14 * 24 * time.Hour)}
	if value != "test" || strings.TrimSpace(name) == "" || len(c.Name) > 128 {
		return c, errors.New("ACTIVATION_CONFIGURATION_INVALID")
	}
	hash, _ := enrollment.CodeHash(value)
	id, err := security.NewID()
	if err != nil {
		return c, errors.New("ACTIVATION_UNAVAILABLE")
	}
	c.ID = id
	// Never resurrect a revoked/expired credential with the same public value.
	tag, err := s.DB.Exec(ctx, `INSERT INTO activation_codes(id,code_hash,kind,seat_limit,name,expires_at) VALUES($1,$2,'test',2,$3,$4) ON CONFLICT(code_hash) DO NOTHING`, id, hash, c.Name, c.Expires)
	if err != nil {
		return c, errors.New("ACTIVATION_UNAVAILABLE")
	}
	if tag.RowsAffected() != 1 {
		return c, errors.New("TEST_CODE_ALREADY_EXISTS")
	}
	return c, nil
}

// Revoke every test credential and its current devices, in the same transaction
// as signed config publication. Nothing is deleted: replay/revocation history
// and normal club/personal credentials are preserved. Serialized with enroll.
func (s *Store) RevokeTestCodes(ctx context.Context, kid string, key []byte, public map[string]string) (int64, error) {
	tx, err := s.DB.Begin(ctx)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback(ctx)
	if _, err = tx.Exec(ctx, "SELECT pg_advisory_xact_lock(724220)"); err != nil {
		return 0, err
	}
	tag, err := tx.Exec(ctx, "UPDATE activation_codes SET revoked=true WHERE kind='test' AND NOT revoked")
	if err != nil {
		return 0, err
	}
	// Also repair device revocation if a past partial/manual change revoked only
	// the code; therefore repeat calls are safe even when no new code is revoked.
	devices, err := tx.Exec(ctx, `UPDATE devices SET revoked=true WHERE NOT revoked AND id IN (SELECT s.device_id FROM activation_slots s JOIN activation_codes c ON c.id=s.code_id WHERE c.kind='test')`)
	if err != nil {
		return 0, err
	}
	if tag.RowsAffected() > 0 || devices.RowsAffected() > 0 {
		if _, err = tx.Exec(ctx, "INSERT INTO audit_log(actor,action,entity_id) VALUES('activation-admin','test-codes.revoke-all','all-test-codes')"); err != nil {
			return 0, err
		}
		if _, err = publishConfigTx(ctx, tx, kid, key, public); err != nil {
			return 0, err
		}
	}
	if err = tx.Commit(ctx); err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}
