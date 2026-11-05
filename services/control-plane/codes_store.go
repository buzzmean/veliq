package controlplane

import (
	"context"
	"encoding/hex"
	"errors"
	"github.com/buzzmean/neexitlag/core/enrollment"
	"github.com/buzzmean/neexitlag/core/security"
	"github.com/jackc/pgx/v5"
	"time"
)

type ActivationCode struct {
	ID      string    `json:"id"`
	Kind    string    `json:"kind"`
	Limit   int       `json:"limit"`
	Name    string    `json:"name"`
	Expires time.Time `json:"expires_at"`
	Revoked bool      `json:"revoked"`
}
type ActivationMachine struct {
	Hash     string `json:"machine_hash"`
	Device   string `json:"device_id"`
	Disabled bool   `json:"disabled"`
}

func (s *Store) HardwareSalt(ctx context.Context) (string, error) {
	var b []byte
	e := s.DB.QueryRow(ctx, "SELECT hardware_salt FROM activation_policy WHERE singleton").Scan(&b)
	return hex.EncodeToString(b), e
}
func (s *Store) CreateCode(ctx context.Context, c ActivationCode) (ActivationCode, string, error) {
	if c.Kind != "club" && c.Kind != "personal" || c.Limit < 1 || c.Limit > 10000 || c.Kind == "personal" && c.Limit != 2 || len(c.Name) > 128 || c.Name == "" || !c.Expires.After(time.Now()) || c.Expires.After(time.Now().Add(366*24*time.Hour)) {
		return c, "", errors.New("ACTIVATION_CONFIGURATION_INVALID")
	}
	code, e := enrollment.NewCode()
	if e != nil {
		return c, "", e
	}
	hash, _ := enrollment.CodeHash(code)
	c.ID, e = security.NewID()
	if e != nil {
		return c, "", e
	}
	_, e = s.DB.Exec(ctx, "INSERT INTO activation_codes(id,code_hash,kind,seat_limit,name,expires_at) VALUES($1,$2,$3,$4,$5,$6)", c.ID, hash, c.Kind, c.Limit, c.Name, c.Expires)
	if e != nil {
		return c, "", errors.New("ACTIVATION_UNAVAILABLE")
	}
	return c, code, nil
}
func (s *Store) Codes(ctx context.Context) ([]ActivationCode, error) {
	rows, e := s.DB.Query(ctx, "SELECT id,kind,seat_limit,name,expires_at,revoked FROM activation_codes ORDER BY id LIMIT 1001")
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []ActivationCode{}
	for rows.Next() {
		var c ActivationCode
		if e = rows.Scan(&c.ID, &c.Kind, &c.Limit, &c.Name, &c.Expires, &c.Revoked); e != nil {
			return nil, e
		}
		out = append(out, c)
	}
	if len(out) > 1000 {
		return nil, errors.New("ACTIVATION_LIST_TOO_LARGE")
	}
	return out, rows.Err()
}
func (s *Store) CodeMachines(ctx context.Context, id string) ([]ActivationMachine, error) {
	rows, e := s.DB.Query(ctx, "SELECT machine_hash,device_id,disabled FROM activation_slots WHERE code_id=$1 ORDER BY machine_hash LIMIT 10001", id)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []ActivationMachine{}
	for rows.Next() {
		var c ActivationMachine
		if e = rows.Scan(&c.Hash, &c.Device, &c.Disabled); e != nil {
			return nil, e
		}
		out = append(out, c)
	}
	if len(out) > 10000 {
		return nil, errors.New("ACTIVATION_LIST_TOO_LARGE")
	}
	return out, rows.Err()
}

// Lock order matches root fresh enrollment and config publication. The entire
// replacement/revocation/config publication succeeds or rolls back as one unit.
func (s *Store) EnrollCode(ctx context.Context, hash []byte, machine string, d Device, kid string, key []byte, public map[string]string) error {
	tx, e := s.DB.Begin(ctx)
	if e != nil {
		return e
	}
	defer tx.Rollback(ctx)
	if _, e = tx.Exec(ctx, "SELECT pg_advisory_xact_lock(724220)"); e != nil {
		return e
	}
	var id string
	var limit int
	var revoked bool
	var expires time.Time
	e = tx.QueryRow(ctx, "SELECT id,seat_limit,revoked,expires_at FROM activation_codes WHERE code_hash=$1 FOR UPDATE", hash).Scan(&id, &limit, &revoked, &expires)
	if errors.Is(e, pgx.ErrNoRows) {
		return errors.New("ACTIVATION_INVALID")
	}
	if e != nil {
		return e
	}
	if revoked {
		return errors.New("ACTIVATION_REVOKED")
	}
	if !time.Now().Before(expires) {
		return errors.New("ACTIVATION_EXPIRED")
	}
	if e = enrollSlotTx(ctx, tx, id, limit, machine, d, kid, key, public, ""); e != nil {
		return e
	}
	return tx.Commit(ctx)
}

// Caller holds the global enrollment lock and the authorization row.
func enrollSlotTx(ctx context.Context, tx pgx.Tx, id string, limit int, machine string, d Device, kid string, key []byte, public map[string]string, account string) error {
	var old string
	var disabled bool
	e := tx.QueryRow(ctx, "SELECT device_id,disabled FROM activation_slots WHERE code_id=$1 AND machine_hash=$2 FOR UPDATE", id, machine).Scan(&old, &disabled)
	if e != nil && !errors.Is(e, pgx.ErrNoRows) {
		return e
	}
	if disabled {
		return errors.New("MACHINE_DISABLED")
	}
	if old == "" {
		var n int
		if e = tx.QueryRow(ctx, "SELECT count(*) FROM activation_slots WHERE code_id=$1 AND NOT disabled", id).Scan(&n); e != nil {
			return e
		}
		if n >= limit {
			return errors.New("ACTIVATION_LIMIT")
		}
	}
	var pub string
	var dead bool
	e = tx.QueryRow(ctx, "SELECT public_key,revoked FROM devices WHERE id=$1 FOR UPDATE", d.ID).Scan(&pub, &dead)
	if e == nil {
		if pub != d.PublicKey || dead || old != d.ID && account == "" {
			return errors.New("ACTIVATION_IDENTITY_CONFLICT")
		}
		if old != d.ID {
			var foreign bool
			if e = tx.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM activation_slots sl JOIN activation_codes c ON c.id=sl.code_id JOIN subscriptions sub ON sub.id=c.subscription_id WHERE sl.device_id=$1 AND NOT sl.disabled AND sub.account_id<>$2)", d.ID, account).Scan(&foreign); e != nil {
				return e
			}
			if foreign {
				return errors.New("ACCOUNT_DEVICE_ALREADY_OWNED")
			}
		}
	} else if errors.Is(e, pgx.ErrNoRows) {
		if _, e = tx.Exec(ctx, "INSERT INTO devices(id,user_id,name,public_key) VALUES($1,'owner',$2,$3)", d.ID, d.Name, d.PublicKey); e != nil {
			return e
		}
	} else {
		return e
	}
	if account != "" {
		if _, e = tx.Exec(ctx, "INSERT INTO account_device_bindings(device_id,subscription_id) SELECT $1,subscription_id FROM activation_codes WHERE id=$2 ON CONFLICT(device_id) DO UPDATE SET subscription_id=excluded.subscription_id", d.ID, id); e != nil {
			return e
		}
	}
	if old == d.ID {
		return nil
	}
	if old != "" && old != d.ID {
		if _, e = tx.Exec(ctx, "UPDATE devices SET revoked=true WHERE id=$1", old); e != nil {
			return e
		}
	}
	if _, e = tx.Exec(ctx, "INSERT INTO activation_slots(code_id,machine_hash,device_id) VALUES($1,$2,$3) ON CONFLICT(code_id,machine_hash) DO UPDATE SET device_id=excluded.device_id,updated_at=now()", id, machine, d.ID); e != nil {
		return e
	}
	if _, e = tx.Exec(ctx, "INSERT INTO audit_log(actor,action,entity_id) VALUES('activation','device.enroll',$1)", d.ID); e != nil {
		return e
	}
	if _, e = publishConfigTx(ctx, tx, kid, key, public); e != nil {
		return e
	}
	return nil
}
func (s *Store) RevokeCode(ctx context.Context, id, machine string, kid string, key []byte, public map[string]string) error {
	tx, e := s.DB.Begin(ctx)
	if e != nil {
		return e
	}
	defer tx.Rollback(ctx)
	if _, e = tx.Exec(ctx, "SELECT pg_advisory_xact_lock(724220)"); e != nil {
		return e
	}
	if machine == "" {
		if tag, err := tx.Exec(ctx, "UPDATE activation_codes SET revoked=true WHERE id=$1", id); err != nil {
			return err
		} else if tag.RowsAffected() != 1 {
			return errors.New("ACTIVATION_NOT_FOUND")
		}
	} else {
		if tag, err := tx.Exec(ctx, "UPDATE activation_slots SET disabled=true WHERE code_id=$1 AND machine_hash=$2", id, machine); err != nil {
			return err
		} else if tag.RowsAffected() != 1 {
			return errors.New("ACTIVATION_NOT_FOUND")
		}
	}
	if _, e = tx.Exec(ctx, "UPDATE devices SET revoked=true WHERE id IN (SELECT device_id FROM activation_slots WHERE code_id=$1 AND ($2='' OR machine_hash=$2))", id, machine); e != nil {
		return e
	}
	if _, e = tx.Exec(ctx, "INSERT INTO audit_log(actor,action,entity_id) VALUES('activation-admin','code.revoke',$1)", id); e != nil {
		return e
	}
	if _, e = publishConfigTx(ctx, tx, kid, key, public); e != nil {
		return e
	}
	return tx.Commit(ctx)
}

// Admin inventory is paged; unlike signed revocation publication it must fit a
// small HTTP response. No truncation is silently presented as the complete list.
func (s *Store) CodesPage(ctx context.Context, after string) ([]ActivationCode, string, error) {
	rows, e := s.DB.Query(ctx, "SELECT id,kind,seat_limit,name,expires_at,revoked FROM activation_codes WHERE id>$1 ORDER BY id LIMIT 129", after)
	if e != nil {
		return nil, "", e
	}
	defer rows.Close()
	out := []ActivationCode{}
	for rows.Next() {
		var c ActivationCode
		if e = rows.Scan(&c.ID, &c.Kind, &c.Limit, &c.Name, &c.Expires, &c.Revoked); e != nil {
			return nil, "", e
		}
		out = append(out, c)
	}
	next := ""
	if len(out) > 128 {
		out = out[:128]
		next = out[len(out)-1].ID
	}
	return out, next, rows.Err()
}
func (s *Store) MachinesPage(ctx context.Context, id, after string) ([]ActivationMachine, string, error) {
	rows, e := s.DB.Query(ctx, "SELECT machine_hash,device_id,disabled FROM activation_slots WHERE code_id=$1 AND machine_hash>$2 ORDER BY machine_hash LIMIT 129", id, after)
	if e != nil {
		return nil, "", e
	}
	defer rows.Close()
	out := []ActivationMachine{}
	for rows.Next() {
		var m ActivationMachine
		if e = rows.Scan(&m.Hash, &m.Device, &m.Disabled); e != nil {
			return nil, "", e
		}
		out = append(out, m)
	}
	next := ""
	if len(out) > 128 {
		out = out[:128]
		next = out[len(out)-1].Hash
	}
	return out, next, rows.Err()
}
