package controlplane

import (
	"context"
	"crypto/rand"
	"embed"
	"encoding/json"
	"errors"
	"github.com/buzzmean/neexitlag/core/optimizer"
	"github.com/buzzmean/neexitlag/core/profiles"
	"github.com/buzzmean/neexitlag/core/security"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"time"
)

//go:embed migrations/*.sql
var migrations embed.FS

type Store struct{ DB *pgxpool.Pool }

func Open(ctx context.Context, url string) (*Store, error) {
	cfg, e := pgxpool.ParseConfig(url)
	if e != nil {
		return nil, e
	}
	cfg.MaxConns = 8
	cfg.MinConns = 1
	cfg.MaxConnIdleTime = 5 * time.Minute
	p, e := pgxpool.NewWithConfig(ctx, cfg)
	if e != nil {
		return nil, e
	}
	if e = p.Ping(ctx); e != nil {
		p.Close()
		return nil, e
	}
	return &Store{p}, nil
}
func (s *Store) Migrate(ctx context.Context) error {
	tx, e := s.DB.Begin(ctx)
	if e != nil {
		return e
	}
	defer tx.Rollback(ctx)
	if _, e = tx.Exec(ctx, "SELECT pg_advisory_xact_lock(724219)"); e != nil {
		return e
	}
	b, e := migrations.ReadFile("migrations/001_initial.sql")
	if e != nil {
		return e
	}
	if _, e = tx.Exec(ctx, string(b)); e != nil {
		return e
	}
	for _, name := range []string{"migrations/002_activation_codes.sql", "migrations/003_temporary_test_codes.sql", "migrations/004_accounts_subscriptions.sql"} {
		b, e := migrations.ReadFile(name)
		if e != nil {
			return e
		}
		if _, e = tx.Exec(ctx, string(b)); e != nil {
			return e
		}
	}
	salt := make([]byte, 32)
	if _, e = rand.Read(salt); e != nil {
		return e
	}
	if _, e = tx.Exec(ctx, "INSERT INTO activation_policy(singleton,hardware_salt) VALUES(true,$1) ON CONFLICT DO NOTHING", salt); e != nil {
		return e
	}
	for _, p := range profiles.Defaults() {
		b, _ := json.Marshal(p)
		if _, e = tx.Exec(ctx, "INSERT INTO application_profiles(id,profile) VALUES($1,$2) ON CONFLICT DO NOTHING", p.ID, b); e != nil {
			return e
		}
	}
	return tx.Commit(ctx)
}

type Device struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	PublicKey string `json:"public_key"`
	Revoked   bool   `json:"revoked"`
}

func (s *Store) Device(ctx context.Context, id string) (Device, error) {
	var d Device
	e := s.DB.QueryRow(ctx, "SELECT id,name,public_key,revoked FROM devices WHERE id=$1", id).Scan(&d.ID, &d.Name, &d.PublicKey, &d.Revoked)
	return d, e
}
func (s *Store) Register(ctx context.Context, d Device) error {
	tx, e := s.DB.Begin(ctx)
	if e != nil {
		return e
	}
	defer tx.Rollback(ctx)
	_, e = tx.Exec(ctx, "INSERT INTO devices(id,user_id,name,public_key) VALUES($1,'owner',$2,$3)", d.ID, d.Name, d.PublicKey)
	if e != nil {
		return e
	}
	if _, e = tx.Exec(ctx, "INSERT INTO audit_log(actor,action,entity_id) VALUES('owner','device.register',$1)", d.ID); e != nil {
		return e
	}
	return tx.Commit(ctx)
}
func (s *Store) Revoke(ctx context.Context, id string) error {
	tx, e := s.DB.Begin(ctx)
	if e != nil {
		return e
	}
	defer tx.Rollback(ctx)
	tag, e := tx.Exec(ctx, "UPDATE devices SET revoked=true WHERE id=$1", id)
	if e != nil {
		return e
	}
	if tag.RowsAffected() != 1 {
		return errors.New("device not found")
	}
	if _, e = tx.Exec(ctx, "INSERT INTO audit_log(actor,action,entity_id) VALUES('owner','device.revoke',$1)", id); e != nil {
		return e
	}
	return tx.Commit(ctx)
}
func (s *Store) ConsumeProof(ctx context.Context, p security.Proof) error {
	tx, e := s.DB.Begin(ctx)
	if e != nil {
		return e
	}
	defer tx.Rollback(ctx)
	var revoked bool
	if e = tx.QueryRow(ctx, "SELECT revoked FROM devices WHERE id=$1 FOR UPDATE", p.DeviceID).Scan(&revoked); e != nil {
		return e
	}
	if revoked {
		return errors.New("device revoked")
	}
	if _, e = tx.Exec(ctx, "DELETE FROM auth_nonces WHERE expires_at < now()"); e != nil {
		return e
	}
	if _, e = tx.Exec(ctx, "INSERT INTO auth_nonces(device_id,nonce,expires_at) VALUES($1,$2,$3)", p.DeviceID, p.Nonce, time.Now().Add(2*time.Minute)); e != nil {
		return e
	}
	if _, e = tx.Exec(ctx, "UPDATE devices SET last_authenticated_at=now() WHERE id=$1", p.DeviceID); e != nil {
		return e
	}
	return tx.Commit(ctx)
}

type querier interface {
	Query(context.Context, string, ...any) (pgx.Rows, error)
}

func (s *Store) Devices(ctx context.Context) ([]Device, error) { return readDevices(ctx, s.DB) }
func readDevices(ctx context.Context, q querier) ([]Device, error) {
	rows, e := q.Query(ctx, "SELECT id,name,public_key,revoked FROM devices ORDER BY id LIMIT 1000")
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []Device{}
	for rows.Next() {
		var d Device
		if e = rows.Scan(&d.ID, &d.Name, &d.PublicKey, &d.Revoked); e != nil {
			return nil, e
		}
		out = append(out, d)
	}
	return out, rows.Err()
}
func (s *Store) Relays(ctx context.Context) ([]optimizer.RelayCandidate, error) {
	return readRelays(ctx, s.DB)
}
func readRelays(ctx context.Context, q querier) ([]optimizer.RelayCandidate, error) {
	rows, e := q.Query(ctx, "SELECT metadata FROM relay_nodes ORDER BY id LIMIT 32")
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []optimizer.RelayCandidate{}
	for rows.Next() {
		var raw []byte
		var r optimizer.RelayCandidate
		if e = rows.Scan(&raw); e != nil {
			return nil, e
		}
		if e = json.Unmarshal(raw, &r); e != nil {
			return nil, e
		}
		out = append(out, r)
	}
	return out, rows.Err()
}
func (s *Store) Apps(ctx context.Context) ([]profiles.Profile, error) { return readApps(ctx, s.DB) }
func readApps(ctx context.Context, q querier) ([]profiles.Profile, error) {
	rows, e := q.Query(ctx, "SELECT profile FROM application_profiles ORDER BY id LIMIT 128")
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []profiles.Profile{}
	for rows.Next() {
		var raw []byte
		var p profiles.Profile
		if e = rows.Scan(&raw); e != nil {
			return nil, e
		}
		if e = json.Unmarshal(raw, &p); e != nil {
			return nil, e
		}
		out = append(out, p)
	}
	return out, rows.Err()
}
func (s *Store) PutRelay(ctx context.Context, r optimizer.RelayCandidate) error {
	b, _ := json.Marshal(r)
	_, e := s.DB.Exec(ctx, "INSERT INTO relay_nodes(id,metadata) VALUES($1,$2) ON CONFLICT(id) DO UPDATE SET metadata=excluded.metadata", r.ID, b)
	return e
}
func (s *Store) PutApp(ctx context.Context, p profiles.Profile) error {
	b, _ := json.Marshal(p)
	_, e := s.DB.Exec(ctx, "INSERT INTO application_profiles(id,profile) VALUES($1,$2) ON CONFLICT(id) DO UPDATE SET profile=excluded.profile", p.ID, b)
	return e
}
func (s *Store) LatestConfig(ctx context.Context) ([]byte, error) {
	var raw []byte
	e := s.DB.QueryRow(ctx, "SELECT document FROM config_versions ORDER BY version DESC LIMIT 1").Scan(&raw)
	return raw, e
}

// Publication must never use the bounded admin Devices listing. One SQL
// statement reads the complete committed revocation snapshot, including errors
// encountered after rows have streamed. The surrounding publication transaction
// commits the signed document and audit entry together, serialized by version.
func readRevokedIDs(ctx context.Context, q querier) ([]string, error) {
	rows, err := q.Query(ctx, "SELECT id FROM devices WHERE revoked ORDER BY id")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	ids := []string{}
	size := 0
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		raw, err := json.Marshal(id)
		if err != nil {
			return nil, err
		}
		size += len(raw) + 1
		if size > security.MaxConfigDocument {
			return nil, errors.New("complete revocation set exceeds configuration size limit; publication aborted")
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return ids, nil
}

func (s *Store) Publish(ctx context.Context, kid string, key []byte, public map[string]string) ([]byte, error) {
	tx, e := s.DB.Begin(ctx)
	if e != nil {
		return nil, e
	}
	defer tx.Rollback(ctx)
	raw, e := publishConfigTx(ctx, tx, kid, key, public)
	if e != nil {
		return nil, e
	}
	if e = tx.Commit(ctx); e != nil {
		return nil, e
	}
	return raw, nil
}

func publishConfigTx(ctx context.Context, tx pgx.Tx, kid string, key []byte, public map[string]string) ([]byte, error) {
	var e error
	if _, e = tx.Exec(ctx, "SELECT pg_advisory_xact_lock(724220)"); e != nil {
		return nil, e
	}
	var version uint64
	if e = tx.QueryRow(ctx, "SELECT nextval(pg_get_serial_sequence('config_versions','version'))").Scan(&version); e != nil {
		return nil, e
	}
	relays, e := readRelays(ctx, tx)
	if e != nil {
		return nil, e
	}
	apps, e := readApps(ctx, tx)
	if e != nil {
		return nil, e
	}
	revoked, e := readRevokedIDs(ctx, tx)
	if e != nil {
		return nil, e
	}
	now := time.Now().UTC()
	cfg := security.Config{Version: version, GeneratedAt: now, ExpiresAt: now.Add(24 * time.Hour), Relays: relays, ApplicationProfiles: apps, RoutingParameters: optimizer.DefaultParameters(), PublicKeys: public, RevokedDevices: revoked, ClientVersion: "0.3.0-dev"}
	raw, e := security.Sign("config", kid, key, cfg)
	if e != nil {
		return nil, e
	}
	if _, e = tx.Exec(ctx, "INSERT INTO config_versions(version,document,generated_at,expires_at) VALUES($1,$2,$3,$4)", version, raw, now, cfg.ExpiresAt); e != nil {
		return nil, e
	}
	if _, e = tx.Exec(ctx, "INSERT INTO audit_log(actor,action,entity_id) VALUES('owner','config.publish',$1)", kid); e != nil {
		return nil, e
	}

	return raw, nil
}

var _ = pgx.ErrNoRows

func (s *Store) SetHeartbeatToken(ctx context.Context, id string, hash []byte) error {
	_, e := s.DB.Exec(ctx, "UPDATE relay_nodes SET heartbeat_token_hash=$2 WHERE id=$1", id, hash)
	return e
}
func (s *Store) Heartbeat(ctx context.Context, id string, hash []byte, healthy bool, load float64) error {
	tag, e := s.DB.Exec(ctx, "UPDATE relay_nodes SET healthy=$3,heartbeat_at=now(),metadata=jsonb_set(metadata,'{load}',to_jsonb($4::double precision)) WHERE id=$1 AND heartbeat_token_hash=$2", id, hash, healthy, load)
	if e != nil {
		return e
	}
	if tag.RowsAffected() != 1 {
		return errors.New("invalid relay identity")
	}
	return nil
}
