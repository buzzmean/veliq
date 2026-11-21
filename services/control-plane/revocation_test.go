package controlplane

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"github.com/buzzmean/neexitlag/core/optimizer"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/buzzmean/neexitlag/core/controlclient"
	"github.com/buzzmean/neexitlag/core/security"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type revokedRows struct {
	pgx.Rows
	ids               []string
	at                int
	queryErr, scanErr error
	closed            bool
}

func (r *revokedRows) Next() bool { return r.at < len(r.ids) }
func (r *revokedRows) Scan(v ...any) error {
	if r.scanErr != nil {
		return r.scanErr
	}
	*v[0].(*string) = r.ids[r.at]
	r.at++
	return nil
}
func (r *revokedRows) Err() error { return r.queryErr }
func (r *revokedRows) Close()     { r.closed = true }

type revokedQuery struct {
	rows *revokedRows
	err  error
	sql  string
}

func (q *revokedQuery) Query(_ context.Context, sql string, _ ...any) (pgx.Rows, error) {
	q.sql = sql
	return q.rows, q.err
}

func TestRevokedSnapshotCompleteOrError(t *testing.T) {
	ids := make([]string, 5000)
	for i := range ids {
		ids[i] = fmt.Sprintf("%032d", i)
	}
	bad := errors.New("DB streaming failed")
	for _, stage := range []string{"success", "query", "scan", "rows"} {
		t.Run(stage, func(t *testing.T) {
			q := &revokedQuery{rows: &revokedRows{ids: ids}}
			switch stage {
			case "query":
				q.err = bad
			case "scan":
				q.rows.scanErr = bad
			case "rows":
				q.rows.queryErr = bad
			}
			got, err := readRevokedIDs(context.Background(), q)
			if strings.Contains(strings.ToUpper(q.sql), "LIMIT") || !strings.Contains(q.sql, "WHERE revoked") {
				t.Fatal("bounded admin listing used", q.sql)
			}
			if stage == "success" {
				if err != nil || !reflect.DeepEqual(got, ids) {
					t.Fatal(len(got), err)
				}
			} else if !errors.Is(err, bad) || got != nil {
				t.Fatal("partial snapshot escaped", len(got), err)
			}
			if stage != "query" && !q.rows.closed {
				t.Fatal("rows leaked")
			}
		})
	}
	q := &revokedQuery{rows: &revokedRows{ids: []string{strings.Repeat("x", security.MaxConfigDocument)}}}
	if got, err := readRevokedIDs(context.Background(), q); err == nil || got != nil {
		t.Fatal("oversized revocations silently truncated")
	}
}

func revocationStore(t *testing.T) (*Store, context.Context) {
	t.Helper()
	url := os.Getenv("NEEXITLAG_TEST_DATABASE_URL")
	if url == "" {
		t.Skip("set NEEXITLAG_TEST_DATABASE_URL for PostgreSQL revocation integration")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	t.Cleanup(cancel)
	root, err := pgxpool.New(ctx, url)
	if err != nil {
		t.Fatal(err)
	}
	suffix, _ := security.NewID()
	schema := "revoked_" + suffix
	if _, err = root.Exec(ctx, "CREATE SCHEMA "+schema); err != nil {
		root.Close()
		t.Fatal(err)
	}
	cfg, err := pgxpool.ParseConfig(url)
	if err != nil {
		t.Fatal(err)
	}
	cfg.ConnConfig.RuntimeParams["search_path"] = schema
	db, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close(); root.Exec(context.Background(), "DROP SCHEMA "+schema+" CASCADE"); root.Close() })
	s := &Store{DB: db}
	if err = s.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	return s, ctx
}
func TestPostgresRevocation5000AtomicPublicationAndRefresh(t *testing.T) {
	s, ctx := revocationStore(t)
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	keys := map[string]ed25519.PublicKey{"root": pub}
	publish := func() []byte {
		t.Helper()
		raw, err := s.Publish(ctx, "root", key, nil)
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	seed := func(from, to int) {
		t.Helper()
		_, err := s.DB.Exec(ctx, `INSERT INTO devices(id,user_id,name,public_key,revoked)
 SELECT lpad(i::text,32,'0'),'owner','club-'||i,'unique-test-key-'||i,true FROM generate_series($1::integer,$2::integer) i`, from, to)
		if err != nil {
			t.Fatal(err)
		}
	}
	check := func(raw []byte, n int) {
		t.Helper()
		cfg, err := security.ValidateConfig(keys, raw, time.Now())
		if err != nil || len(cfg.RevokedDevices) != n {
			t.Fatalf("revoked=%d want=%d error=%v", len(cfg.RevokedDevices), n, err)
		}
		for i, id := range cfg.RevokedDevices {
			if id != fmt.Sprintf("%032d", i+1) {
				t.Fatal("missing/out-of-order revocation", i, id)
			}
		}
	}
	seed(1, 1500)
	raw := publish()
	check(raw, 1500)
	seed(1501, 5000)
	if _, err := s.DB.Exec(ctx, "UPDATE devices SET revoked=false WHERE id=$1", fmt.Sprintf("%032d", 5000)); err != nil {
		t.Fatal(err)
	}
	raw = publish()
	check(raw, 4999)
	if err := s.Revoke(ctx, fmt.Sprintf("%032d", 5000)); err != nil {
		t.Fatal(err)
	}
	raw = publish()
	check(raw, 5000)
	if len(raw) <= security.MaxDocument {
		t.Fatal("test did not cross old document ceiling", len(raw))
	}
	// Follow normal HTTP serving, bounded download, signature/cache persistence,
	// and relay verifier update. All three used to have a 64 KiB bottleneck.
	api := &API{Store: s, Settings: Settings{KeyID: "root", SigningKey: key}, limit: newLimiter(time.Now())} // Same limiter as New; fixture serves only signed GET config.
	server := httptest.NewServer(api.Handler())
	defer server.Close()
	cache := security.NewConfigCache(keys, filepath.Join(t.TempDir(), "config.json"))
	c := &controlclient.Client{BaseURL: server.URL, Cache: cache}
	cfg, err := c.Config(ctx)
	if err != nil || len(cfg.RevokedDevices) != 5000 {
		t.Fatal("HTTP config", len(cfg.RevokedDevices), err)
	}
	loaded := security.NewConfigCache(keys, cache.Path)
	if err = loaded.Load(time.Now()); err != nil {
		t.Fatal("cache restore", err)
	}
	v := security.NewTicketVerifier(keys, "VPS-01")
	v.Update(keys, cfg.RevokedDevices)
	for _, i := range []int{1, 1001, 1500, 4999, 5000} {
		if !v.Revoked(fmt.Sprintf("%032d", i)) {
			t.Fatal("revoked ID absent in relay", i)
		}
	}
	device, _, _ := ed25519.GenerateKey(rand.Reader)
	now := time.Now()
	ticket, err := security.Sign("ticket", "root", key, security.Ticket{ID: "one-shot", DeviceID: fmt.Sprintf("%032d", 5000), DeviceKey: security.Fingerprint(device), RelayID: "VPS-01", IssuedAt: now, ExpiresAt: now.Add(time.Minute)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = v.Accept(ticket, device, now); err == nil {
		t.Fatal("revoked device beyond 1000 authenticated")
	}
	// Exercise heartbeat refresh of a >64 KiB config. The old generic parser
	// silently skipped this refresh, even when the stored config was valid.
	relayToken := strings.Repeat("a", 32)
	hash := sha256.Sum256([]byte(relayToken))
	if err = s.PutRelay(ctx, optimizer.RelayCandidate{ID: "VPS-01", Address: "127.0.0.1:4433"}); err != nil {
		t.Fatal(err)
	}
	if err = s.SetHeartbeatToken(ctx, "VPS-01", hash[:]); err != nil {
		t.Fatal(err)
	}
	cfg.GeneratedAt = time.Now().Add(-time.Minute)
	aged, err := security.Sign("config", "root", key, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.DB.Exec(ctx, "UPDATE config_versions SET document=$1 WHERE version=$2", aged, cfg.Version); err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequestWithContext(ctx, "POST", server.URL+"/api/v1/relays/heartbeat", bytes.NewBufferString(`{"id":"VPS-01","healthy":true,"load":0.2}`))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+relayToken)
	response, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatal("heartbeat refresh", response.StatusCode)
	}
	refreshed, err := c.Config(ctx)
	if err != nil || refreshed.Version <= cfg.Version || len(refreshed.RevokedDevices) != 5000 {
		t.Fatal("large config refresh skipped", refreshed.Version, err)
	}
	// Concurrent publications are serialized by version; every later config must
	// keep the complete revocation set across unrelated app/relay updates.
	if _, err = s.DB.Exec(ctx, "UPDATE relay_nodes SET healthy=false"); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	results := make(chan []byte, 3)
	errs := make(chan error, 3)
	for i := 0; i < 3; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			raw, err := s.Publish(ctx, "root", key, nil)
			if err != nil {
				errs <- err
			} else {
				results <- raw
			}
		}()
	}
	wg.Wait()
	close(results)
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
	var maxVersion uint64
	for raw := range results {
		check(raw, 5000)
		cfg, _ := security.ValidateConfig(keys, raw, time.Now())
		if cfg.Version > maxVersion {
			maxVersion = cfg.Version
		}
	}
	latest, err := s.LatestConfig(ctx)
	if err != nil {
		t.Fatal(err)
	}
	newest, err := security.ValidateConfig(keys, latest, time.Now())
	if err != nil || newest.Version != maxVersion {
		t.Fatal("version publication race", newest.Version, maxVersion, err)
	}
	before, err := s.LatestConfig(ctx)
	if err != nil {
		t.Fatal(err)
	}
	failPublish := func() {
		t.Helper()
		got, err := s.Publish(ctx, "root", key, nil)
		if err == nil || got != nil {
			t.Fatal("failed publication returned document", len(got), err)
		}
		after, e := s.LatestConfig(ctx)
		if e != nil || string(after) != string(before) {
			t.Fatal("publication not atomic", e)
		}
	}
	// A real DB query error must leave the previously published document intact.
	if _, err = s.DB.Exec(ctx, "ALTER TABLE devices RENAME TO devices_hidden"); err != nil {
		t.Fatal(err)
	}
	failPublish()
	if _, err = s.DB.Exec(ctx, "ALTER TABLE devices_hidden RENAME TO devices"); err != nil {
		t.Fatal(err)
	}
	// Failure after document insertion, at COMMIT, must roll it all back and
	// return nil (never a usable partially published signed configuration).
	_, err = s.DB.Exec(ctx, `CREATE FUNCTION reject_publish() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'injected commit failure'; END $$;
 CREATE CONSTRAINT TRIGGER reject_publish AFTER INSERT ON config_versions DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION reject_publish()`)
	if err != nil {
		t.Fatal(err)
	}
	failPublish()
	if _, err = s.DB.Exec(ctx, "DROP TRIGGER reject_publish ON config_versions"); err != nil {
		t.Fatal(err)
	}
	// Oversized complete lists fail explicitly, never publish a truncated suffix.
	seed(5001, 35000)
	failPublish()
	if _, err = s.DB.Exec(ctx, "DELETE FROM devices WHERE id>$1", fmt.Sprintf("%032d", 5000)); err != nil {
		t.Fatal(err)
	}
	check(publish(), 5000)
	t.Log("5000 complete revocations published/served/restored; >1000 rejected; DB/commit/size failures preserved last config")
}
