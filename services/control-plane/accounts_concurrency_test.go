package controlplane

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type loginMailerFunc func(context.Context, string, string, string) error

func (f loginMailerFunc) Send(ctx context.Context, to, subject, body string) error {
	return f(ctx, to, subject, body)
}

func loginStartResponse(a *API, email string) *httptest.ResponseRecorder {
	r := httptest.NewRequest("POST", "/api/v1/account/login/start", strings.NewReader(fmt.Sprintf(`{"email":%q}`, email)))
	r.RemoteAddr = "198.51.100.30:5000"
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Origin", testOrigin)
	w := httptest.NewRecorder()
	a.Handler().ServeHTTP(w, r)
	return w
}

func asyncLoginStart(a *API, email string) <-chan *httptest.ResponseRecorder {
	done := make(chan *httptest.ResponseRecorder, 1)
	go func() { done <- loginStartResponse(a, email) }()
	return done
}

func loginGate(t *testing.T) (<-chan struct{}, func()) {
	t.Helper()
	release := make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	t.Cleanup(unblock)
	return release, unblock
}

func waitLoginMailer(t *testing.T, entered <-chan struct{}) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	select {
	case <-entered:
	case <-ctx.Done():
		t.Fatal("login request did not reach the controlled mailer")
	}
}

// The observer is outside the pool: blocked workers cannot starve the lock
// barrier itself. Poll actual PostgreSQL waits, never sleep to assume overlap.
func accountLockObserver(t *testing.T, s *Store) *pgx.Conn {
	t.Helper()
	c, err := pgx.ConnectConfig(context.Background(), s.DB.Config().ConnConfig.Copy())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close(context.Background()) })
	return c
}

func waitAccountLocks(t *testing.T, c *pgx.Conn, patterns []string, count int, premature <-chan *httptest.ResponseRecorder) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	tick := time.NewTicker(5 * time.Millisecond)
	defer tick.Stop()
	for {
		// A barrier may itself hold a transaction/row lock. PostgreSQL caches
		// activity snapshots within that transaction unless explicitly cleared.
		if _, err := c.Exec(ctx, "SELECT pg_stat_clear_snapshot()"); err != nil {
			t.Fatal("refresh PostgreSQL activity snapshot", err)
		}
		var waiting int
		err := c.QueryRow(ctx, `SELECT count(*) FROM pg_stat_activity
WHERE datname=current_database() AND pid<>pg_backend_pid() AND wait_event_type='Lock' AND query LIKE ANY($1::text[])`, patterns).Scan(&waiting)
		if err != nil {
			t.Fatal("PostgreSQL lock barrier", err)
		}
		if waiting >= count {
			return
		}
		select {
		case response := <-premature:
			t.Fatal("resend acknowledged an unfinished delivery", response.Code)
		case <-ctx.Done():
			t.Fatal("PostgreSQL lock barrier not reached", waiting, count)
		case <-tick.C:
		}
	}
}

func TestAccountLoginReservationConcurrentResends(t *testing.T) {
	for _, existing := range []bool{false, true} {
		t.Run(fmt.Sprint("existing=", existing), func(t *testing.T) {
			s := codeStore(t)
			ctx := context.Background()
			now := time.Now()
			const email = "concurrent@example.com"
			observer := accountLockObserver(t, s)
			if existing {
				if _, _, err := s.StartLogin(ctx, email, now.Add(-2*LoginResendInterval)); err != nil {
					t.Fatal(err)
				}
			}
			barrier, err := observer.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer barrier.Rollback(ctx)
			if existing {
				_, err = barrier.Exec(ctx, "SELECT email FROM login_codes WHERE email=$1 FOR UPDATE", email)
			} else {
				// Also cover racing first-time inserts, not just row replacement.
				_, err = barrier.Exec(ctx, "LOCK TABLE login_codes IN SHARE MODE")
			}
			if err != nil {
				t.Fatal(err)
			}
			const parallel = 4
			type result struct {
				code string
				sent bool
				err  error
			}
			results := make(chan result, parallel)
			for i := 0; i < parallel; i++ {
				go func() {
					code, sent, err := s.StartLogin(ctx, email, now)
					results <- result{code, sent, err}
				}()
			}
			waitAccountLocks(t, observer, []string{"INSERT INTO login_codes%"}, parallel, nil)
			if err = barrier.Commit(ctx); err != nil {
				t.Fatal(err)
			}
			winners, winner := 0, ""
			for i := 0; i < parallel; i++ {
				r := <-results
				if r.err != nil {
					t.Fatal(r.err)
				}
				if r.sent {
					winners++
					winner = r.code
				} else if r.code != "" {
					t.Fatal("throttled caller received a code")
				}
			}
			if winners != 1 {
				t.Fatal("concurrent reservations", winners)
			}
			if _, _, err := s.FinishLogin(ctx, email, winner, now); err != nil {
				t.Fatal("winning code not usable", err)
			}
		})
	}
}

func TestAccountSMTPFailureRollsBackAndRetryReallySends(t *testing.T) {
	a, s, _ := accountAPI(t, false)
	ctx := context.Background()
	const email = "retry@example.com"
	old, _, err := s.StartLogin(ctx, email, time.Now().Add(-2*LoginResendInterval))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.DB.Exec(ctx, "UPDATE login_codes SET attempts=3 WHERE email=$1", email); err != nil {
		t.Fatal(err)
	}
	var calls atomic.Int32
	var delivered string
	a.Settings.Mailer = loginMailerFunc(func(context.Context, string, string, string) error {
		calls.Add(1)
		return errors.New("fixture SMTP failure")
	})
	if w := loginStartResponse(a, email); w.Code != 503 || !strings.Contains(w.Body.String(), "MAIL_UNAVAILABLE") {
		t.Fatal("SMTP failure reported as success", w.Code)
	}
	var hash []byte
	var attempts int
	if err = s.DB.QueryRow(ctx, "SELECT code_hash,attempts FROM login_codes WHERE email=$1", email).Scan(&hash, &attempts); err != nil || !bytes.Equal(hash, loginHash(email, old)) || attempts != 3 {
		t.Fatal("failed resend corrupted previous code/attempts", err, attempts)
	}
	a.Settings.Mailer = loginMailerFunc(func(_ context.Context, _, subject, _ string) error {
		calls.Add(1)
		delivered = strings.TrimPrefix(subject, "Код для входа: ")
		return nil
	})
	for i := 0; i < 2; i++ {
		if w := loginStartResponse(a, email); w.Code != 200 {
			t.Fatal("retry failed", w.Code)
		}
	}
	if calls.Load() != 2 || delivered == "" {
		t.Fatal("retry was not delivered exactly once", calls.Load())
	}
	if _, _, err = s.FinishLogin(ctx, email, delivered, time.Now()); err != nil {
		t.Fatal("delivered retry code invalid", err)
	}
}

func TestAccountConcurrentResendWaitsForSMTPOutcome(t *testing.T) {
	for _, failure := range []bool{false, true} {
		t.Run(fmt.Sprint("failure=", failure), func(t *testing.T) {
			a, s, _ := accountAPI(t, false)
			release, unblock := loginGate(t)
			entered := make(chan struct{})
			var calls atomic.Int32
			a.Settings.Mailer = loginMailerFunc(func(ctx context.Context, _, _, _ string) error {
				if calls.Add(1) == 1 {
					close(entered)
					select {
					case <-release:
					case <-ctx.Done():
						return ctx.Err()
					}
					if failure {
						return errors.New("fixture SMTP failure")
					}
				}
				return nil
			})
			other, err := New(s, a.Settings)
			if err != nil {
				t.Fatal(err)
			}
			first := asyncLoginStart(a, "pending@example.com")
			waitLoginMailer(t, entered)
			second := asyncLoginStart(other, "pending@example.com")
			waitAccountLocks(t, accountLockObserver(t, s), []string{"INSERT INTO login_codes%"}, 1, second)
			unblock()
			wantFirst, wantCalls := 200, int32(1)
			if failure {
				wantFirst, wantCalls = 503, 2
			}
			if w := <-first; w.Code != wantFirst {
				t.Fatal("first delivery status", w.Code)
			}
			if w := <-second; w.Code != 200 || calls.Load() != wantCalls {
				t.Fatal("concurrent resend did not reflect delivery outcome", w.Code, calls.Load())
			}
		})
	}
}

func TestAccountLoginDatabaseFailuresCannotAcknowledgeDelivery(t *testing.T) {
	for _, commitFailure := range []bool{false, true} {
		t.Run(fmt.Sprint("commit=", commitFailure), func(t *testing.T) {
			a, s, _ := accountAPI(t, false)
			var calls atomic.Int32
			a.Settings.Mailer = loginMailerFunc(func(context.Context, string, string, string) error { calls.Add(1); return nil })
			ctx := context.Background()
			statement := `CREATE FUNCTION reject_login_write() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'fixture database failure'; END $$; `
			if commitFailure {
				statement += `CREATE CONSTRAINT TRIGGER reject_login_write AFTER INSERT OR UPDATE ON login_codes DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION reject_login_write()`
			} else {
				statement += `CREATE TRIGGER reject_login_write BEFORE INSERT OR UPDATE ON login_codes FOR EACH ROW EXECUTE FUNCTION reject_login_write()`
			}
			if _, err := s.DB.Exec(ctx, statement); err != nil {
				t.Fatal(err)
			}
			if w := loginStartResponse(a, "db-failure@example.com"); w.Code != 503 || !strings.Contains(w.Body.String(), "ACCOUNT_UNAVAILABLE") {
				t.Fatal("database failure acknowledged", w.Code)
			}
			wantCalls := int32(0)
			if commitFailure {
				wantCalls = 1
			}
			var rows int
			if err := s.DB.QueryRow(ctx, "SELECT count(*) FROM login_codes").Scan(&rows); err != nil || rows != 0 || calls.Load() != wantCalls {
				t.Fatal("failed reservation retained or invalid delivery", err, rows, calls.Load())
			}
			if _, err := s.DB.Exec(ctx, "DROP TRIGGER reject_login_write ON login_codes"); err != nil {
				t.Fatal(err)
			}
			if w := loginStartResponse(a, "db-failure@example.com"); w.Code != 200 || calls.Load() != wantCalls+1 {
				t.Fatal("database recovery did not permit real delivery", w.Code, calls.Load())
			}
		})
	}
}

func TestAccountCanceledSMTPReleasesReservation(t *testing.T) {
	a, s, _ := accountAPI(t, false)
	entered := make(chan struct{})
	a.Settings.Mailer = loginMailerFunc(func(ctx context.Context, _, _, _ string) error {
		close(entered)
		<-ctx.Done()
		return ctx.Err()
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	r := httptest.NewRequest("POST", "/api/v1/account/login/start", strings.NewReader(`{"email":"cancel@example.com"}`)).WithContext(ctx)
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Origin", testOrigin)
	w := httptest.NewRecorder()
	done := make(chan struct{})
	go func() { a.Handler().ServeHTTP(w, r); close(done) }()
	waitLoginMailer(t, entered)
	cancel()
	<-done
	if w.Code != 503 {
		t.Fatal("canceled SMTP reported success", w.Code)
	}
	var rows int
	if err := s.DB.QueryRow(context.Background(), "SELECT count(*) FROM login_codes").Scan(&rows); err != nil || rows != 0 {
		t.Fatal("canceled SMTP retained its reservation", err, rows)
	}
	a.Settings.Mailer = loginMailerFunc(func(context.Context, string, string, string) error { return nil })
	if retry := loginStartResponse(a, "cancel@example.com"); retry.Code != 200 {
		t.Fatal("canceled request leaked a transaction or delivery slot", retry.Code)
	}
}

func TestAccountSlowSMTPLeavesDatabaseCapacity(t *testing.T) {
	a, s, _ := accountAPI(t, false)
	release, unblock := loginGate(t)
	entered := make(chan struct{}, 2)
	var calls atomic.Int32
	a.Settings.Mailer = loginMailerFunc(func(ctx context.Context, _, _, _ string) error {
		calls.Add(1)
		entered <- struct{}{}
		select {
		case <-release:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	})
	first := asyncLoginStart(a, "one@example.com")
	second := asyncLoginStart(a, "two@example.com")
	waitLoginMailer(t, entered)
	waitLoginMailer(t, entered)
	if w := loginStartResponse(a, "three@example.com"); w.Code != 503 || calls.Load() != 2 {
		t.Fatal("unbounded SMTP transactions", w.Code, calls.Load())
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := s.DB.Ping(ctx); err != nil {
		t.Fatal("SMTP exhausted the database pool", err)
	}
	unblock()
	if (<-first).Code != 200 || (<-second).Code != 200 {
		t.Fatal("bounded SMTP requests failed")
	}
}

func TestAccountSubscriptionLimitConcurrentCreation(t *testing.T) {
	for _, isolation := range []string{"read committed", "repeatable read"} {
		t.Run(isolation, func(t *testing.T) { accountSubscriptionLimitConcurrentCreation(t, isolation) })
	}
}

func accountSubscriptionLimitConcurrentCreation(t *testing.T, isolation string) {
	a, s, m := accountAPI(t, false)
	cfg := s.DB.Config()
	cfg.ConnConfig.RuntimeParams["default_transaction_isolation"] = isolation
	pool, err := pgxpool.NewWithConfig(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	s = &Store{pool}
	a.Store = s
	c := &call{api: a}
	login(t, c, m, "limit@example.com")
	ctx := context.Background()
	account, err := s.SessionAccount(ctx, c.cookie, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	p := a.Settings.Plans[0]
	for i := 0; i < 19; i++ {
		if _, err = s.CreateSubscription(ctx, account, p, 1); err != nil {
			t.Fatal(err)
		}
	}
	observer := accountLockObserver(t, s)
	barrier, err := observer.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer barrier.Rollback(ctx)
	if _, err = barrier.Exec(ctx, "SELECT id FROM accounts WHERE id=$1 FOR UPDATE", account.ID); err != nil {
		t.Fatal(err)
	}
	const parallel = 4
	results := make(chan error, parallel)
	for i := 0; i < parallel; i++ {
		go func() { _, err := s.CreateSubscription(ctx, account, p, 1); results <- err }()
	}
	waitAccountLocks(t, observer, []string{"SELECT id,account_type FROM accounts%FOR NO KEY UPDATE", "INSERT INTO subscriptions%"}, parallel, nil)
	if err = barrier.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	created := 0
	for i := 0; i < parallel; i++ {
		err := <-results
		if err == nil {
			created++
		} else if err.Error() != "SUBSCRIPTION_LIMIT" {
			t.Fatal("unexpected concurrency error", err)
		}
	}
	var subscriptions, codes int
	if err = s.DB.QueryRow(ctx, "SELECT count(*) FROM subscriptions WHERE account_id=$1", account.ID).Scan(&subscriptions); err != nil {
		t.Fatal(err)
	}
	if err = s.DB.QueryRow(ctx, "SELECT count(*) FROM activation_codes WHERE subscription_id IS NOT NULL").Scan(&codes); err != nil || subscriptions != 20 || codes != 20 || created != 1 {
		t.Fatal("subscription limit or atomic code creation", err, subscriptions, codes, created)
	}
	if status, _ := c.do(t, "POST", "/api/v1/account/subscriptions", map[string]any{"plan_id": p.ID, "seats": 1}); status != 400 {
		t.Fatal("API did not retain subscription limit", status)
	}
}

func TestAccountLogoutDatabaseFailureAndIdempotentRetry(t *testing.T) {
	a, s, m := accountAPI(t, false)
	c := &call{api: a}
	login(t, c, m, "logout@example.com")
	token := c.cookie
	ctx := context.Background()
	_, err := s.DB.Exec(ctx, `CREATE FUNCTION reject_session_delete() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'fixture database failure'; END $$;
CREATE TRIGGER reject_session_delete BEFORE DELETE ON account_sessions FOR EACH ROW EXECUTE FUNCTION reject_session_delete()`)
	if err != nil {
		t.Fatal(err)
	}
	if status, out := c.do(t, "POST", "/api/v1/account/logout", nil); status != 503 || out["error"] != "ACCOUNT_UNAVAILABLE" || c.cookie != token {
		t.Fatal("logout falsely succeeded or lost retry cookie", status)
	}
	if _, err = s.SessionAccount(ctx, token, time.Now()); err != nil {
		t.Fatal("failure fixture did not retain server session", err)
	}
	if _, err = s.DB.Exec(ctx, "DROP TRIGGER reject_session_delete ON account_sessions"); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		c.cookie = token // Repeat the same logout request, including its old cookie.
		if status, _ := c.do(t, "POST", "/api/v1/account/logout", nil); status != 200 || c.cookie != "" {
			t.Fatal("logout retry was not idempotent", status)
		}
	}
	if _, err = s.SessionAccount(ctx, token, time.Now()); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatal("server session survived successful logout", err)
	}
}

func TestAccountSubscriptionDatabaseFailureRollsBackAndReleasesLock(t *testing.T) {
	a, s, m := accountAPI(t, false)
	c := &call{api: a}
	login(t, c, m, "rollback@example.com")
	ctx := context.Background()
	account, err := s.SessionAccount(ctx, c.cookie, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	// Fail after the subscription INSERT, so both the row and account lock
	// must roll back before another attempt can succeed.
	_, err = s.DB.Exec(ctx, `CREATE FUNCTION reject_subscription_code() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'fixture database failure'; END $$;
CREATE TRIGGER reject_subscription_code BEFORE INSERT ON activation_codes FOR EACH ROW EXECUTE FUNCTION reject_subscription_code()`)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.CreateSubscription(ctx, account, a.Settings.Plans[0], 1); err == nil {
		t.Fatal("subscription database failure acknowledged")
	}
	var subscriptions, codes int
	if err = s.DB.QueryRow(ctx, "SELECT (SELECT count(*) FROM subscriptions), (SELECT count(*) FROM activation_codes)").Scan(&subscriptions, &codes); err != nil || subscriptions != 0 || codes != 0 {
		t.Fatal("partial subscription committed", err, subscriptions, codes)
	}
	if _, err = s.DB.Exec(ctx, "DROP TRIGGER reject_subscription_code ON activation_codes"); err != nil {
		t.Fatal(err)
	}
	retry, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	if _, err = s.CreateSubscription(retry, account, a.Settings.Plans[0], 1); err != nil {
		t.Fatal("failed transaction retained account lock or prevented retry", err)
	}
}
