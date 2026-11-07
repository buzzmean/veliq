package support

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

func testStore(t *testing.T) *Store {
	t.Helper()
	dsn := os.Getenv("VELIQ_SUPPORT_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("isolated PostgreSQL not configured")
	}
	ctx := context.Background()
	admin, e := pgxpool.New(ctx, dsn)
	if e != nil {
		t.Fatal("test database unavailable")
	}
	schemaName := "test_support_" + randomID()[:16]
	if _, e = admin.Exec(ctx, "CREATE SCHEMA "+schemaName); e != nil {
		t.Fatal(e)
	}
	cfg, e := pgxpool.ParseConfig(dsn)
	if e != nil {
		t.Fatal(e)
	}
	cfg.ConnConfig.RuntimeParams["search_path"] = schemaName
	cfg.MaxConns = 20
	db, e := pgxpool.NewWithConfig(ctx, cfg)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { db.Close(); _, _ = admin.Exec(ctx, "DROP SCHEMA "+schemaName+" CASCADE"); admin.Close() })
	s := &Store{DB: db}
	if e = s.Migrate(ctx); e != nil {
		t.Fatal(e)
	}
	if e = s.Migrate(ctx); e != nil {
		t.Fatal("repeat migration", e)
	}
	return s
}
func visitor(t *testing.T, s *Store) string {
	t.Helper()
	token, e := s.Session(context.Background(), randomID())
	if e != nil {
		t.Fatal(e)
	}
	return token
}
func newTicket(t *testing.T, s *Store, token string) string {
	t.Helper()
	id, e := s.Mutate(context.Background(), token, "fixture", "message", Mutation{Key: randomID(), Body: "Не подключается CS2"})
	if e != nil {
		t.Fatal(e)
	}
	return id
}
func bot(s *Store) *Telegram {
	return &Telegram{Store: s, ChatID: -100123, Operators: map[int64]bool{11: true, 22: true}, Token: "123:fixture-only"}
}
func mapMessage(t *testing.T, s *Store, ticket string, id int64) {
	t.Helper()
	_, e := s.DB.Exec(context.Background(), `INSERT INTO support_telegram_messages VALUES(-100123,$1,$2)`, id, ticket)
	if e != nil {
		t.Fatal(e)
	}
}
func callback(id, operator, msg int64, data string) TGUpdate {
	return TGUpdate{ID: id, Callback: &TGCallback{ID: fmt.Sprint(id), From: TGUser{ID: operator}, Message: &TGMessage{ID: msg, Chat: TGChat{ID: -100123}}, Data: data}}
}
func reply(id, operator, msg int64, text string) TGUpdate {
	return TGUpdate{ID: id, Message: &TGMessage{ID: id, From: TGUser{ID: operator}, Chat: TGChat{ID: -100123}, Reply: &TGMessage{ID: msg}, Text: text}}
}
func state(t *testing.T, s *Store, token string) State {
	t.Helper()
	st, e := s.State(context.Background(), token, "", 0)
	if e != nil {
		t.Fatal(e)
	}
	return st
}
func TestSupportLifecycleAndPersistence(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	token := visitor(t, s)
	ticket := newTicket(t, s, token)
	mapMessage(t, s, ticket, 10)
	tg := bot(s)
	if _, e := tg.Process(ctx, callback(1, 11, 10, "claim")); e != nil {
		t.Fatal(e)
	}
	u := reply(2, 11, 10, "Проверьте локальный режим.")
	if _, e := tg.Process(ctx, u); e != nil {
		t.Fatal(e)
	}
	if _, e := tg.Process(ctx, u); e != nil {
		t.Fatal(e)
	}
	// A fresh store instance restores authoritative state; no process-local ticket cache.
	st := state(t, &Store{DB: s.DB}, token)
	if st.Ticket.Status != "assigned" || len(st.Messages) != 3 {
		t.Fatalf("bad state: %+v", st)
	}
	rev := st.Ticket.Revision
	if _, e := s.Mutate(ctx, token, "p", "resolve", Mutation{Key: randomID(), Ticket: ticket, Revision: rev - 1}); !errors.Is(e, ErrConflict) {
		t.Fatal("stale close accepted", e)
	}
	m := Mutation{Key: randomID(), Ticket: ticket, Revision: rev}
	if _, e := s.Mutate(ctx, token, "p", "resolve", m); e != nil {
		t.Fatal(e)
	}
	if _, e := s.Mutate(ctx, token, "p", "resolve", m); e != nil {
		t.Fatal(e)
	}
	st = state(t, s, token)
	if st.Ticket.Status != "resolved" {
		t.Fatal("not resolved")
	}
	answer, e := tg.Process(ctx, reply(3, 11, 10, "late"))
	if e != nil || !strings.Contains(answer, "не отправлен") {
		t.Fatal(answer, e)
	}
	if len(state(t, s, token).Messages) != 4 {
		t.Fatal("late reply persisted")
	}
	if newID := newTicket(t, s, token); newID == ticket {
		t.Fatal("new issue reused closed ticket")
	}
}
func TestSupportConcurrentClaimAndCrossVisitorIsolation(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	token := visitor(t, s)
	ticket := newTicket(t, s, token)
	mapMessage(t, s, ticket, 10)
	tg := bot(s)
	var wg sync.WaitGroup
	errs := make(chan error, 2)
	for i, op := range []int64{11, 22} {
		wg.Add(1)
		go func(id, operator int64) {
			defer wg.Done()
			_, e := tg.Process(ctx, callback(id, operator, 10, "claim"))
			errs <- e
		}(int64(i+1), op)
	}
	wg.Wait()
	close(errs)
	for e := range errs {
		if e != nil {
			t.Fatal(e)
		}
	}
	var assigned int64
	s.DB.QueryRow(ctx, `SELECT operator_id FROM support_tickets WHERE id=$1`, ticket).Scan(&assigned)
	if assigned != 11 && assigned != 22 {
		t.Fatal("no winner")
	}
	loser := int64(33) - assigned
	a, e := tg.Process(ctx, reply(3, loser, 10, "foreign"))
	if e != nil || !strings.Contains(a, "не отправлен") {
		t.Fatal(a, e)
	}
	if len(state(t, s, token).Messages) != 2 {
		t.Fatal("loser replied")
	}
	other := visitor(t, s)
	st, e := s.State(ctx, other, ticket, 0)
	if e != nil || st.Ticket != nil {
		t.Fatal("cross visitor read")
	}
	_, e = s.Mutate(ctx, other, "p", "message", Mutation{Key: randomID(), Ticket: ticket, Body: "x"})
	if !errors.Is(e, ErrUnauthorized) {
		t.Fatal("cross visitor mutation", e)
	}
	if _, e = tg.Process(ctx, callback(4, assigned, 10, "release")); e != nil {
		t.Fatal(e)
	}
	if _, e = tg.Process(ctx, callback(5, loser, 10, "claim")); e != nil {
		t.Fatal(e)
	}
	if _, e = tg.Process(ctx, reply(6, loser, 10, "Теперь я помогу")); e != nil {
		t.Fatal(e)
	}
	if state(t, s, token).Messages[4].Role != "operator" {
		t.Fatal("handover failed")
	}
}
func TestSupportRejectUnauthorizedTelegram(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	token := visitor(t, s)
	ticket := newTicket(t, s, token)
	mapMessage(t, s, ticket, 10)
	tg := bot(s)
	cases := []TGUpdate{callback(1, 99, 10, "claim"), callback(2, 11, 999, "claim"), callback(3, 11, 10, "claim"), callback(4, 11, 10, "claim")}
	cases[2].Callback.Message.Chat.ID = -999
	cases[3].Callback.From.Bot = true
	for _, u := range cases {
		if _, e := tg.Process(ctx, u); e != nil {
			t.Fatal(e)
		}
	}
	if state(t, s, token).Ticket.Status != "queued" {
		t.Fatal("unauthorized claim")
	}
	_, _ = tg.Process(ctx, callback(5, 11, 10, "claim"))
	u := reply(6, 11, 10, "anonymous")
	u.Message.SenderChat = &TGChat{ID: -100123}
	_, _ = tg.Process(ctx, u)
	if len(state(t, s, token).Messages) != 2 {
		t.Fatal("anonymous admin replied")
	}
}
func TestSupportIdempotencyLimitsAndHistory(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	token := visitor(t, s)
	m := Mutation{Key: randomID(), Body: "hello"}
	id, e := s.Mutate(ctx, token, "peer", "message", m)
	if e != nil {
		t.Fatal(e)
	}
	id2, e := s.Mutate(ctx, token, "peer", "message", m)
	if e != nil || id != id2 {
		t.Fatal("retry", e)
	}
	m.Body = "changed"
	if _, e = s.Mutate(ctx, token, "peer", "message", m); !errors.Is(e, ErrConflict) {
		t.Fatal("key changed content")
	}
	for i := 0; i < 19; i++ {
		if _, e = s.Mutate(ctx, token, "peer", "message", Mutation{Key: randomID(), Ticket: id, Body: "test"}); e != nil {
			t.Fatal(e)
		}
	}
	if _, e = s.Mutate(ctx, token, "peer", "message", Mutation{Key: randomID(), Ticket: id, Body: "over limit"}); !errors.Is(e, ErrLimit) {
		t.Fatal("no rate limit", e)
	}
	_, e = s.DB.Exec(ctx, `INSERT INTO support_messages(ticket,role,body) SELECT $1,'system','history' FROM generate_series(1,120)`, id)
	if e != nil {
		t.Fatal(e)
	}
	st := state(t, s, token)
	if len(st.Messages) != 100 || !st.More {
		t.Fatal("not paginated")
	}
	old, e := s.State(ctx, token, id, st.Messages[0].ID)
	if e != nil || len(old.Messages) != 40 || old.More {
		t.Fatal("older page", e)
	}
}
func TestSupportTelegramOutageDurableOutbox(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	token := visitor(t, s)
	ticket := newTicket(t, s, token)
	tg := bot(s)
	var failed atomic.Bool
	failed.Store(true)
	var received atomic.Int32
	fake := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if failed.Load() {
			w.WriteHeader(503)
			return
		}
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		if body["parse_mode"] != nil {
			t.Error("user text must not become markup")
		}
		received.Add(1)
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "result": TGMessage{ID: 101, Chat: TGChat{ID: -100123}}})
	}))
	defer fake.Close()
	tg.apiURL = fake.URL
	if _, e := tg.DeliverOne(ctx); e == nil {
		t.Fatal("outage unobserved")
	}
	var n int
	s.DB.QueryRow(ctx, `SELECT count(*) FROM support_outbox WHERE sent_at IS NULL AND attempts=1`).Scan(&n)
	if n != 1 {
		t.Fatal("lost outbox")
	}
	failed.Store(false)
	s.DB.Exec(ctx, `UPDATE support_outbox SET next_at=now()`)
	if sent, e := tg.DeliverOne(ctx); e != nil || !sent {
		t.Fatal("retry", e)
	}
	if _, e := tg.DeliverOne(ctx); e != nil {
		t.Fatal(e)
	}
	var mapped string
	s.DB.QueryRow(ctx, `SELECT ticket FROM support_telegram_messages WHERE message_id=101`).Scan(&mapped)
	if mapped != ticket || received.Load() != 1 {
		t.Fatal("mapping/retry duplicate")
	}
}
func TestResolutionNoticeSurvivesDeliveryFailure(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	token := visitor(t, s)
	ticket := newTicket(t, s, token)
	tg := bot(s)
	var failClose atomic.Bool
	failClose.Store(true)
	var notices atomic.Int64
	var messageID atomic.Int64
	fake := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var payload map[string]any
		if e := json.NewDecoder(r.Body).Decode(&payload); e != nil {
			t.Error(e)
			w.WriteHeader(400)
			return
		}
		body, _ := payload["text"].(string)
		if strings.Contains(body, "Тикет закрыт.") {
			if failClose.Load() {
				w.WriteHeader(503)
				return
			}
			if !strings.HasPrefix(body, "VELIQ · #"+ticket[:12]+"\n") ||
				!strings.Contains(body, "Пользователь подтвердил решение.") || payload["reply_markup"] != nil {
				t.Error("resolution notice must identify the ticket and have no active controls")
			}
			notices.Add(1)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "result": TGMessage{ID: messageID.Add(1), Chat: TGChat{ID: tg.ChatID}}})
	}))
	defer fake.Close()
	tg.apiURL = fake.URL
	if sent, e := tg.DeliverOne(ctx); e != nil || !sent {
		t.Fatal("initial message", sent, e)
	}
	m := Mutation{Key: randomID(), Ticket: ticket, Revision: state(t, s, token).Ticket.Revision}
	for range 2 { // Same HTTP operation retried after an ambiguous response.
		if _, e := s.Mutate(ctx, token, "fixture", "resolve", m); e != nil {
			t.Fatal(e)
		}
	}
	var count int
	if e := s.DB.QueryRow(ctx, `SELECT count(*) FROM support_outbox WHERE ticket=$1 AND sent_at IS NULL`, ticket).Scan(&count); e != nil || count != 1 {
		t.Fatal("closure must enqueue exactly one notice", count, e)
	}
	if _, e := tg.DeliverOne(ctx); e == nil {
		t.Fatal("delivery failure must be retained for retry")
	}
	// Recreate the worker with the same DB, without relying on process memory.
	tg.Store = &Store{DB: s.DB}
	failClose.Store(false)
	if _, e := s.DB.Exec(ctx, `UPDATE support_outbox SET next_at=now() WHERE ticket=$1`, ticket); e != nil {
		t.Fatal(e)
	}
	if sent, e := tg.DeliverOne(ctx); e != nil || !sent {
		t.Fatal("closure retry", sent, e)
	}
	if sent, e := tg.DeliverOne(ctx); e != nil || sent || notices.Load() != 1 {
		t.Fatal("unexpected duplicate notice", sent, notices.Load(), e)
	}
}

func TestSupportHTTPBoundaries(t *testing.T) {
	s := testStore(t)
	token := visitor(t, s)
	h := &Server{Store: s, Origin: "https://veliq.test", Enabled: true}
	request := func(path, origin, body, cookie string) *httptest.ResponseRecorder {
		r := httptest.NewRequest("POST", "https://veliq.test/api/v1/account/support/"+path, strings.NewReader(body))
		r.Header.Set("Origin", origin)
		r.Header.Set("Content-Type", "application/json")
		r.RemoteAddr = "127.0.0.1:9999"
		r.Header.Set("X-Support-Context", hash("guest-context\x00"+cookie))
		if cookie != "" {
			r.AddCookie(&http.Cookie{Name: cookieName, Value: cookie})
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	if w := request("session", "https://attacker.test", "{}", ""); w.Code != 403 {
		t.Fatal(w.Code)
	}
	if w := request("session", h.Origin, "{}", ""); w.Code != 200 || !strings.Contains(w.Header().Get("Set-Cookie"), "HttpOnly") || !strings.Contains(w.Header().Get("Set-Cookie"), "Secure") {
		t.Fatal("cookie boundary")
	}
	if w := request("message", h.Origin, `{"body":"x","key":"`+randomID()+`"}`, ""); w.Code != 401 {
		t.Fatal(w.Code)
	}
	if w := request("message", h.Origin, `{"body":"x","key":"`+randomID()+`","extra":true}`, token); w.Code != 400 {
		t.Fatal(w.Code)
	}
	if w := request("message", h.Origin, `{"body":"`+strings.Repeat("a", 2001)+`","key":"`+randomID()+`"}`, token); w.Code != 400 {
		t.Fatal(w.Code)
	}
	h.Enabled = false
	if w := request("message", h.Origin, `{}`, token); w.Code != 503 {
		t.Fatal(w.Code)
	}
	if w := request("forget", h.Origin, `{}`, token); w.Code != 200 || !strings.Contains(w.Header().Get("Set-Cookie"), "Max-Age=0") {
		t.Fatal("forget", w.Code)
	}
	if s.ValidSession(context.Background(), token) {
		t.Fatal("forgotten token still valid")
	}
}
func TestSupportBrowser(t *testing.T) {
	if os.Getenv("VELIQ_SUPPORT_BROWSER") != "1" {
		t.Skip("browser fixture opt-in")
	}
	s := testStore(t)
	tg := bot(s)
	var seq atomic.Int64
	seq.Store(1000)
	fake := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "result": TGMessage{ID: seq.Add(1), Chat: TGChat{ID: -100123}}})
	}))
	defer fake.Close()
	tg.apiURL = fake.URL
	root, e := filepath.Abs("../../website")
	if e != nil {
		t.Fatal(e)
	}
	h := &Server{Store: s, Enabled: true}
	var authMu sync.Mutex
	sessions := map[string]string{}
	h.Accounts = verifierFunc(func(_ context.Context, token string) (string, error) {
		authMu.Lock()
		defer authMu.Unlock()
		if email := sessions[token]; email != "" {
			return hash("fixture-account:" + email)[:32], nil
		}
		return "", ErrUnauthorized
	})
	mux := http.NewServeMux()
	mux.Handle("/api/v1/account/support/", h)
	mux.HandleFunc("/api/v1/account/login/verify", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" || r.Header.Get("Origin") != h.Origin {
			w.WriteHeader(403)
			return
		}
		var q struct {
			Email string `json:"email"`
		}
		if json.NewDecoder(r.Body).Decode(&q) != nil || !strings.HasSuffix(q.Email, "@example.test") {
			w.WriteHeader(400)
			return
		}
		http.SetCookie(w, &http.Cookie{Name: cookieName, Path: "/", MaxAge: -1, Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode})
		token := randomID()[:43]
		authMu.Lock()
		sessions[token] = q.Email
		authMu.Unlock()
		http.SetCookie(w, &http.Cookie{Name: accountCookie, Value: token, Path: "/api/v1/account", HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode})
		_, _ = w.Write([]byte(`{"ok":true}`))
	})
	mux.HandleFunc("/api/v1/account/logout", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" || r.Header.Get("Origin") != h.Origin {
			w.WriteHeader(403)
			return
		}
		http.SetCookie(w, &http.Cookie{Name: cookieName, Path: "/", MaxAge: -1, Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode})
		if c, e := r.Cookie(accountCookie); e == nil {
			authMu.Lock()
			delete(sessions, c.Value)
			authMu.Unlock()
		}
		http.SetCookie(w, &http.Cookie{Name: accountCookie, Path: "/api/v1/account", MaxAge: -1, HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode})
		_, _ = w.Write([]byte(`{"ok":true}`))
	})
	mux.Handle("/", http.FileServer(http.Dir(root)))
	fixtureKey := randomID()
	mux.HandleFunc("/_fixture/reply", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Fixture") != fixtureKey {
			w.WriteHeader(403)
			return
		}
		ctx := r.Context()
		sent, e := tg.DeliverOne(ctx)
		if e != nil || !sent {
			w.WriteHeader(500)
			return
		}
		var msg int64
		s.DB.QueryRow(ctx, `SELECT max(message_id) FROM support_telegram_messages`).Scan(&msg)
		if _, e = tg.Process(ctx, callback(seq.Add(1), 11, msg, "claim")); e != nil {
			w.WriteHeader(500)
			return
		}
		if _, e = tg.Process(ctx, reply(seq.Add(1), 11, msg, "Ответ специалиста <script>alert(1)</script>")); e != nil {
			w.WriteHeader(500)
			return
		}
		w.WriteHeader(204)
	})
	server := httptest.NewUnstartedServer(mux)
	h.Origin = "http://" + server.Listener.Addr().String()
	server.Start()
	defer server.Close()
	cmd := exec.Command("python3", "../../tests/frontend/support_chat_smoke.py", "--origin", server.URL)
	cmd.Env = append(os.Environ(), "VELIQ_SUPPORT_FIXTURE_KEY="+fixtureKey)
	out, e := cmd.CombinedOutput()
	if e != nil {
		t.Fatalf("browser: %v\n%s", e, out)
	}
	t.Log(string(bytes.TrimSpace(out)))
}

func TestSupportMigrationRefusesControlPlane(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	if _, e := s.DB.Exec(ctx, `CREATE TABLE subscriptions(id text)`); e != nil {
		t.Fatal(e)
	}
	if e := s.Migrate(ctx); e == nil || e.Error() != "support_requires_separate_database" {
		t.Fatal("wrong database accepted", e)
	}
}
func TestSupportRetention(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	token := visitor(t, s)
	ticket := newTicket(t, s, token)
	mapMessage(t, s, ticket, 10)
	if _, e := s.DB.Exec(ctx, `UPDATE support_tickets SET updated_at=now()-interval '91 days' WHERE id=$1`, ticket); e != nil {
		t.Fatal(e)
	}
	if e := s.Prune(ctx); e != nil {
		t.Fatal(e)
	}
	if state(t, s, token).Ticket != nil {
		t.Fatal("retained expired ticket")
	}
	for _, table := range []string{"support_messages", "support_outbox", "support_telegram_messages"} {
		var n int
		if e := s.DB.QueryRow(ctx, "SELECT count(*) FROM "+table).Scan(&n); e != nil || n != 0 {
			t.Fatal(table, n, e)
		}
	}
}
