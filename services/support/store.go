// Package support implements the website support queue independently of account billing.
package support

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

//go:embed schema.sql
var schema string

var ErrUnauthorized = errors.New("session_expired")
var ErrConflict = errors.New("ticket_changed")
var ErrLimit = errors.New("rate_limited")
var ErrInvalid = errors.New("invalid_request")

type Store struct{ DB *pgxpool.Pool }
type Ticket struct {
	ID       string    `json:"id"`
	Status   string    `json:"status"`
	Revision int64     `json:"revision"`
	Created  time.Time `json:"created_at"`
	Updated  time.Time `json:"updated_at"`
}
type Message struct {
	ID      int64     `json:"id"`
	Role    string    `json:"role"`
	Body    string    `json:"body"`
	Created time.Time `json:"created_at"`
}
type State struct {
	Available bool      `json:"available"`
	Session   bool      `json:"session"`
	Ticket    *Ticket   `json:"ticket"`
	Messages  []Message `json:"messages"`
	More      bool      `json:"has_more"`
}
type Mutation struct {
	Key      string `json:"key"`
	Ticket   string `json:"ticket"`
	Body     string `json:"body"`
	Revision int64  `json:"revision"`
}

func randomID() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}
func hash(s string) string  { h := sha256.Sum256([]byte(s)); return hex.EncodeToString(h[:]) }
func validID(s string) bool { b, e := hex.DecodeString(s); return e == nil && len(b) == 32 }
func validBody(s string) bool {
	return utf8.ValidString(s) && strings.TrimSpace(s) != "" && utf8.RuneCountInString(s) <= 2000 && !strings.ContainsRune(s, 0)
}

// Migrate is explicit: the regular service does not change schemas on startup.
func (s *Store) Migrate(ctx context.Context) error {
	// Refuse known control-plane tables if a wrong credential was supplied.
	var cp bool
	if e := s.DB.QueryRow(ctx, `SELECT to_regclass('accounts') IS NOT NULL OR to_regclass('devices') IS NOT NULL OR to_regclass('subscriptions') IS NOT NULL`).Scan(&cp); e != nil {
		return e
	}
	if cp {
		return errors.New("support_requires_separate_database")
	}
	_, e := s.DB.Exec(ctx, schema)
	return e
}

func limit(ctx context.Context, tx pgx.Tx, key string, max int, seconds int) error {
	var n int
	err := tx.QueryRow(ctx, `INSERT INTO support_limits(key,count,expires_at) VALUES($1,1,now()+$2*interval '1 second')
 ON CONFLICT(key) DO UPDATE SET count=CASE WHEN support_limits.expires_at<=now() THEN 1 ELSE support_limits.count+1 END,
 expires_at=CASE WHEN support_limits.expires_at<=now() THEN excluded.expires_at ELSE support_limits.expires_at END RETURNING count`, key, seconds).Scan(&n)
	if err != nil {
		return err
	}
	if n > max {
		return ErrLimit
	}
	return nil
}
func (s *Store) Session(ctx context.Context, peer string) (string, error) {
	tx, e := s.DB.Begin(ctx)
	if e != nil {
		return "", e
	}
	defer tx.Rollback(ctx)
	if e = limit(ctx, tx, "session:"+hash(peer), 120, 3600); e != nil {
		return "", e
	}
	token := randomID()
	_, e = tx.Exec(ctx, `INSERT INTO support_visitors VALUES($1,now()+interval '30 days')`, hash(token))
	if e != nil {
		return "", e
	}
	return token, tx.Commit(ctx)
}
func (s *Store) sessionStatus(ctx context.Context, token string) (bool, error) {
	if !validID(token) {
		return false, nil
	}
	var ok bool
	e := s.DB.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM support_visitors WHERE id=$1 AND expires_at>now())`, hash(token)).Scan(&ok)
	return ok, e
}
func (s *Store) ValidSession(ctx context.Context, token string) bool {
	ok, err := s.sessionStatus(ctx, token)
	return ok && err == nil
}
func (s *Store) State(ctx context.Context, token, ticket string, before int64) (State, error) {
	st := State{Messages: []Message{}}
	ok, err := s.sessionStatus(ctx, token)
	if err != nil {
		return st, err
	}
	if !ok {
		return st, ErrUnauthorized
	}
	st.Session = true
	t := Ticket{}
	e := s.DB.QueryRow(ctx, `SELECT id,status,revision,created_at,updated_at FROM support_tickets WHERE visitor=$1 AND ($2='' OR id=$2) ORDER BY created_at DESC LIMIT 1`, hash(token), ticket).Scan(&t.ID, &t.Status, &t.Revision, &t.Created, &t.Updated)
	if errors.Is(e, pgx.ErrNoRows) {
		return st, nil
	}
	if e != nil {
		return st, e
	}
	st.Ticket = &t
	rows, e := s.DB.Query(ctx, `SELECT id,role,body,created_at FROM support_messages WHERE ticket=$1 AND ($2::bigint=0 OR id<$2) ORDER BY id DESC LIMIT 101`, t.ID, before)
	if e != nil {
		return st, e
	}
	defer rows.Close()
	for rows.Next() {
		var m Message
		if e = rows.Scan(&m.ID, &m.Role, &m.Body, &m.Created); e != nil {
			return st, e
		}
		st.Messages = append(st.Messages, m)
	}
	if e = rows.Err(); e != nil {
		return st, e
	}
	if len(st.Messages) > 100 {
		st.More = true
		st.Messages = st.Messages[:100]
	}
	for i, j := 0, len(st.Messages)-1; i < j; i, j = i+1, j-1 {
		st.Messages[i], st.Messages[j] = st.Messages[j], st.Messages[i]
	}
	return st, nil
}
func addMessage(ctx context.Context, tx pgx.Tx, ticket, role, body string) error {
	_, e := tx.Exec(ctx, `INSERT INTO support_messages(ticket,role,body) VALUES($1,$2,$3)`, ticket, role, body)
	return e
}
func enqueue(ctx context.Context, tx pgx.Tx, ticket, body string) error {
	_, e := tx.Exec(ctx, `INSERT INTO support_outbox(ticket,body) VALUES($1,$2)`, ticket, body)
	return e
}

// Mutate locks the visitor and ticket. A stable request key makes transport retries safe.
func (s *Store) Mutate(ctx context.Context, token, peer, action string, m Mutation) (string, error) {
	if !validID(token) || !validID(m.Key) || (m.Ticket != "" && !validID(m.Ticket)) {
		return "", ErrInvalid
	}
	if action == "message" && !validBody(m.Body) {
		return "", ErrInvalid
	}
	if action != "message" && action != "resolve" {
		return "", ErrInvalid
	}
	tx, e := s.DB.Begin(ctx)
	if e != nil {
		return "", e
	}
	defer tx.Rollback(ctx)
	visitor := hash(token)
	var id string
	e = tx.QueryRow(ctx, `SELECT id FROM support_visitors WHERE id=$1 AND expires_at>now() FOR UPDATE`, visitor).Scan(&id)
	if errors.Is(e, pgx.ErrNoRows) {
		return "", ErrUnauthorized
	}
	if e != nil {
		return "", e
	}
	digest := hash(fmt.Sprintf("%s\x00%s\x00%s\x00%d", action, m.Ticket, m.Body, m.Revision))
	var oldDigest, oldTicket string
	e = tx.QueryRow(ctx, `SELECT digest,ticket FROM support_requests WHERE visitor=$1 AND key=$2`, visitor, m.Key).Scan(&oldDigest, &oldTicket)
	if e == nil {
		if oldDigest != digest {
			return "", ErrConflict
		}
		return oldTicket, nil
	}
	if !errors.Is(e, pgx.ErrNoRows) {
		return "", e
	}
	if e = limit(ctx, tx, "visitor:"+visitor, 20, 60); e != nil {
		return "", e
	}
	if e = limit(ctx, tx, "ip:"+hash(peer), 600, 3600); e != nil {
		return "", e
	}
	ticket := m.Ticket
	if ticket == "" {
		if action != "message" {
			return "", ErrInvalid
		}
		if e = limit(ctx, tx, "tickets:"+hash(peer), 60, 3600); e != nil {
			return "", e
		}
		var active string
		e = tx.QueryRow(ctx, `SELECT id FROM support_tickets WHERE visitor=$1 AND status<>'resolved'`, visitor).Scan(&active)
		if e == nil {
			return "", ErrConflict
		}
		if !errors.Is(e, pgx.ErrNoRows) {
			return "", e
		}
		// Serialize only new ticket creation to bound the global queue across visitors.
		if _, e = tx.Exec(ctx, `SELECT pg_advisory_xact_lock(74651006)`); e != nil {
			return "", e
		}
		var queued int
		if e = tx.QueryRow(ctx, `SELECT count(*) FROM support_tickets WHERE status<>'resolved'`).Scan(&queued); e != nil {
			return "", e
		}
		if queued >= 5000 {
			return "", ErrLimit
		}
		ticket = randomID()
		_, e = tx.Exec(ctx, `INSERT INTO support_tickets(id,visitor,status) VALUES($1,$2,'queued')`, ticket, visitor)
		if e != nil {
			return "", e
		}
	}
	var status string
	var revision int64
	e = tx.QueryRow(ctx, `SELECT status,revision FROM support_tickets WHERE id=$1 AND visitor=$2 FOR UPDATE`, ticket, visitor).Scan(&status, &revision)
	if errors.Is(e, pgx.ErrNoRows) {
		return "", ErrUnauthorized
	}
	if e != nil {
		return "", e
	}
	if status == "resolved" {
		return "", ErrConflict
	}
	if action == "resolve" {
		// An unseen operator response must never be silently closed by a stale browser tab.
		if m.Revision != revision {
			return "", ErrConflict
		}
		_, e = tx.Exec(ctx, `UPDATE support_tickets SET status='resolved',revision=revision+1,updated_at=now() WHERE id=$1`, ticket)
		if e == nil {
			e = addMessage(ctx, tx, ticket, "system", "Пользователь подтвердил: вопрос решён.")
		}
		if e == nil {
			e = enqueue(ctx, tx, ticket, "Пользователь подтвердил решение. Тикет закрыт.")
		}
	} else {
		var n int
		e = tx.QueryRow(ctx, `SELECT count(*) FROM support_messages WHERE ticket=$1`, ticket).Scan(&n)
		if e != nil {
			return "", e
		}
		if n >= 2000 {
			return "", ErrLimit
		}
		e = addMessage(ctx, tx, ticket, "visitor", strings.TrimSpace(m.Body))
		if e == nil {
			_, e = tx.Exec(ctx, `UPDATE support_tickets SET revision=revision+1,updated_at=now() WHERE id=$1`, ticket)
		}
		if e == nil {
			e = enqueue(ctx, tx, ticket, "Сообщение пользователя:\n"+strings.TrimSpace(m.Body))
		}
	}
	if e != nil {
		return "", e
	}
	_, e = tx.Exec(ctx, `INSERT INTO support_requests(visitor,key,digest,ticket) VALUES($1,$2,$3,$4)`, visitor, m.Key, digest, ticket)
	if e != nil {
		return "", e
	}
	return ticket, tx.Commit(ctx)
}

// Prune bounds stored content to 90 days after last activity. Retention is not a resolution.
func (s *Store) Prune(ctx context.Context) error {
	tx, e := s.DB.Begin(ctx)
	if e != nil {
		return e
	}
	defer tx.Rollback(ctx)
	for _, q := range []string{
		`DELETE FROM support_tickets WHERE updated_at<now()-interval '90 days'`,
		`DELETE FROM support_requests WHERE created_at<now()-interval '30 days'`,
		`DELETE FROM support_updates WHERE created_at<now()-interval '7 days'`,
		`DELETE FROM support_limits WHERE expires_at<now()`,
		`DELETE FROM support_visitors v WHERE expires_at<now() AND NOT EXISTS(SELECT 1 FROM support_tickets t WHERE t.visitor=v.id) AND NOT EXISTS(SELECT 1 FROM support_requests r WHERE r.visitor=v.id)`,
	} {
		if _, e = tx.Exec(ctx, q); e != nil {
			return e
		}
	}
	return tx.Commit(ctx)
}
