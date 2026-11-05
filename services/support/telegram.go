package support

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

type TGUser struct {
	ID  int64 `json:"id"`
	Bot bool  `json:"is_bot"`
}
type TGChat struct {
	ID int64 `json:"id"`
}
type TGMessage struct {
	ID         int64      `json:"message_id"`
	Chat       TGChat     `json:"chat"`
	From       TGUser     `json:"from"`
	SenderChat *TGChat    `json:"sender_chat"`
	Text       string     `json:"text"`
	Reply      *TGMessage `json:"reply_to_message"`
}
type TGCallback struct {
	ID      string     `json:"id"`
	From    TGUser     `json:"from"`
	Message *TGMessage `json:"message"`
	Data    string     `json:"data"`
}
type TGUpdate struct {
	ID       int64       `json:"update_id"`
	Message  *TGMessage  `json:"message"`
	Callback *TGCallback `json:"callback_query"`
}

type Telegram struct {
	Store     *Store
	Token     string
	ChatID    int64
	Operators map[int64]bool
	Client    *http.Client
	// apiURL is injected only by package tests, never by configuration.
	apiURL string
}

func (t *Telegram) call(ctx context.Context, method string, payload any, result any) error {
	b, e := json.Marshal(payload)
	if e != nil {
		return errors.New("telegram_request_invalid")
	}
	base := "https://api.telegram.org"
	if t.apiURL != "" {
		base = t.apiURL
	}
	req, e := http.NewRequestWithContext(ctx, "POST", base+"/bot"+t.Token+"/"+method, bytes.NewReader(b))
	if e != nil {
		return errors.New("telegram_request_invalid")
	}
	req.Header.Set("Content-Type", "application/json")
	client := t.Client
	if client == nil {
		client = &http.Client{Timeout: 40 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	}
	resp, e := client.Do(req)
	if e != nil {
		return errors.New("telegram_transport_failed")
	}
	defer resp.Body.Close()
	var envelope struct {
		OK     bool            `json:"ok"`
		Result json.RawMessage `json:"result"`
	}
	if resp.StatusCode != 200 {
		return errors.New("telegram_unavailable")
	}
	if e = json.NewDecoder(io.LimitReader(resp.Body, 2<<20)).Decode(&envelope); e != nil || !envelope.OK {
		return errors.New("telegram_response_failed")
	}
	if result != nil {
		if e = json.Unmarshal(envelope.Result, result); e != nil {
			return errors.New("telegram_response_invalid")
		}
	}
	return nil
}
func (t *Telegram) allowed(u TGUser, chat int64, sender *TGChat) bool {
	return chat == t.ChatID && u.ID > 0 && !u.Bot && sender == nil && t.Operators[u.ID]
}

// Process commits the update, ticket mutation and acknowledgment together. Duplicate deliveries are inert.
func (t *Telegram) Process(ctx context.Context, u TGUpdate) (string, error) {
	tx, e := t.Store.DB.Begin(ctx)
	if e != nil {
		return "", e
	}
	defer tx.Rollback(ctx)
	tag, e := tx.Exec(ctx, `INSERT INTO support_updates(id) VALUES($1) ON CONFLICT DO NOTHING`, u.ID)
	if e != nil {
		return "", e
	}
	if tag.RowsAffected() == 0 {
		return "Уже обработано", nil
	}
	result := "Недоступное действие"
	if c := u.Callback; c != nil && c.Message != nil && t.allowed(c.From, c.Message.Chat.ID, nil) {
		// Telegram callback_data is capped at 64 bytes: compact 32-byte ticket in base16 is mapped by message, not embedded.
		var ticket string
		e = tx.QueryRow(ctx, `SELECT ticket FROM support_telegram_messages WHERE chat_id=$1 AND message_id=$2`, t.ChatID, c.Message.ID).Scan(&ticket)
		if e == nil {
			result, e = t.action(ctx, tx, ticket, c.From.ID, c.Data, "")
		} else if errors.Is(e, pgx.ErrNoRows) {
			e = nil
		}
	} else if m := u.Message; m != nil && t.allowed(m.From, m.Chat.ID, m.SenderChat) && m.Reply != nil {
		var ticket string
		e = tx.QueryRow(ctx, `SELECT ticket FROM support_telegram_messages WHERE chat_id=$1 AND message_id=$2`, t.ChatID, m.Reply.ID).Scan(&ticket)
		if e == nil {
			if validBody(m.Text) {
				result, e = t.action(ctx, tx, ticket, m.From.ID, "reply", strings.TrimSpace(m.Text))
			} else {
				result = "Не отправлено: нужен текст от 1 до 2000 символов, без вложений."
			}
			if e == nil {
				e = enqueue(ctx, tx, ticket, result)
			}
		} else if errors.Is(e, pgx.ErrNoRows) {
			e = nil
		}
	}
	if e != nil {
		return "", e
	}
	_, e = tx.Exec(ctx, `UPDATE support_worker SET offset_id=GREATEST(offset_id,$1) WHERE id=1`, u.ID+1)
	if e != nil {
		return "", e
	}
	return result, tx.Commit(ctx)
}
func (t *Telegram) action(ctx context.Context, tx pgx.Tx, ticket string, operator int64, action, body string) (string, error) {
	var status string
	var assigned int64
	e := tx.QueryRow(ctx, `SELECT status,operator_id FROM support_tickets WHERE id=$1 FOR UPDATE`, ticket).Scan(&status, &assigned)
	if e != nil {
		return "", e
	}
	if status == "resolved" {
		return "Тикет уже решён пользователем. Ответ не отправлен.", nil
	}
	switch action {
	case "claim":
		if assigned == operator {
			return "Уже в вашей работе", nil
		}
		if assigned != 0 {
			return "Уже взят другим оператором", nil
		}
		_, e = tx.Exec(ctx, `UPDATE support_tickets SET status='assigned',operator_id=$2,revision=revision+1,updated_at=now() WHERE id=$1`, ticket, operator)
		if e == nil {
			e = addMessage(ctx, tx, ticket, "system", "Специалист подключился к диалогу.")
		}
		if e == nil {
			e = enqueue(ctx, tx, ticket, fmt.Sprintf("Тикет взял оператор %d. Ответьте на сообщение бота через «Ответить».", operator))
		}
		return "Тикет в вашей работе", e
	case "release":
		if assigned != operator {
			return "Снять назначение может только текущий оператор", nil
		}
		_, e = tx.Exec(ctx, `UPDATE support_tickets SET status='queued',operator_id=0,revision=revision+1,updated_at=now() WHERE id=$1`, ticket)
		if e == nil {
			e = addMessage(ctx, tx, ticket, "system", "Обращение передано свободному специалисту.")
		}
		if e == nil {
			e = enqueue(ctx, tx, ticket, "Тикет возвращён в очередь. Его может взять другой оператор.")
		}
		return "Возвращено в очередь", e
	case "reply":
		if assigned != operator {
			return "Ответ не отправлен: сначала возьмите тикет в работу.", nil
		}
		e = addMessage(ctx, tx, ticket, "operator", body)
		if e == nil {
			_, e = tx.Exec(ctx, `UPDATE support_tickets SET revision=revision+1,updated_at=now() WHERE id=$1`, ticket)
		}
		return "Ответ сохранён и доступен пользователю на сайте.", e
	}
	return "Неизвестное действие", nil
}

// DeliverOne holds a transaction while sending one bounded request. On an ambiguous
// network failure Telegram may show a duplicate notification, but ticket messages
// and claims remain idempotent. Never log the request URL (it contains the token).
func (t *Telegram) DeliverOne(ctx context.Context) (bool, error) {
	tx, e := t.Store.DB.Begin(ctx)
	if e != nil {
		return false, e
	}
	defer tx.Rollback(ctx)
	var id int64
	var ticket, body, status string
	var operator int64
	var attempts int
	e = tx.QueryRow(ctx, `SELECT o.id,o.ticket,o.body,o.attempts,t.status,t.operator_id FROM support_outbox o JOIN support_tickets t ON t.id=o.ticket WHERE o.sent_at IS NULL AND o.next_at<=now() AND NOT EXISTS(SELECT 1 FROM support_outbox p WHERE p.ticket=o.ticket AND p.sent_at IS NULL AND p.id<o.id) ORDER BY o.id LIMIT 1 FOR UPDATE OF o SKIP LOCKED`).Scan(&id, &ticket, &body, &attempts, &status, &operator)
	if errors.Is(e, pgx.ErrNoRows) {
		return false, nil
	}
	if e != nil {
		return false, e
	}
	payload := map[string]any{"chat_id": t.ChatID, "text": "VELIQ · #" + ticket[:12] + "\n" + body, "protect_content": true, "link_preview_options": map[string]bool{"is_disabled": true}}
	if status != "resolved" {
		label, action := "Взять в работу", "claim"
		if operator != 0 {
			label, action = "Вернуть в очередь", "release"
		}
		payload["reply_markup"] = map[string]any{"inline_keyboard": [][]map[string]string{{{"text": label, "callback_data": action}}}}
	}
	var msg TGMessage
	sendCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	e = t.call(sendCtx, "sendMessage", payload, &msg)
	cancel()
	if e == nil && (msg.ID <= 0 || msg.Chat.ID != t.ChatID) {
		e = errors.New("telegram_message_invalid")
	}
	if e != nil {
		delay := min(300, 5*(1<<min(attempts, 6)))
		_, dbErr := tx.Exec(ctx, `UPDATE support_outbox SET attempts=attempts+1,next_at=now()+$2*interval '1 second' WHERE id=$1`, id, delay)
		if dbErr != nil {
			return false, dbErr
		}
		if dbErr = tx.Commit(ctx); dbErr != nil {
			return false, dbErr
		}
		return false, e
	}
	_, e = tx.Exec(ctx, `INSERT INTO support_telegram_messages(chat_id,message_id,ticket) VALUES($1,$2,$3) ON CONFLICT DO NOTHING`, t.ChatID, msg.ID, ticket)
	if e != nil {
		return false, e
	}
	_, e = tx.Exec(ctx, `UPDATE support_outbox SET sent_at=now() WHERE id=$1`, id)
	if e != nil {
		return false, e
	}
	return true, tx.Commit(ctx)
}

// Run requires an exclusive advisory lock for the lifetime of the poller. No webhook is used.
func (t *Telegram) Run(ctx context.Context, report func(string)) error {
	conn, e := t.Store.DB.Acquire(ctx)
	if e != nil {
		return e
	}
	defer conn.Release()
	var locked bool
	e = conn.QueryRow(ctx, `SELECT pg_try_advisory_lock(74651005)`).Scan(&locked)
	if e != nil {
		return e
	}
	if !locked {
		return errors.New("support_worker_already_running")
	}
	defer conn.Exec(context.WithoutCancel(ctx), `SELECT pg_advisory_unlock(74651005)`)
	outCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	done := make(chan struct{})
	go func() {
		defer close(done)
		timer := time.NewTicker(time.Second)
		defer timer.Stop()
		for {
			select {
			case <-outCtx.Done():
				return
			case <-timer.C:
				_, err := t.DeliverOne(outCtx)
				if err != nil {
					report("telegram_delivery_retry")
				}
			}
		}
	}()
	defer func() { cancel(); <-done }()
	cleanup := time.Now()
	for ctx.Err() == nil {
		// Detect loss of the connection carrying the singleton lock before polling again.
		if e = conn.Ping(ctx); e != nil {
			return errors.New("support_worker_lock_lost")
		}
		if time.Since(cleanup) > time.Hour {
			if e = t.Store.Prune(ctx); e != nil {
				report("retention_retry")
			}
			cleanup = time.Now()
		}
		var offset int64
		if e = t.Store.DB.QueryRow(ctx, `SELECT offset_id FROM support_worker WHERE id=1`).Scan(&offset); e != nil {
			return e
		}
		var updates []TGUpdate
		e = t.call(ctx, "getUpdates", map[string]any{"offset": offset, "timeout": 25, "limit": 50, "allowed_updates": []string{"message", "callback_query"}}, &updates)
		if e != nil {
			report("telegram_poll_retry")
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(5 * time.Second):
			}
			continue
		}
		for _, u := range updates {
			answer, err := t.Process(ctx, u)
			if err != nil {
				report("telegram_update_retry")
				break
			}
			if u.Callback != nil {
				_ = t.call(ctx, "answerCallbackQuery", map[string]any{"callback_query_id": u.Callback.ID, "text": answer, "show_alert": true}, nil)
			}
		}
	}
	return ctx.Err()
}
func ParseOperators(raw string) (map[int64]bool, error) {
	ids := map[int64]bool{}
	for _, v := range strings.Split(raw, ",") {
		id, e := strconv.ParseInt(strings.TrimSpace(v), 10, 64)
		if e != nil || id <= 0 {
			return nil, errors.New("invalid_operator_id")
		}
		ids[id] = true
	}
	return ids, nil
}
