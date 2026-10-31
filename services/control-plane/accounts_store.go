package controlplane

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"
	"time"

	"github.com/buzzmean/neexitlag/core/enrollment"
	"github.com/buzzmean/neexitlag/core/security"
	"github.com/jackc/pgx/v5"
)

const (
	LoginCodeLifetime   = 10 * time.Minute
	LoginCodeAttempts   = 5
	LoginResendInterval = time.Minute
	SessionLifetime     = 30 * 24 * time.Hour
	// SubscriptionGrace keeps a device working for a few days after the paid
	// period so a late renewal or a payment retry never interrupts a guest.
	SubscriptionGrace = 72 * time.Hour
	// Subscription codes never expire by themselves: the subscription period decides access.
	subscriptionCodeLifetime = 20 * 365 * 24 * time.Hour
	maxAccountSubscriptions  = 20
)

type Account struct {
	ID    string `json:"id"`
	Email string `json:"email"`
}
type Subscription struct {
	ID        string     `json:"id"`
	PlanID    string     `json:"plan_id"`
	Kind      string     `json:"kind"`
	Seats     int        `json:"seats"`
	PaidUntil *time.Time `json:"paid_until"`
	AutoRenew bool       `json:"auto_renew"`
	Active    bool       `json:"active"`
	Used      int        `json:"used_seats"`
	Devices   []SeatInfo `json:"devices"`
}
type SeatInfo struct {
	Machine  string     `json:"machine"`
	LastSeen *time.Time `json:"last_seen"`
}
type Payment struct {
	ID         string    `json:"id"`
	Subscribed string    `json:"subscription_id"`
	Provider   string    `json:"provider"`
	Amount     int64     `json:"amount_kopecks"`
	PeriodDays int       `json:"period_days"`
	Status     string    `json:"status"`
	Created    time.Time `json:"created_at"`
}

// Entitlement is the access decision for one device. Unmanaged devices (no
// activation slot, e.g. registered by the operator) are never limited.
type Entitlement struct {
	Managed bool
	Until   time.Time
}

func (e Entitlement) Active(now time.Time) bool {
	return !e.Managed || now.Before(e.Until.Add(SubscriptionGrace))
}

func loginHash(email, code string) []byte {
	h := sha256.Sum256([]byte("neexitlag:login-code:v1\x00" + email + "\x00" + code))
	return h[:]
}
func tokenHash(token string) []byte {
	h := sha256.Sum256([]byte("neexitlag:account-session:v1\x00" + token))
	return h[:]
}
func newLoginCode() (string, error) {
	n, e := rand.Int(rand.Reader, big.NewInt(1_000_000))
	if e != nil {
		return "", e
	}
	return fmt.Sprintf("%06d", n.Int64()), nil
}

// StartLogin stores a fresh one-time code. sent=false means a code was sent
// less than a minute ago and nothing new must be mailed.
func (s *Store) StartLogin(ctx context.Context, email string, now time.Time) (code string, sent bool, err error) {
	var last time.Time
	e := s.DB.QueryRow(ctx, "SELECT sent_at FROM login_codes WHERE email=$1", email).Scan(&last)
	if e == nil && now.Sub(last) < LoginResendInterval {
		return "", false, nil
	}
	if e != nil && !errors.Is(e, pgx.ErrNoRows) {
		return "", false, e
	}
	if code, e = newLoginCode(); e != nil {
		return "", false, e
	}
	_, e = s.DB.Exec(ctx, "INSERT INTO login_codes(email,code_hash,expires_at,attempts,sent_at) VALUES($1,$2,$3,0,$4) ON CONFLICT(email) DO UPDATE SET code_hash=excluded.code_hash,expires_at=excluded.expires_at,attempts=0,sent_at=excluded.sent_at", email, loginHash(email, code), now.Add(LoginCodeLifetime), now)
	if e != nil {
		return "", false, e
	}
	return code, true, nil
}

// FinishLogin checks the code, creates the account on first login and opens a session.
func (s *Store) FinishLogin(ctx context.Context, email, code string, now time.Time) (Account, string, error) {
	tx, e := s.DB.Begin(ctx)
	if e != nil {
		return Account{}, "", e
	}
	defer tx.Rollback(ctx)
	var hash []byte
	var expires time.Time
	var attempts int
	e = tx.QueryRow(ctx, "SELECT code_hash,expires_at,attempts FROM login_codes WHERE email=$1 FOR UPDATE", email).Scan(&hash, &expires, &attempts)
	if errors.Is(e, pgx.ErrNoRows) {
		return Account{}, "", errors.New("LOGIN_CODE_INVALID")
	}
	if e != nil {
		return Account{}, "", e
	}
	if !now.Before(expires) || attempts >= LoginCodeAttempts {
		return Account{}, "", errors.New("LOGIN_CODE_INVALID")
	}
	if subtle.ConstantTimeCompare(hash, loginHash(email, code)) != 1 {
		// The attempt counter must survive the failed login, so commit it.
		if _, e = tx.Exec(ctx, "UPDATE login_codes SET attempts=attempts+1 WHERE email=$1", email); e != nil {
			return Account{}, "", e
		}
		if e = tx.Commit(ctx); e != nil {
			return Account{}, "", e
		}
		return Account{}, "", errors.New("LOGIN_CODE_INVALID")
	}
	if _, e = tx.Exec(ctx, "DELETE FROM login_codes WHERE email=$1", email); e != nil {
		return Account{}, "", e
	}
	id, e := security.NewID()
	if e != nil {
		return Account{}, "", e
	}
	var a Account
	var disabled bool
	e = tx.QueryRow(ctx, "INSERT INTO accounts(id,email) VALUES($1,$2) ON CONFLICT(email) DO UPDATE SET email=excluded.email RETURNING id,email,disabled", id, email).Scan(&a.ID, &a.Email, &disabled)
	if e != nil {
		return Account{}, "", e
	}
	if disabled {
		return Account{}, "", errors.New("ACCOUNT_DISABLED")
	}
	raw := make([]byte, 32)
	if _, e = rand.Read(raw); e != nil {
		return Account{}, "", e
	}
	token := base64.RawURLEncoding.EncodeToString(raw)
	if _, e = tx.Exec(ctx, "DELETE FROM account_sessions WHERE expires_at<$1", now); e != nil {
		return Account{}, "", e
	}
	if _, e = tx.Exec(ctx, "INSERT INTO account_sessions(token_hash,account_id,expires_at) VALUES($1,$2,$3)", tokenHash(token), a.ID, now.Add(SessionLifetime)); e != nil {
		return Account{}, "", e
	}
	if _, e = tx.Exec(ctx, "INSERT INTO audit_log(actor,action,entity_id) VALUES('account','account.login',$1)", a.ID); e != nil {
		return Account{}, "", e
	}
	return a, token, tx.Commit(ctx)
}

func (s *Store) SessionAccount(ctx context.Context, token string, now time.Time) (Account, error) {
	var a Account
	e := s.DB.QueryRow(ctx, "SELECT a.id,a.email FROM account_sessions s JOIN accounts a ON a.id=s.account_id WHERE s.token_hash=$1 AND s.expires_at>$2 AND NOT a.disabled", tokenHash(token), now).Scan(&a.ID, &a.Email)
	return a, e
}
func (s *Store) EndSession(ctx context.Context, token string) error {
	_, e := s.DB.Exec(ctx, "DELETE FROM account_sessions WHERE token_hash=$1", tokenHash(token))
	return e
}

// CreateSubscription adds an unpaid subscription with its activation code row.
// The code value itself is issued separately (IssueSubscriptionCode).
func (s *Store) CreateSubscription(ctx context.Context, account Account, p Plan, seats int) (string, error) {
	if seats < 1 || seats > p.MaxSeats {
		return "", errors.New("SUBSCRIPTION_INVALID")
	}
	tx, e := s.DB.Begin(ctx)
	if e != nil {
		return "", e
	}
	defer tx.Rollback(ctx)
	var n int
	if e = tx.QueryRow(ctx, "SELECT count(*) FROM subscriptions WHERE account_id=$1", account.ID).Scan(&n); e != nil {
		return "", e
	}
	if n >= maxAccountSubscriptions {
		return "", errors.New("SUBSCRIPTION_LIMIT")
	}
	id, e := security.NewID()
	if e != nil {
		return "", e
	}
	codeID, e := security.NewID()
	if e != nil {
		return "", e
	}
	// A random placeholder hash: nobody knows a code for it until one is issued.
	placeholder := make([]byte, 32)
	if _, e = rand.Read(placeholder); e != nil {
		return "", e
	}
	kind := "personal"
	if p.Kind == "club" {
		kind = "club"
	}
	name := p.Title + " · " + account.Email
	if len(name) > 128 {
		name = name[:128]
	}
	if _, e = tx.Exec(ctx, "INSERT INTO subscriptions(id,account_id,plan_id,kind,seats) VALUES($1,$2,$3,$4,$5)", id, account.ID, p.ID, p.Kind, seats); e != nil {
		return "", e
	}
	if _, e = tx.Exec(ctx, "INSERT INTO activation_codes(id,code_hash,kind,seat_limit,name,expires_at,subscription_id) VALUES($1,$2,$3,$4,$5,$6,$7)", codeID, placeholder, kind, seats, name, time.Now().Add(subscriptionCodeLifetime), id); e != nil {
		return "", e
	}
	if _, e = tx.Exec(ctx, "INSERT INTO audit_log(actor,action,entity_id) VALUES($1,'subscription.create',$2)", "account:"+account.ID, id); e != nil {
		return "", e
	}
	return id, tx.Commit(ctx)
}

// IssueSubscriptionCode replaces the code value of a subscription. Computers
// already activated keep their seats; only the old value stops activating new ones.
func (s *Store) IssueSubscriptionCode(ctx context.Context, account Account, subscription string) (string, error) {
	code, e := enrollment.NewCode()
	if e != nil {
		return "", e
	}
	hash, e := enrollment.CodeHash(code)
	if e != nil {
		return "", e
	}
	tag, e := s.DB.Exec(ctx, "UPDATE activation_codes SET code_hash=$1 WHERE revoked=false AND subscription_id=(SELECT id FROM subscriptions WHERE id=$2 AND account_id=$3)", hash, subscription, account.ID)
	if e != nil {
		return "", e
	}
	if tag.RowsAffected() != 1 {
		return "", errors.New("SUBSCRIPTION_NOT_FOUND")
	}
	_, e = s.DB.Exec(ctx, "INSERT INTO audit_log(actor,action,entity_id) VALUES($1,'subscription.code',$2)", "account:"+account.ID, subscription)
	return code, e
}

// ReleaseSeat frees one computer of the subscription and revokes its device.
// The computer can be activated again with the current code.
func (s *Store) ReleaseSeat(ctx context.Context, account Account, subscription, machinePrefix string, kid string, key []byte, public map[string]string) error {
	if len(machinePrefix) < 12 || len(machinePrefix) > 64 {
		return errors.New("SEAT_NOT_FOUND")
	}
	tx, e := s.DB.Begin(ctx)
	if e != nil {
		return e
	}
	defer tx.Rollback(ctx)
	if _, e = tx.Exec(ctx, "SELECT pg_advisory_xact_lock(724220)"); e != nil {
		return e
	}
	var code, machine, device string
	rows, e := tx.Query(ctx, "SELECT c.id,sl.machine_hash,sl.device_id FROM activation_slots sl JOIN activation_codes c ON c.id=sl.code_id JOIN subscriptions sub ON sub.id=c.subscription_id WHERE sub.id=$1 AND sub.account_id=$2 AND left(sl.machine_hash,$4)=$3", subscription, account.ID, machinePrefix, len(machinePrefix))
	if e != nil {
		return e
	}
	n := 0
	for rows.Next() {
		if e = rows.Scan(&code, &machine, &device); e != nil {
			rows.Close()
			return e
		}
		n++
	}
	rows.Close()
	if e = rows.Err(); e != nil {
		return e
	}
	if n != 1 {
		return errors.New("SEAT_NOT_FOUND")
	}
	if _, e = tx.Exec(ctx, "DELETE FROM activation_slots WHERE code_id=$1 AND machine_hash=$2", code, machine); e != nil {
		return e
	}
	if _, e = tx.Exec(ctx, "UPDATE devices SET revoked=true WHERE id=$1", device); e != nil {
		return e
	}
	if _, e = tx.Exec(ctx, "INSERT INTO audit_log(actor,action,entity_id) VALUES($1,'subscription.release',$2)", "account:"+account.ID, device); e != nil {
		return e
	}
	if _, e = publishConfigTx(ctx, tx, kid, key, public); e != nil {
		return e
	}
	return tx.Commit(ctx)
}

func (s *Store) SetAutoRenew(ctx context.Context, account Account, subscription string, on bool) error {
	tag, e := s.DB.Exec(ctx, "UPDATE subscriptions SET auto_renew=$3 WHERE id=$1 AND account_id=$2", subscription, account.ID, on)
	if e != nil {
		return e
	}
	if tag.RowsAffected() != 1 {
		return errors.New("SUBSCRIPTION_NOT_FOUND")
	}
	return nil
}

func (s *Store) AccountSubscriptions(ctx context.Context, account Account, now time.Time) ([]Subscription, error) {
	rows, e := s.DB.Query(ctx, "SELECT id,plan_id,kind,seats,paid_until,auto_renew FROM subscriptions WHERE account_id=$1 ORDER BY created_at", account.ID)
	if e != nil {
		return nil, e
	}
	out := []Subscription{}
	for rows.Next() {
		var sub Subscription
		if e = rows.Scan(&sub.ID, &sub.PlanID, &sub.Kind, &sub.Seats, &sub.PaidUntil, &sub.AutoRenew); e != nil {
			rows.Close()
			return nil, e
		}
		sub.Active = sub.PaidUntil != nil && now.Before(*sub.PaidUntil)
		sub.Devices = []SeatInfo{}
		out = append(out, sub)
	}
	rows.Close()
	if e = rows.Err(); e != nil {
		return nil, e
	}
	for i := range out {
		seats, e := s.DB.Query(ctx, "SELECT sl.machine_hash,d.last_authenticated_at FROM activation_slots sl JOIN activation_codes c ON c.id=sl.code_id JOIN devices d ON d.id=sl.device_id WHERE c.subscription_id=$1 AND NOT sl.disabled ORDER BY sl.updated_at LIMIT 10001", out[i].ID)
		if e != nil {
			return nil, e
		}
		for seats.Next() {
			var info SeatInfo
			if e = seats.Scan(&info.Machine, &info.LastSeen); e != nil {
				seats.Close()
				return nil, e
			}
			// A prefix is enough to tell computers apart and to release a seat.
			info.Machine = info.Machine[:12]
			out[i].Devices = append(out[i].Devices, info)
		}
		seats.Close()
		if e = seats.Err(); e != nil {
			return nil, e
		}
		out[i].Used = len(out[i].Devices)
	}
	return out, nil
}

func (s *Store) AccountPayments(ctx context.Context, account Account) ([]Payment, error) {
	rows, e := s.DB.Query(ctx, "SELECT p.id,p.subscription_id,p.provider,p.amount_kopecks,p.period_days,p.status,p.created_at FROM payments p JOIN subscriptions sub ON sub.id=p.subscription_id WHERE sub.account_id=$1 ORDER BY p.created_at DESC LIMIT 100", account.ID)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []Payment{}
	for rows.Next() {
		var p Payment
		if e = rows.Scan(&p.ID, &p.Subscribed, &p.Provider, &p.Amount, &p.PeriodDays, &p.Status, &p.Created); e != nil {
			return nil, e
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// RecordPayment stores a payment and, when it succeeded, extends the period.
// The (provider, provider_payment_id) pair makes repeated notifications harmless:
// a payment extends the subscription exactly once.
func (s *Store) RecordPayment(ctx context.Context, subscription, provider, providerID string, amount int64, days int, status, reference, actor string, now time.Time) (time.Time, bool, error) {
	if provider == "" || len(provider) > 32 || providerID == "" || len(providerID) > 128 || len(reference) > 256 || amount < 0 || days < 1 || days > 400 || (status != "pending" && status != "succeeded" && status != "canceled") {
		return time.Time{}, false, errors.New("PAYMENT_INVALID")
	}
	tx, e := s.DB.Begin(ctx)
	if e != nil {
		return time.Time{}, false, e
	}
	defer tx.Rollback(ctx)
	var paid *time.Time
	if e = tx.QueryRow(ctx, "SELECT paid_until FROM subscriptions WHERE id=$1 FOR UPDATE", subscription).Scan(&paid); errors.Is(e, pgx.ErrNoRows) {
		return time.Time{}, false, errors.New("SUBSCRIPTION_NOT_FOUND")
	} else if e != nil {
		return time.Time{}, false, e
	}
	var old string
	e = tx.QueryRow(ctx, "SELECT status FROM payments WHERE provider=$1 AND provider_payment_id=$2 FOR UPDATE", provider, providerID).Scan(&old)
	switch {
	case errors.Is(e, pgx.ErrNoRows):
		id, err := security.NewID()
		if err != nil {
			return time.Time{}, false, err
		}
		if _, e = tx.Exec(ctx, "INSERT INTO payments(id,subscription_id,provider,provider_payment_id,amount_kopecks,period_days,status,reference) VALUES($1,$2,$3,$4,$5,$6,$7,$8)", id, subscription, provider, providerID, amount, days, status, reference); e != nil {
			return time.Time{}, false, e
		}
	case e != nil:
		return time.Time{}, false, e
	case old == "succeeded" || old == status:
		until := time.Time{}
		if paid != nil {
			until = *paid
		}
		return until, false, tx.Commit(ctx)
	default:
		if _, e = tx.Exec(ctx, "UPDATE payments SET status=$3 WHERE provider=$1 AND provider_payment_id=$2", provider, providerID, status); e != nil {
			return time.Time{}, false, e
		}
	}
	until := time.Time{}
	if paid != nil {
		until = *paid
	}
	extended := false
	if status == "succeeded" {
		if until.Before(now) {
			until = now
		}
		// PostgreSQL keeps microseconds; returning the stored value keeps answers stable.
		until = until.Add(time.Duration(days) * 24 * time.Hour).Truncate(time.Microsecond)
		extended = true
		if _, e = tx.Exec(ctx, "UPDATE subscriptions SET paid_until=$2 WHERE id=$1", subscription, until); e != nil {
			return time.Time{}, false, e
		}
	}
	if _, e = tx.Exec(ctx, "INSERT INTO audit_log(actor,action,entity_id) VALUES($1,$2,$3)", actor, "payment."+status, subscription); e != nil {
		return time.Time{}, false, e
	}
	return until, extended, tx.Commit(ctx)
}

// RecordProviderPayment applies an authenticated provider notification to a
// payment that was recorded as pending when the link was created. The stored
// row is authoritative: an unknown provider id is rejected, the event amount
// must match the pending record, and the credited sum/period come from the
// record, not from the notification. Repeats and out-of-order deliveries are
// harmless: the same status is a no-op, and a payment that already succeeded
// is never reopened by a later event.
func (s *Store) RecordProviderPayment(ctx context.Context, provider, providerID string, amount int64, status, actor string, now time.Time) (time.Time, bool, error) {
	if provider == "" || len(provider) > 32 || providerID == "" || len(providerID) > 128 || amount < 0 || (status != "succeeded" && status != "canceled") {
		return time.Time{}, false, errors.New("PAYMENT_INVALID")
	}
	tx, e := s.DB.Begin(ctx)
	if e != nil {
		return time.Time{}, false, e
	}
	defer tx.Rollback(ctx)
	var subscription, old string
	var storedAmount int64
	var days int
	e = tx.QueryRow(ctx, "SELECT subscription_id, amount_kopecks, period_days, status FROM payments WHERE provider=$1 AND provider_payment_id=$2 FOR UPDATE", provider, providerID).Scan(&subscription, &storedAmount, &days, &old)
	if errors.Is(e, pgx.ErrNoRows) {
		return time.Time{}, false, errors.New("PAYMENT_UNKNOWN")
	}
	if e != nil {
		return time.Time{}, false, e
	}
	if storedAmount != amount {
		return time.Time{}, false, errors.New("PAYMENT_MISMATCH")
	}
	var paid *time.Time
	if e = tx.QueryRow(ctx, "SELECT paid_until FROM subscriptions WHERE id=$1 FOR UPDATE", subscription).Scan(&paid); e != nil {
		return time.Time{}, false, e
	}
	until := time.Time{}
	if paid != nil {
		until = *paid
	}
	if old == "succeeded" || old == status {
		return until, false, tx.Commit(ctx)
	}
	if _, e = tx.Exec(ctx, "UPDATE payments SET status=$3 WHERE provider=$1 AND provider_payment_id=$2", provider, providerID, status); e != nil {
		return time.Time{}, false, e
	}
	extended := false
	if status == "succeeded" {
		if until.Before(now) {
			until = now
		}
		// PostgreSQL keeps microseconds; returning the stored value keeps answers stable.
		until = until.Add(time.Duration(days) * 24 * time.Hour).Truncate(time.Microsecond)
		extended = true
		if _, e = tx.Exec(ctx, "UPDATE subscriptions SET paid_until=$2 WHERE id=$1", subscription, until); e != nil {
			return time.Time{}, false, e
		}
	}
	if _, e = tx.Exec(ctx, "INSERT INTO audit_log(actor,action,entity_id) VALUES($1,$2,$3)", actor, "payment."+status, subscription); e != nil {
		return time.Time{}, false, e
	}
	return until, extended, tx.Commit(ctx)
}

// DeviceEntitlement finds the latest paid-until across every slot of the device.
func (s *Store) DeviceEntitlement(ctx context.Context, device string) (Entitlement, error) {
	rows, e := s.DB.Query(ctx, "SELECT c.subscription_id IS NOT NULL,c.expires_at,sub.paid_until FROM activation_slots sl JOIN activation_codes c ON c.id=sl.code_id LEFT JOIN subscriptions sub ON sub.id=c.subscription_id WHERE sl.device_id=$1 AND NOT sl.disabled AND NOT c.revoked", device)
	if e != nil {
		return Entitlement{}, e
	}
	defer rows.Close()
	var out Entitlement
	for rows.Next() {
		var withSub bool
		var expires time.Time
		var paid *time.Time
		if e = rows.Scan(&withSub, &expires, &paid); e != nil {
			return Entitlement{}, e
		}
		out.Managed = true
		until := expires
		if withSub {
			until = time.Time{}
			if paid != nil {
				until = *paid
			}
		}
		if until.After(out.Until) {
			out.Until = until
		}
	}
	return out, rows.Err()
}

type CutoffDevice struct {
	Device   string     `json:"device_id"`
	Code     string     `json:"code_name"`
	Until    time.Time  `json:"until"`
	LastSeen *time.Time `json:"last_seen"`
}

// SubscriptionCutoff lists active devices that enforcement would stop right now,
// so the operator can review them before switching enforcement on.
func (s *Store) SubscriptionCutoff(ctx context.Context, now time.Time) ([]CutoffDevice, error) {
	rows, e := s.DB.Query(ctx, `SELECT d.id, max(c.name), max(CASE WHEN c.subscription_id IS NULL THEN c.expires_at ELSE coalesce(sub.paid_until,'epoch'::timestamptz) END) AS until, d.last_authenticated_at
FROM devices d JOIN activation_slots sl ON sl.device_id=d.id AND NOT sl.disabled JOIN activation_codes c ON c.id=sl.code_id AND NOT c.revoked LEFT JOIN subscriptions sub ON sub.id=c.subscription_id
WHERE NOT d.revoked GROUP BY d.id, d.last_authenticated_at HAVING max(CASE WHEN c.subscription_id IS NULL THEN c.expires_at ELSE coalesce(sub.paid_until,'epoch'::timestamptz) END) + $1::interval <= $2 ORDER BY d.id LIMIT 1000`, fmt.Sprintf("%d seconds", int(SubscriptionGrace.Seconds())), now)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []CutoffDevice{}
	for rows.Next() {
		var d CutoffDevice
		if e = rows.Scan(&d.Device, &d.Code, &d.Until, &d.LastSeen); e != nil {
			return nil, e
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

type AdminSubscription struct {
	ID        string     `json:"id"`
	Email     string     `json:"email"`
	PlanID    string     `json:"plan_id"`
	Seats     int        `json:"seats"`
	PaidUntil *time.Time `json:"paid_until"`
}

func (s *Store) AdminSubscriptions(ctx context.Context) ([]AdminSubscription, error) {
	rows, e := s.DB.Query(ctx, "SELECT sub.id,a.email,sub.plan_id,sub.seats,sub.paid_until FROM subscriptions sub JOIN accounts a ON a.id=sub.account_id ORDER BY sub.created_at DESC LIMIT 1000")
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []AdminSubscription{}
	for rows.Next() {
		var x AdminSubscription
		if e = rows.Scan(&x.ID, &x.Email, &x.PlanID, &x.Seats, &x.PaidUntil); e != nil {
			return nil, e
		}
		out = append(out, x)
	}
	return out, rows.Err()
}
