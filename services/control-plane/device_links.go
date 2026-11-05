package controlplane

import (
	"context"
	"crypto/ed25519"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"
	"unicode"

	"github.com/buzzmean/neexitlag/core/enrollment"
	"github.com/jackc/pgx/v5"
)

const deviceLinkLifetime = 10 * time.Minute
const clubBootstrapLifetime = 90 * 24 * time.Hour

type deviceLinkRow struct {
	ID, Mode, Name, Device, Machine, PublicKey string
	SecretHash, BootstrapHash                  []byte
	Expires                                    time.Time
	Account, Subscription                      string
	Completed                                  bool
}

func readDeviceLink(ctx context.Context, tx pgx.Tx, id string) (deviceLinkRow, error) {
	var l deviceLinkRow
	e := tx.QueryRow(ctx, `SELECT id,mode,name,device_id,machine_hash,public_key,secret_hash,bootstrap_hash,expires_at,coalesce(account_id,''),coalesce(subscription_id,''),completed FROM account_device_links WHERE id=$1 FOR UPDATE`, id).Scan(&l.ID, &l.Mode, &l.Name, &l.Device, &l.Machine, &l.PublicKey, &l.SecretHash, &l.BootstrapHash, &l.Expires, &l.Account, &l.Subscription, &l.Completed)
	if errors.Is(e, pgx.ErrNoRows) {
		return l, errors.New("ACCOUNT_LINK_INVALID")
	}
	return l, e
}
func (s *Store) startDeviceLink(ctx context.Context, q enrollment.DeviceLinkRequest, pub ed25519.PublicKey) (deviceLinkRow, error) {
	hash, e := enrollment.AccountSecretHash(q.Secret)
	if e != nil {
		return deviceLinkRow{}, e
	}
	bootstrap, _ := hex.DecodeString(q.BootstrapHash)
	l := deviceLinkRow{ID: q.ID, Mode: q.Mode, Name: q.Name, Device: q.Device.DeviceID, Machine: q.Device.MachineHash, PublicKey: base64.RawURLEncoding.EncodeToString(pub), SecretHash: hash, BootstrapHash: bootstrap, Expires: time.Now().UTC().Add(deviceLinkLifetime)}
	tx, e := s.DB.Begin(ctx)
	if e != nil {
		return l, e
	}
	defer tx.Rollback(ctx)
	if _, e = tx.Exec(ctx, "SELECT pg_advisory_xact_lock(724221)"); e != nil {
		return l, e
	}
	if _, e = tx.Exec(ctx, "DELETE FROM account_device_links WHERE id IN (SELECT id FROM account_device_links WHERE expires_at<now() LIMIT 128)"); e != nil {
		return l, e
	}
	old, oe := readDeviceLink(ctx, tx, q.ID)
	if oe == nil {
		if subtle.ConstantTimeCompare(old.SecretHash, hash) != 1 || old.Mode != l.Mode || old.Name != l.Name || old.Device != l.Device || old.Machine != l.Machine || old.PublicKey != l.PublicKey || subtle.ConstantTimeCompare(old.BootstrapHash, bootstrap) != 1 {
			return l, errors.New("ACCOUNT_LINK_INVALID")
		}
		return old, tx.Commit(ctx)
	}
	if oe.Error() != "ACCOUNT_LINK_INVALID" {
		return l, oe
	}
	var count int
	if e = tx.QueryRow(ctx, "SELECT count(*) FROM account_device_links WHERE expires_at>now()").Scan(&count); e != nil {
		return l, e
	}
	if count >= 4096 {
		return l, errors.New("ACTIVATION_RATE_LIMIT")
	}
	_, e = tx.Exec(ctx, `INSERT INTO account_device_links(id,secret_hash,mode,name,device_id,machine_hash,public_key,bootstrap_hash,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)`, l.ID, l.SecretHash, l.Mode, l.Name, l.Device, l.Machine, l.PublicKey, l.BootstrapHash, l.Expires)
	if e != nil {
		return l, e
	}
	return l, tx.Commit(ctx)
}

type accountSubscription struct {
	Binding enrollment.AccountBinding
	Code    string
	Limit   int
}

func accountSubscriptionTx(ctx context.Context, tx pgx.Tx, account, subscription string, enforce bool) (accountSubscription, error) {
	var out accountSubscription
	var paid *time.Time
	var expires time.Time
	var revoked, disabled bool
	e := tx.QueryRow(ctx, `SELECT sub.id,sub.kind,sub.seats,sub.paid_until,ac.email,ac.display_name,ac.disabled,c.id,c.revoked,c.expires_at FROM subscriptions sub JOIN accounts ac ON ac.id=sub.account_id JOIN activation_codes c ON c.subscription_id=sub.id WHERE sub.id=$1 AND sub.account_id=$2 FOR UPDATE OF sub,ac,c`, subscription, account).Scan(&out.Binding.Subscription, &out.Binding.Kind, &out.Limit, &paid, &out.Binding.Email, &out.Binding.Name, &disabled, &out.Code, &revoked, &expires)
	if errors.Is(e, pgx.ErrNoRows) {
		return out, errors.New("ACCOUNT_SUBSCRIPTION_REQUIRED")
	}
	if e != nil {
		return out, e
	}
	if disabled || revoked || !expires.After(time.Now()) {
		return out, errors.New("ACCOUNT_SUBSCRIPTION_REQUIRED")
	}
	if enforce && (paid == nil || !paid.Add(SubscriptionGrace).After(time.Now())) {
		return out, errors.New("SUBSCRIPTION_EXPIRED")
	}
	if out.Binding.Name == "" {
		if out.Binding.Kind == "club" {
			out.Binding.Name = "Клуб"
		} else {
			out.Binding.Name = "Личный аккаунт"
		}
	}
	return out, nil
}
func (s *Store) approveDeviceLink(ctx context.Context, account Account, id, subscription string, enforce bool) error {
	tx, e := s.DB.Begin(ctx)
	if e != nil {
		return e
	}
	defer tx.Rollback(ctx)
	if _, e = tx.Exec(ctx, "SELECT pg_advisory_xact_lock(724220)"); e != nil {
		return e
	}
	l, e := readDeviceLink(ctx, tx, id)
	if e != nil {
		return e
	}
	if !l.Expires.After(time.Now()) {
		return errors.New("ACCOUNT_LINK_EXPIRED")
	}
	if l.Account != "" && (l.Account != account.ID || l.Subscription != subscription) {
		return errors.New("ACCOUNT_LINK_INVALID")
	}
	sub, e := accountSubscriptionTx(ctx, tx, account.ID, subscription, enforce)
	if e != nil {
		return e
	}
	if l.Mode == "image" && sub.Binding.Kind != "club" {
		return errors.New("ACCOUNT_SUBSCRIPTION_REQUIRED")
	}
	if l.Mode == "device" {
		var foreign bool
		if e = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM activation_slots sl JOIN activation_codes c ON c.id=sl.code_id JOIN subscriptions sub ON sub.id=c.subscription_id WHERE sl.device_id=$1 AND NOT sl.disabled AND sub.account_id<>$2)`, l.Device, account.ID).Scan(&foreign); e != nil {
			return e
		}
		if foreign {
			return errors.New("ACCOUNT_DEVICE_ALREADY_OWNED")
		}
	}
	if _, e = tx.Exec(ctx, "UPDATE account_device_links SET account_id=$2,subscription_id=$3 WHERE id=$1", id, account.ID, subscription); e != nil {
		return e
	}
	return tx.Commit(ctx)
}
func (a *API) accountLinkAvailable() bool {
	u, e := url.Parse(a.Settings.AccountOrigin)
	return e == nil && u.Scheme == "https" && u.Host != "" && u.User == nil && u.Path == "" && u.RawQuery == "" && u.Fragment == "" && len(a.Settings.EnrollmentProbeToken) >= 24 && a.Settings.Mailer != nil
}
func (a *API) deviceLinkStart(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if !a.accountLinkAvailable() {
		a.fail(w, 503, "ACCOUNT_NOT_CONFIGURED")
		return
	}
	if !a.enrollIP.allow(time.Now(), sourceKey(r)) {
		a.fail(w, 429, "ACTIVATION_RATE_LIMIT")
		return
	}
	var q enrollment.DeviceLinkRequest
	if body(r, &q) != nil {
		a.fail(w, 400, "ACCOUNT_LINK_INVALID")
		return
	}
	pub, e := q.Validate(time.Now())
	if e != nil {
		a.fail(w, 400, "ACCOUNT_LINK_INVALID")
		return
	}
	l, e := a.Store.startDeviceLink(r.Context(), q, pub)
	if e != nil {
		a.deviceLinkFailure(w, e)
		return
	}
	respond(w, 201, enrollment.DeviceLinkStatus{State: "PENDING", VerificationURL: a.Settings.AccountOrigin + "/account.html#device=" + q.ID, ExpiresAt: l.Expires, Interval: 3})
}
func (a *API) deviceLinkPoll(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if !a.accountLinkAvailable() {
		a.fail(w, 503, "ACCOUNT_NOT_CONFIGURED")
		return
	}
	var q enrollment.DeviceLinkPoll
	if body(r, &q) != nil || !enrollment.AccountLinkID(q.ID) {
		a.fail(w, 400, "ACCOUNT_LINK_INVALID")
		return
	}
	hash, e := enrollment.AccountSecretHash(q.Secret)
	if e != nil {
		a.fail(w, 401, "ACCOUNT_LINK_INVALID")
		return
	}
	tx, e := a.Store.DB.Begin(r.Context())
	if e != nil {
		a.deviceLinkFailure(w, e)
		return
	}
	defer tx.Rollback(r.Context())
	if _, e = tx.Exec(r.Context(), "SELECT pg_advisory_xact_lock(724220)"); e != nil {
		a.deviceLinkFailure(w, e)
		return
	}
	l, e := readDeviceLink(r.Context(), tx, q.ID)
	if e != nil || subtle.ConstantTimeCompare(hash, l.SecretHash) != 1 {
		a.fail(w, 401, "ACCOUNT_LINK_INVALID")
		return
	}
	if !l.Expires.After(time.Now()) {
		a.fail(w, 410, "ACCOUNT_LINK_EXPIRED")
		return
	}
	if l.Account == "" {
		respond(w, 202, enrollment.DeviceLinkStatus{State: "PENDING", ExpiresAt: l.Expires, Interval: 3})
		return
	}
	sub, e := accountSubscriptionTx(r.Context(), tx, l.Account, l.Subscription, true)
	if e != nil {
		a.deviceLinkFailure(w, e)
		return
	}
	out := enrollment.DeviceLinkStatus{State: "APPROVED", ExpiresAt: l.Expires, Interval: 3, Account: sub.Binding}
	if l.Mode == "image" {
		if sub.Binding.Kind != "club" {
			a.fail(w, 403, "ACCOUNT_SUBSCRIPTION_REQUIRED")
			return
		}
		if !l.Completed {
			var n int
			if e = tx.QueryRow(r.Context(), "SELECT count(*) FROM club_bootstraps WHERE subscription_id=$1 AND NOT revoked AND expires_at>now()", l.Subscription).Scan(&n); e != nil {
				a.deviceLinkFailure(w, e)
				return
			}
			if n >= 4 {
				a.fail(w, 409, "ACCOUNT_IMAGE_LIMIT")
				return
			}
			if _, e = tx.Exec(r.Context(), "INSERT INTO club_bootstraps(id,secret_hash,subscription_id,account_id,name,expires_at) VALUES($1,$2,$3,$4,$5,$6)", l.ID, l.BootstrapHash, l.Subscription, l.Account, l.Name, time.Now().Add(clubBootstrapLifetime)); e != nil {
				a.deviceLinkFailure(w, e)
				return
			}
		}
		var revoked bool
		if e = tx.QueryRow(r.Context(), "SELECT revoked FROM club_bootstraps WHERE id=$1", l.ID).Scan(&revoked); e != nil {
			a.deviceLinkFailure(w, e)
			return
		}
		if revoked {
			a.fail(w, 403, "ACCOUNT_IMAGE_REVOKED")
			return
		}
		out.BootstrapID = l.ID
	} else {
		pub, e := securityPublic(l.PublicKey)
		if e != nil {
			a.deviceLinkFailure(w, e)
			return
		}
		if e = enrollSlotTx(r.Context(), tx, sub.Code, sub.Limit, l.Machine, Device{ID: l.Device, Name: l.Name, PublicKey: l.PublicKey}, a.Settings.KeyID, a.Settings.SigningKey, a.deviceTrust(), l.Account); e != nil {
			a.deviceLinkFailure(w, e)
			return
		}
		der, e := issueClientCertificate(a.Settings.CA, a.Settings.CAKey, pub, time.Now())
		if e != nil {
			a.deviceLinkFailure(w, e)
			return
		}
		out.Enrollment = &enrollment.Response{ProbeToken: a.Settings.EnrollmentProbeToken, DeviceID: l.Device, Certificate: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), Trust: a.deviceTrust()}
	}
	if _, e = tx.Exec(r.Context(), "UPDATE account_device_links SET completed=true WHERE id=$1", l.ID); e != nil {
		a.deviceLinkFailure(w, e)
		return
	}
	if e = tx.Commit(r.Context()); e != nil {
		a.deviceLinkFailure(w, e)
		return
	}
	respond(w, 200, out)
}
func securityPublic(s string) (ed25519.PublicKey, error) {
	b, e := base64.RawURLEncoding.DecodeString(s)
	if e != nil || len(b) != ed25519.PublicKeySize {
		return nil, errors.New("ACCOUNT_LINK_INVALID")
	}
	return ed25519.PublicKey(b), nil
}
func (a *API) deviceTrust() map[string]string {
	return map[string]string{a.Settings.KeyID: base64.RawURLEncoding.EncodeToString(a.Settings.SigningKey.Public().(ed25519.PublicKey))}
}
func (a *API) deviceLinkFailure(w http.ResponseWriter, e error) {
	code, status := "ACCOUNT_LINK_UNAVAILABLE", 503
	switch e.Error() {
	case "ACCOUNT_LINK_INVALID", "ACCOUNT_LINK_EXPIRED", "ACCOUNT_SUBSCRIPTION_REQUIRED", "ACCOUNT_DEVICE_ALREADY_OWNED", "ACCOUNT_IMAGE_REVOKED", "SUBSCRIPTION_EXPIRED", "ACTIVATION_LIMIT", "MACHINE_DISABLED", "ACTIVATION_IDENTITY_CONFLICT":
		code = e.Error()
		status = 403
	case "ACTIVATION_RATE_LIMIT":
		code = e.Error()
		status = 429
	}
	a.fail(w, status, code)
}
func (a *API) accountDeviceLink(w http.ResponseWriter, r *http.Request) {
	if !a.accountRequest(w, r) {
		return
	}
	account, _, ok := a.session(w, r)
	if !ok {
		return
	}
	parts := strings.Split(strings.Trim(strings.TrimPrefix(r.URL.Path, "/api/v1/account/device-links/"), "/"), "/")
	if len(parts) < 1 || !enrollment.AccountLinkID(parts[0]) {
		a.fail(w, 404, "ACCOUNT_LINK_INVALID")
		return
	}
	if r.Method == "POST" && len(parts) == 2 && parts[1] == "approve" {
		var q struct {
			Subscription string `json:"subscription_id"`
		}
		if body(r, &q) != nil || !enrollment.AccountLinkID(q.Subscription) {
			a.fail(w, 400, "ACCOUNT_SUBSCRIPTION_REQUIRED")
			return
		}
		if e := a.Store.approveDeviceLink(r.Context(), account, parts[0], q.Subscription, true); e != nil {
			a.deviceLinkFailure(w, e)
			return
		}
		respond(w, 200, map[string]string{"state": "APPROVED"})
		return
	}
	if r.Method != "GET" || len(parts) != 1 {
		a.fail(w, 405, "ACCOUNT_LINK_INVALID")
		return
	}
	var name, mode, owner string
	var expires time.Time
	e := a.Store.DB.QueryRow(r.Context(), "SELECT name,mode,expires_at,coalesce(account_id,'') FROM account_device_links WHERE id=$1", parts[0]).Scan(&name, &mode, &expires, &owner)
	if e != nil || !expires.After(time.Now()) || owner != "" && owner != account.ID {
		a.fail(w, 404, "ACCOUNT_LINK_EXPIRED")
		return
	}
	respond(w, 200, map[string]any{"name": name, "mode": mode, "expires_at": expires, "approved": owner != ""})
}
func (a *API) enrollClub(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if !a.accountLinkAvailable() {
		a.fail(w, 503, "ACCOUNT_NOT_CONFIGURED")
		return
	}
	if !a.enrollIP.allow(time.Now(), sourceKey(r)) {
		a.fail(w, 429, "ACTIVATION_RATE_LIMIT")
		return
	}
	var q enrollment.ClubEnrollmentRequest
	if body(r, &q) != nil || q.Mode != "device" {
		a.fail(w, 400, "ACCOUNT_LINK_INVALID")
		return
	}
	pub, e := q.Validate(time.Now())
	if e != nil {
		a.fail(w, 400, "ACCOUNT_LINK_INVALID")
		return
	}
	hash, _ := enrollment.AccountSecretHash(q.Secret)
	tx, e := a.Store.DB.Begin(r.Context())
	if e != nil {
		a.deviceLinkFailure(w, e)
		return
	}
	defer tx.Rollback(r.Context())
	if _, e = tx.Exec(r.Context(), "SELECT pg_advisory_xact_lock(724220)"); e != nil {
		a.deviceLinkFailure(w, e)
		return
	}
	var account, sub string
	var stored []byte
	var revoked bool
	var expires time.Time
	e = tx.QueryRow(r.Context(), "SELECT account_id,subscription_id,secret_hash,revoked,expires_at FROM club_bootstraps WHERE id=$1 FOR UPDATE", q.ID).Scan(&account, &sub, &stored, &revoked, &expires)
	if e != nil || subtle.ConstantTimeCompare(hash, stored) != 1 || revoked || !expires.After(time.Now()) {
		a.fail(w, 403, "ACCOUNT_IMAGE_REVOKED")
		return
	}
	binding, e := accountSubscriptionTx(r.Context(), tx, account, sub, true)
	if e != nil {
		a.deviceLinkFailure(w, e)
		return
	}
	if binding.Binding.Kind != "club" {
		a.fail(w, 403, "ACCOUNT_SUBSCRIPTION_REQUIRED")
		return
	}
	if e = enrollSlotTx(r.Context(), tx, binding.Code, binding.Limit, q.Device.MachineHash, Device{ID: q.Device.DeviceID, Name: "Клубный ПК", PublicKey: base64.RawURLEncoding.EncodeToString(pub)}, a.Settings.KeyID, a.Settings.SigningKey, a.deviceTrust(), account); e != nil {
		a.deviceLinkFailure(w, e)
		return
	}
	der, e := issueClientCertificate(a.Settings.CA, a.Settings.CAKey, pub, time.Now())
	if e != nil {
		a.deviceLinkFailure(w, e)
		return
	}
	if e = tx.Commit(r.Context()); e != nil {
		a.deviceLinkFailure(w, e)
		return
	}
	respond(w, 201, enrollment.Response{Account: &binding.Binding, ProbeToken: a.Settings.EnrollmentProbeToken, DeviceID: q.Device.DeviceID, Certificate: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), Trust: a.deviceTrust()})
}
func (a *API) accountProfile(w http.ResponseWriter, r *http.Request) {
	if !a.accountRequest(w, r) {
		return
	}
	account, _, ok := a.session(w, r)
	if !ok {
		return
	}
	var q struct {
		Kind string `json:"kind"`
		Name string `json:"name"`
	}
	if body(r, &q) != nil || (q.Kind != "player" && q.Kind != "club") {
		a.fail(w, 400, "ACCOUNT_PROFILE_INVALID")
		return
	}
	q.Name = strings.TrimSpace(q.Name)
	if len(q.Name) > 160 || len([]rune(q.Name)) > 80 || strings.IndexFunc(q.Name, unicode.IsControl) >= 0 || q.Kind == "club" && len([]rune(q.Name)) < 2 {
		a.fail(w, 400, "ACCOUNT_PROFILE_INVALID")
		return
	}
	tx, e := a.Store.DB.Begin(r.Context())
	if e != nil {
		a.deviceLinkFailure(w, e)
		return
	}
	defer tx.Rollback(r.Context())
	var id string
	if e = tx.QueryRow(r.Context(), "SELECT id FROM accounts WHERE id=$1 AND NOT disabled FOR UPDATE", account.ID).Scan(&id); e != nil {
		a.deviceLinkFailure(w, e)
		return
	}
	var conflict bool
	if e = tx.QueryRow(r.Context(), "SELECT EXISTS(SELECT 1 FROM subscriptions WHERE account_id=$1 AND kind<>$2)", account.ID, q.Kind).Scan(&conflict); e != nil {
		a.deviceLinkFailure(w, e)
		return
	}
	if conflict {
		a.fail(w, 409, "ACCOUNT_PROFILE_CONFLICT")
		return
	}
	if _, e = tx.Exec(r.Context(), "UPDATE accounts SET account_type=$2,display_name=$3 WHERE id=$1", account.ID, q.Kind, q.Name); e != nil {
		a.deviceLinkFailure(w, e)
		return
	}
	if e = tx.Commit(r.Context()); e != nil {
		a.deviceLinkFailure(w, e)
		return
	}
	respond(w, 200, map[string]string{"kind": q.Kind, "name": q.Name})
}

func (a *API) accountClubImages(w http.ResponseWriter, r *http.Request) {
	if !a.accountRequest(w, r) {
		return
	}
	account, _, ok := a.session(w, r)
	if !ok {
		return
	}
	path := strings.Trim(strings.TrimPrefix(r.URL.Path, "/api/v1/account/club-images"), "/")
	if r.Method == "GET" && path == "" {
		rows, e := a.Store.DB.Query(r.Context(), "SELECT id,subscription_id,name,expires_at,revoked FROM club_bootstraps WHERE account_id=$1 ORDER BY created_at DESC LIMIT 81", account.ID)
		if e != nil {
			a.deviceLinkFailure(w, e)
			return
		}
		defer rows.Close()
		out := []map[string]any{}
		for rows.Next() {
			var id, sub, name string
			var expires time.Time
			var revoked bool
			if e = rows.Scan(&id, &sub, &name, &expires, &revoked); e != nil {
				a.deviceLinkFailure(w, e)
				return
			}
			out = append(out, map[string]any{"id": id, "subscription_id": sub, "name": name, "expires_at": expires, "revoked": revoked})
		}
		if rows.Err() != nil {
			a.deviceLinkFailure(w, rows.Err())
			return
		}
		if len(out) > 80 {
			a.fail(w, 503, "ACCOUNT_IMAGE_LIST_LIMIT")
			return
		}
		respond(w, 200, map[string]any{"images": out})
		return
	}
	parts := strings.Split(path, "/")
	if r.Method != "POST" || len(parts) != 2 || parts[1] != "revoke" || !enrollment.AccountLinkID(parts[0]) {
		a.fail(w, 404, "ACCOUNT_LINK_INVALID")
		return
	}
	tag, e := a.Store.DB.Exec(r.Context(), "UPDATE club_bootstraps SET revoked=true WHERE id=$1 AND account_id=$2", parts[0], account.ID)
	if e != nil {
		a.deviceLinkFailure(w, e)
		return
	}
	if tag.RowsAffected() != 1 {
		a.fail(w, 404, "ACCOUNT_LINK_INVALID")
		return
	}
	respond(w, 200, map[string]string{"state": "REVOKED"})
}
