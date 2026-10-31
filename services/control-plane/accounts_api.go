package controlplane

import (
	"context"
	"errors"
	"net/http"
	"net/mail"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

const sessionCookie = "veliq_session"

// PaymentProvider is the seam for card/SBP acquiring. A provider verifies the
// authenticity of its own notifications; the store keeps crediting idempotent.
type PaymentProvider interface {
	Name() string
	CreatePayment(ctx context.Context, q PaymentRequest) (redirectURL, providerID string, err error)
	HandleWebhook(r *http.Request) (PaymentEvent, error)
}
type PaymentRequest struct {
	Subscription  string
	AmountKopecks int64
	PeriodDays    int
	Description   string
	Email         string
	AccountID     string
	ReturnURL     string
	SaveMethod    bool
}
type PaymentEvent struct {
	ProviderID    string
	Subscription  string
	AmountKopecks int64
	PeriodDays    int
	Status        string
}

func normalizeEmail(raw string) (string, bool) {
	raw = strings.ToLower(strings.TrimSpace(raw))
	if len(raw) < 3 || len(raw) > 254 {
		return "", false
	}
	a, e := mail.ParseAddress(raw)
	if e != nil || a.Address != raw || a.Name != "" || !strings.Contains(raw[strings.LastIndex(raw, "@")+1:], ".") {
		return "", false
	}
	return raw, true
}

// accountRequest guards every cabinet call: the feature must be configured,
// and state-changing calls must come from the cabinet page itself.
func (a *API) accountRequest(w http.ResponseWriter, r *http.Request) bool {
	if a.Settings.AccountOrigin == "" {
		a.fail(w, 503, "ACCOUNT_NOT_CONFIGURED")
		return false
	}
	if r.Method != "GET" {
		if !strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") || r.Header.Get("Origin") != a.Settings.AccountOrigin {
			a.fail(w, 403, "ACCOUNT_ORIGIN_REJECTED")
			return false
		}
	}
	w.Header().Set("Cache-Control", "no-store")
	return true
}

func (a *API) session(w http.ResponseWriter, r *http.Request) (Account, string, bool) {
	c, e := r.Cookie(sessionCookie)
	if e != nil || len(c.Value) != 43 {
		a.fail(w, 401, "ACCOUNT_LOGIN_REQUIRED")
		return Account{}, "", false
	}
	acc, e := a.Store.SessionAccount(r.Context(), c.Value, time.Now())
	if errors.Is(e, pgx.ErrNoRows) {
		a.fail(w, 401, "ACCOUNT_LOGIN_REQUIRED")
		return Account{}, "", false
	}
	if e != nil {
		a.fail(w, 503, "ACCOUNT_UNAVAILABLE")
		return Account{}, "", false
	}
	return acc, c.Value, true
}

func setSession(w http.ResponseWriter, token string, maxAge int) {
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: token, Path: "/api/v1/account", MaxAge: maxAge, HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode})
}

func (a *API) loginStart(w http.ResponseWriter, r *http.Request) {
	if !a.accountRequest(w, r) {
		return
	}
	if a.Settings.Mailer == nil {
		a.fail(w, 503, "MAIL_NOT_CONFIGURED")
		return
	}
	if !a.loginIP.allow(time.Now(), sourceKey(r)) {
		a.fail(w, 429, "ACCOUNT_RATE_LIMIT")
		return
	}
	var q struct {
		Email string `json:"email"`
	}
	email, ok := "", false
	if body(r, &q) == nil {
		email, ok = normalizeEmail(q.Email)
	}
	if !ok {
		a.fail(w, 400, "EMAIL_INVALID")
		return
	}
	code, sent, e := a.Store.StartLogin(r.Context(), email, time.Now())
	if e != nil {
		a.fail(w, 503, "ACCOUNT_UNAVAILABLE")
		return
	}
	if sent {
		text := "Код для входа в личный кабинет VELIQ: " + code + "\n\nКод действует 10 минут. Если вы не входили в кабинет, просто удалите это письмо."
		if e = a.Settings.Mailer.Send(r.Context(), email, "Код для входа: "+code, text); e != nil {
			a.fail(w, 503, "MAIL_UNAVAILABLE")
			return
		}
	}
	// The same answer for new and known addresses and for a throttled resend.
	respond(w, 200, map[string]string{"status": "sent"})
}

func (a *API) loginVerify(w http.ResponseWriter, r *http.Request) {
	if !a.accountRequest(w, r) {
		return
	}
	if !a.loginIP.allow(time.Now(), sourceKey(r)) {
		a.fail(w, 429, "ACCOUNT_RATE_LIMIT")
		return
	}
	var q struct {
		Email string `json:"email"`
		Code  string `json:"code"`
	}
	email, ok := "", false
	if body(r, &q) == nil {
		email, ok = normalizeEmail(q.Email)
	}
	q.Code = strings.TrimSpace(q.Code)
	if !ok || len(q.Code) != 6 {
		a.fail(w, 401, "LOGIN_CODE_INVALID")
		return
	}
	acc, token, e := a.Store.FinishLogin(r.Context(), email, q.Code, time.Now())
	if e != nil {
		switch e.Error() {
		case "LOGIN_CODE_INVALID":
			a.fail(w, 401, "LOGIN_CODE_INVALID")
		case "ACCOUNT_DISABLED":
			a.fail(w, 403, "ACCOUNT_DISABLED")
		default:
			a.fail(w, 503, "ACCOUNT_UNAVAILABLE")
		}
		return
	}
	setSession(w, token, int(SessionLifetime.Seconds()))
	respond(w, 200, map[string]string{"email": acc.Email})
}

func (a *API) logout(w http.ResponseWriter, r *http.Request) {
	if !a.accountRequest(w, r) {
		return
	}
	if c, e := r.Cookie(sessionCookie); e == nil {
		_ = a.Store.EndSession(r.Context(), c.Value)
	}
	setSession(w, "", -1)
	respond(w, 200, map[string]string{"status": "ok"})
}

func (a *API) accountView(w http.ResponseWriter, r *http.Request) {
	if !a.accountRequest(w, r) {
		return
	}
	acc, _, ok := a.session(w, r)
	if !ok {
		return
	}
	subs, e := a.Store.AccountSubscriptions(r.Context(), acc, time.Now())
	if e != nil {
		a.fail(w, 503, "ACCOUNT_UNAVAILABLE")
		return
	}
	pays, e := a.Store.AccountPayments(r.Context(), acc)
	if e != nil {
		a.fail(w, 503, "ACCOUNT_UNAVAILABLE")
		return
	}
	respond(w, 200, map[string]any{"email": acc.Email, "subscriptions": subs, "payments": pays, "plans": a.Settings.Plans, "payments_enabled": a.Settings.Payments != nil})
}

func (a *API) subscriptionCreate(w http.ResponseWriter, r *http.Request) {
	if !a.accountRequest(w, r) {
		return
	}
	acc, _, ok := a.session(w, r)
	if !ok {
		return
	}
	var q struct {
		PlanID string `json:"plan_id"`
		Seats  int    `json:"seats"`
	}
	if body(r, &q) != nil {
		a.fail(w, 400, "SUBSCRIPTION_INVALID")
		return
	}
	p, found := a.plan(q.PlanID)
	if !found {
		a.fail(w, 400, "SUBSCRIPTION_INVALID")
		return
	}
	id, e := a.Store.CreateSubscription(r.Context(), acc, p, q.Seats)
	if e != nil {
		switch e.Error() {
		case "SUBSCRIPTION_INVALID", "SUBSCRIPTION_LIMIT":
			a.fail(w, 400, e.Error())
		default:
			a.fail(w, 503, "ACCOUNT_UNAVAILABLE")
		}
		return
	}
	respond(w, 201, map[string]string{"id": id})
}

// subscriptionAction serves /api/v1/account/subscriptions/{id}/{code|pay|auto-renew|devices/{machine}/release}.
func (a *API) subscriptionAction(w http.ResponseWriter, r *http.Request) {
	if !a.accountRequest(w, r) {
		return
	}
	acc, _, ok := a.session(w, r)
	if !ok {
		return
	}
	parts := strings.Split(strings.Trim(strings.TrimPrefix(r.URL.Path, "/api/v1/account/subscriptions/"), "/"), "/")
	if len(parts) < 2 || len(parts[0]) != 32 {
		a.fail(w, 404, "SUBSCRIPTION_NOT_FOUND")
		return
	}
	id := parts[0]
	switch {
	case len(parts) == 2 && parts[1] == "code":
		code, e := a.Store.IssueSubscriptionCode(r.Context(), acc, id)
		if e != nil {
			a.storeFail(w, e)
			return
		}
		respond(w, 200, map[string]string{"code": code})
	case len(parts) == 2 && parts[1] == "auto-renew":
		var q struct {
			Enabled bool `json:"enabled"`
		}
		if body(r, &q) != nil {
			a.fail(w, 400, "SUBSCRIPTION_INVALID")
			return
		}
		if e := a.Store.SetAutoRenew(r.Context(), acc, id, q.Enabled); e != nil {
			a.storeFail(w, e)
			return
		}
		respond(w, 200, map[string]bool{"auto_renew": q.Enabled})
	case len(parts) == 4 && parts[1] == "devices" && parts[3] == "release":
		if e := a.Store.ReleaseSeat(r.Context(), acc, id, parts[2], a.Settings.KeyID, a.Settings.SigningKey, a.trust()); e != nil {
			a.storeFail(w, e)
			return
		}
		respond(w, 200, map[string]string{"status": "released"})
	case len(parts) == 2 && parts[1] == "pay":
		a.pay(w, r, acc, id)
	default:
		a.fail(w, 404, "SUBSCRIPTION_NOT_FOUND")
	}
}

func (a *API) storeFail(w http.ResponseWriter, e error) {
	switch e.Error() {
	case "SUBSCRIPTION_NOT_FOUND", "SEAT_NOT_FOUND":
		a.fail(w, 404, e.Error())
	default:
		a.fail(w, 503, "ACCOUNT_UNAVAILABLE")
	}
}

func (a *API) pay(w http.ResponseWriter, r *http.Request, acc Account, id string) {
	if a.Settings.Payments == nil {
		a.fail(w, 503, "PAYMENT_NOT_CONFIGURED")
		return
	}
	subs, e := a.Store.AccountSubscriptions(r.Context(), acc, time.Now())
	if e != nil {
		a.fail(w, 503, "ACCOUNT_UNAVAILABLE")
		return
	}
	var sub *Subscription
	for i := range subs {
		if subs[i].ID == id {
			sub = &subs[i]
		}
	}
	if sub == nil {
		a.fail(w, 404, "SUBSCRIPTION_NOT_FOUND")
		return
	}
	p, found := a.plan(sub.PlanID)
	if !found || p.PricePerSeatRub == 0 {
		a.fail(w, 409, "PRICE_NOT_SET")
		return
	}
	var q struct {
		AutoRenew bool `json:"auto_renew"`
	}
	_ = body(r, &q)
	amount := p.PricePerSeatRub * int64(sub.Seats) * 100
	redirect, providerID, e := a.Settings.Payments.CreatePayment(r.Context(), PaymentRequest{Subscription: id, AmountKopecks: amount, PeriodDays: p.PeriodDays, Description: "Подписка VELIQ «" + p.Title + "»", Email: acc.Email, AccountID: acc.ID, ReturnURL: a.Settings.AccountOrigin + "/account.html", SaveMethod: q.AutoRenew})
	if e != nil {
		if errors.Is(e, ErrAutoRenewUnavailable) {
			a.fail(w, 409, "PAYMENT_AUTORENEW_UNAVAILABLE")
			return
		}
		a.fail(w, 502, "PAYMENT_UNAVAILABLE")
		return
	}
	if _, _, e = a.Store.RecordPayment(r.Context(), id, a.Settings.Payments.Name(), providerID, amount, p.PeriodDays, "pending", "", "account:"+acc.ID, time.Now()); e != nil {
		a.fail(w, 503, "ACCOUNT_UNAVAILABLE")
		return
	}
	respond(w, 200, map[string]string{"redirect": redirect})
}

func (a *API) paymentWebhook(w http.ResponseWriter, r *http.Request) {
	if a.Settings.Payments == nil {
		a.fail(w, 404, "PAYMENT_NOT_CONFIGURED")
		return
	}
	ev, e := a.Settings.Payments.HandleWebhook(r)
	if errors.Is(e, ErrPaymentEventIgnored) {
		// Authentic but not actionable (e.g. PARTIALLY_REFUNDED): acknowledge so
		// the provider stops retrying, record nothing.
		respond(w, 200, map[string]string{"status": "ignored"})
		return
	}
	if e != nil {
		a.fail(w, 400, "PAYMENT_EVENT_REJECTED")
		return
	}
	// The store credits against the pending row created at payment time: an
	// unknown provider id or an amount that differs from that row is rejected,
	// and the row itself decides the credited sum and period.
	_, _, e = a.Store.RecordProviderPayment(r.Context(), a.Settings.Payments.Name(), ev.ProviderID, ev.AmountKopecks, ev.Status, "payment:"+a.Settings.Payments.Name(), time.Now())
	if e != nil {
		switch e.Error() {
		case "PAYMENT_UNKNOWN", "PAYMENT_MISMATCH", "PAYMENT_INVALID":
			a.fail(w, 400, e.Error())
		default:
			// A retry from the provider will deliver it again.
			a.fail(w, 503, "ACCOUNT_UNAVAILABLE")
		}
		return
	}
	respond(w, 200, map[string]string{"status": "ok"})
}
