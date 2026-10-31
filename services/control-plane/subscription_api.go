package controlplane

import (
	"crypto/ed25519"
	"encoding/base64"
	"net/http"
	"strings"
	"time"

	"github.com/buzzmean/neexitlag/core/security"
)

// SubscriptionStatus is what a computer learns about its own access. It carries
// no personal data: no email, plan price or other computers.
type SubscriptionStatus struct {
	Managed    bool       `json:"managed"`
	Enforced   bool       `json:"enforced"`
	Active     bool       `json:"active"`
	PaidUntil  *time.Time `json:"paid_until,omitempty"`
	GraceUntil *time.Time `json:"grace_until,omitempty"`
}

func (a *API) trust() map[string]string {
	pub := a.Settings.SigningKey.Public().(ed25519.PublicKey)
	return map[string]string{a.Settings.KeyID: base64.RawURLEncoding.EncodeToString(pub)}
}

func statusFor(ent Entitlement, enforced bool, now time.Time) SubscriptionStatus {
	out := SubscriptionStatus{Managed: ent.Managed, Enforced: enforced, Active: !enforced || ent.Active(now)}
	if ent.Managed {
		until, grace := ent.Until.UTC(), ent.Until.Add(SubscriptionGrace).UTC()
		out.PaidUntil, out.GraceUntil = &until, &grace
	}
	return out
}

// subscriptionStatus answers a signed, single-use device proof bound to its own audience.
func (a *API) subscriptionStatus(w http.ResponseWriter, r *http.Request) {
	var p security.Proof
	if body(r, &p) != nil || p.RelayID != security.SubscriptionAudience {
		a.fail(w, 400, "invalid subscription proof")
		return
	}
	d, e := a.Store.Device(r.Context(), p.DeviceID)
	if e != nil || d.Revoked {
		a.AuthFailures.Add(1)
		a.fail(w, 401, "device unavailable")
		return
	}
	key, e := security.DecodePublicKey(d.PublicKey)
	if e != nil || p.Verify(key, time.Now()) != nil {
		a.AuthFailures.Add(1)
		a.fail(w, 401, "invalid device proof")
		return
	}
	if e = a.Store.ConsumeProof(r.Context(), p); e != nil {
		a.AuthFailures.Add(1)
		a.fail(w, 401, "proof replay or revoked device")
		return
	}
	ent, e := a.Store.DeviceEntitlement(r.Context(), d.ID)
	if e != nil {
		a.fail(w, 503, "SUBSCRIPTION_UNAVAILABLE")
		return
	}
	respond(w, 200, statusFor(ent, a.Settings.EnforceSubscription, time.Now()))
}

// adminSubscriptions: GET list, GET ?cutoff=1 preview of devices enforcement
// would stop now, POST /payments manual (invoice) credit.
func (a *API) adminSubscriptions(w http.ResponseWriter, r *http.Request) {
	if !a.admin(r) {
		a.fail(w, 401, "administrator authorization required")
		return
	}
	switch {
	case r.Method == "GET" && strings.HasSuffix(r.URL.Path, "/cutoff"):
		out, e := a.Store.SubscriptionCutoff(r.Context(), time.Now())
		if e != nil {
			a.fail(w, 503, "SUBSCRIPTION_UNAVAILABLE")
			return
		}
		respond(w, 200, map[string]any{"enforced": a.Settings.EnforceSubscription, "devices": out})
	case r.Method == "GET":
		out, e := a.Store.AdminSubscriptions(r.Context())
		if e != nil {
			a.fail(w, 503, "SUBSCRIPTION_UNAVAILABLE")
			return
		}
		respond(w, 200, map[string]any{"subscriptions": out})
	case r.Method == "POST" && strings.HasSuffix(r.URL.Path, "/payments"):
		var q struct {
			Subscription string `json:"subscription_id"`
			Amount       int64  `json:"amount_kopecks"`
			PeriodDays   int    `json:"period_days"`
			Reference    string `json:"reference"`
		}
		if body(r, &q) != nil || q.Reference == "" {
			a.fail(w, 400, "PAYMENT_INVALID")
			return
		}
		until, extended, e := a.Store.RecordPayment(r.Context(), q.Subscription, "manual", q.Reference, q.Amount, q.PeriodDays, "succeeded", q.Reference, "admin", time.Now())
		if e != nil {
			switch e.Error() {
			case "PAYMENT_INVALID":
				a.fail(w, 400, e.Error())
			case "SUBSCRIPTION_NOT_FOUND":
				a.fail(w, 404, e.Error())
			default:
				a.fail(w, 503, "SUBSCRIPTION_UNAVAILABLE")
			}
			return
		}
		respond(w, 200, map[string]any{"paid_until": until.UTC(), "extended": extended})
	default:
		a.fail(w, 405, "method not allowed")
	}
}
