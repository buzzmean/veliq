package controlplane

import (
	"net/http"
	"strings"
	"time"
)

// An uncertain create result is never retried. An operator may locate its ID in
// the provider dashboard and ask the server to verify it before binding/crediting.
// A canceled result remains reserved: cancellation is not proof that a link can
// never be paid. This endpoint cannot release capacity or reset a spent code.
func (a *API) reconcilePromotion(w http.ResponseWriter, r *http.Request) {
	if !a.admin(r) {
		a.fail(w, 401, "UNAUTHORIZED")
		return
	}
	var q struct {
		PaymentID  string `json:"payment_id"`
		ProviderID string `json:"provider_payment_id"`
	}
	if body(r, &q) != nil || !subIDFormat.MatchString(q.PaymentID) || q.ProviderID == "" || len(q.ProviderID) > 128 || strings.HasPrefix(q.ProviderID, "reservation:") {
		a.fail(w, 400, "PAYMENT_INVALID")
		return
	}
	checker, ok := a.Settings.Payments.(PaymentStatusProvider)
	if !ok {
		a.fail(w, 503, "PAYMENT_NOT_CONFIGURED")
		return
	}
	var sub, provider, old string
	var amount int64
	var personal bool
	e := a.Store.DB.QueryRow(r.Context(), `SELECT p.subscription_id,p.provider,p.provider_payment_id,p.amount_kopecks,
 EXISTS(SELECT 1 FROM personal_payment_orders o WHERE o.payment_id=p.id)
 FROM payments p LEFT JOIN promotion_reservations r ON r.payment_id=p.id WHERE p.id=$1 AND
 (r.id IS NOT NULL OR p.reference LIKE 'club-order;%' OR EXISTS(SELECT 1 FROM club_payment_orders o WHERE o.payment_id=p.id)
 OR EXISTS(SELECT 1 FROM personal_payment_orders o WHERE o.payment_id=p.id))`, q.PaymentID).Scan(&sub, &provider, &old, &amount, &personal)
	if e != nil || provider != a.Settings.Payments.Name() || (old != "reservation:"+q.PaymentID && old != q.ProviderID) {
		a.fail(w, 409, "PAYMENT_MISMATCH")
		return
	}
	ev, e := checker.CheckPayment(r.Context(), q.ProviderID)
	if e != nil {
		a.fail(w, 502, "PAYMENT_CHECK_UNAVAILABLE")
		return
	}
	if ev.ProviderID != q.ProviderID || ev.Subscription != sub || ev.AmountKopecks != amount {
		a.fail(w, 409, "PAYMENT_MISMATCH")
		return
	}
	if old != q.ProviderID {
		if personal {
			e = a.Store.AttachPersonalPayment(r.Context(), q.PaymentID, provider, q.ProviderID, "")
		} else {
			e = a.Store.AttachPromotionPayment(r.Context(), q.PaymentID, provider, q.ProviderID)
		}
		if e != nil {
			a.fail(w, 409, "PAYMENT_MISMATCH")
			return
		}
	}
	_, _, e = a.Store.RecordProviderPayment(r.Context(), provider, q.ProviderID, sub, amount, ev.Status, "payment-reconcile:admin", time.Now(), ev)
	if e != nil {
		a.fail(w, 503, "ACCOUNT_UNAVAILABLE")
		return
	}
	var status, state string
	e = a.Store.DB.QueryRow(r.Context(), "SELECT p.status,coalesce(r.state,'not-applicable') FROM payments p LEFT JOIN promotion_reservations r ON r.payment_id=p.id WHERE p.id=$1", q.PaymentID).Scan(&status, &state)
	if e != nil {
		a.fail(w, 503, "ACCOUNT_UNAVAILABLE")
		return
	}
	respond(w, 200, map[string]string{"status": status, "promotion_state": state})
}
