package controlplane

import (
	"errors"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5"
)

// Refresh only a payment owned by the authenticated account. A database claim
// limits provider calls across tabs/processes, without holding a SQL transaction
// open during network I/O. A timeout leaves the original order unchanged.
func (a *API) paymentRefresh(w http.ResponseWriter, r *http.Request) {
	if !a.accountRequest(w, r) {
		return
	}
	acc, _, ok := a.session(w, r)
	if !ok {
		return
	}
	checker, ok := a.Settings.Payments.(PaymentStatusProvider)
	if !ok {
		a.fail(w, 503, "PAYMENT_NOT_CONFIGURED")
		return
	}
	id := r.PathValue("id")
	var provider, providerID string
	e := a.Store.DB.QueryRow(r.Context(), `SELECT p.provider,p.provider_payment_id FROM payments p JOIN subscriptions s ON s.id=p.subscription_id WHERE p.id=$1 AND s.account_id=$2`, id, acc.ID).Scan(&provider, &providerID)
	if errors.Is(e, pgx.ErrNoRows) {
		a.fail(w, 404, "PAYMENT_NOT_FOUND")
		return
	}
	if e != nil {
		a.fail(w, 503, "ACCOUNT_UNAVAILABLE")
		return
	}
	if provider != a.Settings.Payments.Name() {
		a.fail(w, 409, "PAYMENT_REFRESH_UNAVAILABLE")
		return
	}
	result, e := a.Store.DB.Exec(r.Context(), `UPDATE payments SET last_checked_at=now() WHERE id=$1 AND (last_checked_at IS NULL OR last_checked_at<now()-interval '15 seconds')`, id)
	if e != nil {
		a.fail(w, 503, "ACCOUNT_UNAVAILABLE")
		return
	}
	if result.RowsAffected() == 0 {
		a.fail(w, 429, "PAYMENT_CHECK_TOO_SOON")
		return
	}
	ev, e := checker.CheckPayment(r.Context(), providerID)
	if e != nil {
		a.fail(w, 502, "PAYMENT_CHECK_UNAVAILABLE")
		return
	}
	if ev.ProviderID != providerID {
		a.fail(w, 502, "PAYMENT_EVENT_REJECTED")
		return
	}
	_, _, e = a.Store.RecordProviderPayment(r.Context(), provider, providerID, ev.Subscription, ev.AmountKopecks, ev.Status, "payment-check:"+acc.ID, time.Now(), ev)
	if e != nil {
		switch e.Error() {
		case "PAYMENT_MISMATCH", "PAYMENT_INVALID", "PAYMENT_UNKNOWN":
			a.fail(w, 409, e.Error())
		default:
			a.fail(w, 503, "ACCOUNT_UNAVAILABLE")
		}
		return
	}
	// Report the authoritative stored status, which may have advanced concurrently.
	var status string
	var review bool
	e = a.Store.DB.QueryRow(r.Context(), `SELECT status,EXISTS(SELECT 1 FROM payment_review_events WHERE payment_id=$1) FROM payments WHERE id=$1`, id).Scan(&status, &review)
	if e != nil {
		a.fail(w, 503, "ACCOUNT_UNAVAILABLE")
		return
	}
	respond(w, 200, map[string]any{"status": status, "review_required": review})
}
