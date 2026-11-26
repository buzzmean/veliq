package controlplane

import (
	"context"
	"crypto/subtle"
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/buzzmean/veliq/core/enrollment"
	"github.com/jackc/pgx/v5"
)

var (
	errClubPaymentRequired     = errors.New("CLUB_PAYMENT_REQUIRED")
	errClubVerificationPending = errors.New("CLUB_VERIFICATION_PENDING")
	errClubVerificationExpired = errors.New("SUBSCRIPTION_EXPIRED")
)

func checkClubVerification(ctx context.Context, tx pgx.Tx, subscription string) (bool, error) {
	var state string
	err := tx.QueryRow(ctx, "SELECT state FROM club_verification_status WHERE subscription_id=$1", subscription).Scan(&state)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	switch state {
	case "verified":
		return true, nil
	case "expired":
		return true, errClubVerificationExpired
	case "pending":
		return true, errClubVerificationPending
	default:
		return true, errClubPaymentRequired
	}
}

type clubVerificationRequest struct {
	Subscription string `json:"subscription_id"`
	Seats        int    `json:"seats"`
}

func (a *API) authorizeClubVerification(w http.ResponseWriter, r *http.Request) bool {
	w.Header().Set("Cache-Control", "no-store")
	if a.Settings.ClubVerificationToken == "" {
		a.fail(w, http.StatusNotFound, "CLUB_VERIFICATION_DISABLED")
		return false
	}
	value, bearer := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !bearer || subtle.ConstantTimeCompare([]byte(value), []byte(a.Settings.ClubVerificationToken)) != 1 {
		a.fail(w, http.StatusUnauthorized, "CLUB_VERIFICATION_UNAUTHORIZED")
		return false
	}
	return true
}

func (a *API) clubVerificationQueue(w http.ResponseWriter, r *http.Request) {
	if !a.authorizeClubVerification(w, r) {
		return
	}
	rows, err := a.Store.DB.Query(r.Context(), `SELECT subscription_id,seats FROM club_verification_status
		WHERE state='pending' AND notified_at IS NULL ORDER BY subscription_id LIMIT 50`)
	if err != nil {
		a.fail(w, http.StatusServiceUnavailable, "CLUB_VERIFICATION_UNAVAILABLE")
		return
	}
	defer rows.Close()
	requests := []clubVerificationRequest{}
	for rows.Next() {
		var v clubVerificationRequest
		if err = rows.Scan(&v.Subscription, &v.Seats); err != nil {
			break
		}
		requests = append(requests, v)
	}
	if err != nil || rows.Err() != nil {
		a.fail(w, http.StatusServiceUnavailable, "CLUB_VERIFICATION_UNAVAILABLE")
		return
	}
	respond(w, http.StatusOK, map[string]any{"requests": requests})
}

func (a *API) clubVerificationNotified(w http.ResponseWriter, r *http.Request) {
	if !a.authorizeClubVerification(w, r) {
		return
	}
	id := r.PathValue("id")
	if !enrollment.AccountLinkID(id) {
		a.fail(w, http.StatusNotFound, "SUBSCRIPTION_NOT_FOUND")
		return
	}
	result, err := a.Store.DB.Exec(r.Context(), `UPDATE club_verifications SET notified_at=coalesce(notified_at,now())
		WHERE subscription_id=$1 AND EXISTS(SELECT 1 FROM club_verification_status WHERE subscription_id=$1 AND state IN ('pending','verified'))`, id)
	if err != nil {
		a.fail(w, http.StatusServiceUnavailable, "CLUB_VERIFICATION_UNAVAILABLE")
		return
	}
	if result.RowsAffected() != 1 {
		a.fail(w, http.StatusConflict, "CLUB_VERIFICATION_NOT_PENDING")
		return
	}
	respond(w, http.StatusOK, map[string]bool{"notified": true})
}

func (a *API) clubVerificationApprove(w http.ResponseWriter, r *http.Request) {
	if !a.authorizeClubVerification(w, r) {
		return
	}
	id := r.PathValue("id")
	if !enrollment.AccountLinkID(id) {
		a.fail(w, http.StatusNotFound, "SUBSCRIPTION_NOT_FOUND")
		return
	}
	var q struct {
		Operator int64 `json:"operator_id"`
	}
	if body(r, &q) != nil || q.Operator <= 0 {
		a.fail(w, http.StatusBadRequest, "CLUB_VERIFICATION_INVALID")
		return
	}
	ctx := r.Context()
	tx, err := a.Store.DB.Begin(ctx)
	if err != nil {
		a.fail(w, http.StatusServiceUnavailable, "CLUB_VERIFICATION_UNAVAILABLE")
		return
	}
	defer tx.Rollback(ctx)
	var account string
	err = tx.QueryRow(ctx, `SELECT a.id FROM subscriptions s JOIN accounts a ON a.id=s.account_id
		WHERE s.id=$1 AND s.kind='club' AND NOT a.disabled FOR NO KEY UPDATE OF a`, id).Scan(&account)
	if errors.Is(err, pgx.ErrNoRows) {
		a.fail(w, http.StatusNotFound, "SUBSCRIPTION_NOT_FOUND")
		return
	}
	if err != nil {
		a.fail(w, http.StatusServiceUnavailable, "CLUB_VERIFICATION_UNAVAILABLE")
		return
	}
	result, err := tx.Exec(ctx, `UPDATE club_verifications SET approved_at=now()
		WHERE subscription_id=$1 AND approved_at IS NULL
		AND EXISTS(SELECT 1 FROM club_verification_status WHERE subscription_id=$1 AND state='pending')`, id)
	if err != nil {
		a.fail(w, http.StatusServiceUnavailable, "CLUB_VERIFICATION_UNAVAILABLE")
		return
	}
	if result.RowsAffected() == 1 {
		if err = awardClubReferral(ctx, tx, account, id); err != nil {
			a.fail(w, http.StatusServiceUnavailable, "CLUB_VERIFICATION_UNAVAILABLE")
			return
		}
		if _, err = tx.Exec(ctx, "INSERT INTO audit_log(actor,action,entity_id) VALUES($1,'subscription.club_verified',$2)", "club-verification:"+strconv.FormatInt(q.Operator, 10), id); err != nil {
			a.fail(w, http.StatusServiceUnavailable, "CLUB_VERIFICATION_UNAVAILABLE")
			return
		}
	} else {
		gated, checkErr := checkClubVerification(ctx, tx, id)
		if !gated || checkErr != nil {
			a.fail(w, http.StatusConflict, "CLUB_VERIFICATION_NOT_PENDING")
			return
		}
	}
	if err = tx.Commit(ctx); err != nil {
		a.fail(w, http.StatusServiceUnavailable, "CLUB_VERIFICATION_UNAVAILABLE")
		return
	}
	respond(w, http.StatusOK, map[string]bool{"verified": true})
}
