package controlplane

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"errors"
	"net/http"
	"time"

	"github.com/buzzmean/veliq/core/enrollment"
	"github.com/jackc/pgx/v5"
)

var errTrialUnavailable = errors.New("TRIAL_UNAVAILABLE")

const trialEligibleSQL = `
 (SELECT count(*) FROM subscriptions WHERE account_id=$1) <= 1
 AND NOT EXISTS (
   SELECT 1 FROM subscriptions s
   WHERE s.account_id=$1 AND (s.kind<>'player' OR s.seats<>1 OR s.lifetime OR s.paid_until IS NOT NULL OR s.trial_until IS NOT NULL
     OR EXISTS (SELECT 1 FROM payments p WHERE p.subscription_id=s.id AND p.status='succeeded')
     OR NOT EXISTS (SELECT 1 FROM activation_codes c WHERE c.subscription_id=s.id AND NOT c.revoked AND c.expires_at>now())
     OR EXISTS (SELECT 1 FROM activation_codes c JOIN activation_slots sl ON sl.code_id=c.id
                WHERE c.subscription_id=s.id AND NOT sl.disabled))
 )`

func (s *Store) trialOffer(ctx context.Context, account Account) (string, error) {
	var code string
	err := s.DB.QueryRow(ctx, "SELECT code FROM account_trial_offers WHERE account_id=$1 AND"+trialEligibleSQL, account.ID).Scan(&code)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", nil
	}
	return code, err
}

func (s *Store) activateTrial(ctx context.Context, account Account, plan Plan, code string) (time.Time, error) {
	tx, err := s.DB.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return time.Time{}, err
	}
	defer tx.Rollback(ctx)
	var kind string
	err = tx.QueryRow(ctx, "SELECT account_type FROM accounts WHERE id=$1 AND NOT disabled FOR NO KEY UPDATE", account.ID).Scan(&kind)
	if errors.Is(err, pgx.ErrNoRows) || (err == nil && kind != "player") {
		return time.Time{}, errTrialUnavailable
	}
	if err != nil {
		return time.Time{}, err
	}
	var stored string
	err = tx.QueryRow(ctx, "SELECT code FROM account_trial_offers WHERE account_id=$1", account.ID).Scan(&stored)
	if errors.Is(err, pgx.ErrNoRows) || (err == nil && subtle.ConstantTimeCompare([]byte(code), []byte(stored)) != 1) {
		return time.Time{}, errTrialUnavailable
	}
	if err != nil {
		return time.Time{}, err
	}
	var until time.Time
	err = tx.QueryRow(ctx, "SELECT trial_until FROM subscriptions WHERE account_id=$1 AND trial_until IS NOT NULL", account.ID).Scan(&until)
	if !errors.Is(err, pgx.ErrNoRows) {
		return until, err
	}
	// Serialize the eligibility check with legacy enrollment, which locks its code before using a seat.
	if _, err = tx.Exec(ctx, `SELECT c.id FROM activation_codes c JOIN subscriptions s ON s.id=c.subscription_id
		WHERE s.account_id=$1 FOR UPDATE OF c`, account.ID); err != nil {
		return time.Time{}, err
	}
	var eligible bool
	if err = tx.QueryRow(ctx, "SELECT"+trialEligibleSQL, account.ID).Scan(&eligible); err != nil {
		return time.Time{}, err
	}
	if !eligible {
		return time.Time{}, errTrialUnavailable
	}
	id, err := subscriptionForAccountTx(ctx, tx, account, plan, 1)
	if err != nil {
		return time.Time{}, err
	}
	// Invalidate any unused raw code issued before this account activated its trial.
	var placeholder [32]byte
	if _, err = rand.Read(placeholder[:]); err != nil {
		return time.Time{}, err
	}
	if _, err = tx.Exec(ctx, "UPDATE activation_codes SET code_hash=$2 WHERE subscription_id=$1", id, placeholder[:]); err != nil {
		return time.Time{}, err
	}
	if err = tx.QueryRow(ctx, "UPDATE subscriptions SET trial_until=clock_timestamp()+interval '24 hours' WHERE id=$1 RETURNING trial_until", id).Scan(&until); err != nil {
		return time.Time{}, err
	}
	if _, err = tx.Exec(ctx, "INSERT INTO audit_log(actor,action,entity_id) VALUES($1,'subscription.trial.activate',$2)", "account:"+account.ID, id); err != nil {
		return time.Time{}, err
	}
	return until.UTC(), tx.Commit(ctx)
}

func (a *API) personalTrialPlan() (Plan, bool) {
	if !a.Settings.PersonalTrials || !a.accountLinkAvailable() {
		return Plan{}, false
	}
	var selected Plan
	for _, p := range a.Settings.Plans {
		if p.Kind != "player" || !p.supportsSeats(1) {
			continue
		}
		if selected.ID != "" {
			return Plan{}, false
		}
		selected = p
	}
	return selected, selected.ID != ""
}

func (a *API) trialAvailability(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	_, available := a.personalTrialPlan()
	respond(w, http.StatusOK, map[string]bool{"available": available})
}

func (a *API) trialActivate(w http.ResponseWriter, r *http.Request) {
	if !a.accountRequest(w, r) {
		return
	}
	account, _, ok := a.session(w, r)
	if !ok {
		return
	}
	plan, available := a.personalTrialPlan()
	var req struct {
		Code string `json:"code"`
	}
	if !available || body(r, &req) != nil || !enrollment.AccountLinkID(req.Code) {
		a.fail(w, http.StatusConflict, errTrialUnavailable.Error())
		return
	}
	until, err := a.Store.activateTrial(r.Context(), account, plan, req.Code)
	switch {
	case errors.Is(err, errTrialUnavailable):
		a.fail(w, http.StatusConflict, errTrialUnavailable.Error())
	case err != nil:
		a.fail(w, http.StatusServiceUnavailable, "ACCOUNT_UNAVAILABLE")
	default:
		respond(w, http.StatusOK, map[string]time.Time{"trial_until": until.UTC()})
	}
}
