package controlplane

import (
	"context"
	"errors"
	"net/http"
	"regexp"
	"strings"

	"github.com/buzzmean/veliq/core/security"
	"github.com/jackc/pgx/v5"
)

var (
	clubInviteCode           = regexp.MustCompile(`^vi-[0-9a-f]{32}$`)
	errClubInviteInvalid     = errors.New("CLUB_INVITE_INVALID")
	errClubInviteClaimed     = errors.New("CLUB_INVITE_ALREADY_CLAIMED")
	errClubInviteTooLate     = errors.New("CLUB_INVITE_TOO_LATE")
	errClubInviteNotEligible = errors.New("CLUB_INVITE_NOT_ELIGIBLE")
)

const clubReferralCreditPrefix = "vr-"

func clubReferralCode(code string) string {
	code = strings.ToLower(strings.TrimSpace(code))
	if strings.HasPrefix(code, clubReferralCreditPrefix) {
		return code
	}
	return ""
}

const eligibleClubInviter = `EXISTS(
 SELECT 1 FROM accounts a JOIN subscriptions s ON s.account_id=a.id
 JOIN payments p ON p.subscription_id=s.id
 WHERE a.id=$1 AND a.account_type='club' AND NOT a.disabled AND s.kind='club'
 AND p.amount_kopecks>0 AND p.status='succeeded'
 AND NOT EXISTS(SELECT 1 FROM payment_review_events e WHERE e.payment_id=p.id)
 AND (EXISTS(SELECT 1 FROM club_verifications v WHERE v.subscription_id=s.id AND v.approved_at IS NOT NULL)
      OR EXISTS(SELECT 1 FROM promotion_club_approvals v WHERE v.account_id=a.id)))`

// A checkout creates the payment row before calling the acquiring provider.
// This makes the invitation deadline independent of provider callback timing.
const clubReferralCheckoutStarted = `EXISTS(
 SELECT 1 FROM payments p JOIN subscriptions s ON s.id=p.subscription_id
 WHERE s.account_id=$1 AND s.kind='club' AND p.amount_kopecks>0)`

type clubReferralCredit struct {
	Code  string `json:"code"`
	State string `json:"state"`
}

type clubReferralView struct {
	CanInvite      bool                 `json:"can_invite"`
	CanClaim       bool                 `json:"can_claim"`
	Claimed        bool                 `json:"claimed"`
	ClaimEarned    bool                 `json:"claim_earned"`
	InvitationCode string               `json:"invitation_code,omitempty"`
	Credits        []clubReferralCredit `json:"credits"`
}

func (s *Store) clubReferrals(ctx context.Context, account string) (clubReferralView, error) {
	view := clubReferralView{Credits: []clubReferralCredit{}}
	err := s.DB.QueryRow(ctx, `SELECT `+eligibleClubInviter+`, NOT `+clubReferralCheckoutStarted+`,
 EXISTS(SELECT 1 FROM club_referral_claims WHERE invitee_id=$1),
 EXISTS(SELECT 1 FROM club_referral_claims WHERE invitee_id=$1 AND source_payment_id IS NOT NULL),
 coalesce((SELECT code FROM club_referral_links WHERE account_id=$1),'')`, account).
		Scan(&view.CanInvite, &view.CanClaim, &view.Claimed, &view.ClaimEarned, &view.InvitationCode)
	if err != nil {
		return view, err
	}
	view.CanClaim = view.CanClaim && !view.Claimed
	rows, err := s.DB.Query(ctx, `SELECT r.code, CASE
 WHEN reserved.status='succeeded' THEN 'redeemed'
 WHEN r.reserved_payment_id IS NOT NULL THEN 'reserved'
 WHEN source.status<>'succeeded' OR EXISTS(SELECT 1 FROM payment_review_events e WHERE e.payment_id=source.id) THEN 'held'
 ELSE 'available' END
 FROM club_referral_credits r JOIN club_referral_claims c USING(invitee_id)
 JOIN payments source ON source.id=c.source_payment_id
 LEFT JOIN payments reserved ON reserved.id=r.reserved_payment_id
 WHERE r.account_id=$1 ORDER BY r.created_at DESC,r.code`, account)
	if err != nil {
		return view, err
	}
	defer rows.Close()
	for rows.Next() {
		var credit clubReferralCredit
		if err = rows.Scan(&credit.Code, &credit.State); err != nil {
			return view, err
		}
		view.Credits = append(view.Credits, credit)
	}
	return view, rows.Err()
}

func (s *Store) createClubInvitation(ctx context.Context, account string) (string, error) {
	tx, err := s.DB.Begin(ctx)
	if err != nil {
		return "", err
	}
	defer tx.Rollback(ctx)
	if err = lockClubAccount(ctx, tx, account); err != nil {
		return "", err
	}
	var eligible bool
	if err = tx.QueryRow(ctx, `SELECT `+eligibleClubInviter, account).Scan(&eligible); err != nil {
		return "", err
	}
	if !eligible {
		return "", errClubInviteNotEligible
	}
	var code string
	err = tx.QueryRow(ctx, "SELECT code FROM club_referral_links WHERE account_id=$1", account).Scan(&code)
	if errors.Is(err, pgx.ErrNoRows) {
		id, genErr := security.NewID()
		if genErr != nil {
			return "", genErr
		}
		code = "vi-" + id
		_, err = tx.Exec(ctx, "INSERT INTO club_referral_links(account_id,code) VALUES($1,$2)", account, code)
	}
	if err != nil {
		return "", err
	}
	return code, tx.Commit(ctx)
}

func (s *Store) claimClubInvitation(ctx context.Context, account, code string) error {
	if !clubInviteCode.MatchString(code) {
		return errClubInviteInvalid
	}
	tx, err := s.DB.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if err = lockClubAccount(ctx, tx, account); err != nil {
		return err
	}
	var inviter string
	err = tx.QueryRow(ctx, "SELECT account_id FROM club_referral_links WHERE code=$1", code).Scan(&inviter)
	if errors.Is(err, pgx.ErrNoRows) || err == nil && inviter == account {
		return errClubInviteInvalid
	}
	if err != nil {
		return err
	}
	var previous string
	err = tx.QueryRow(ctx, "SELECT inviter_id FROM club_referral_claims WHERE invitee_id=$1", account).Scan(&previous)
	if err == nil {
		if previous == inviter {
			return nil
		}
		return errClubInviteClaimed
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return err
	}
	var eligible, started bool
	if err = tx.QueryRow(ctx, `SELECT `+eligibleClubInviter, inviter).Scan(&eligible); err != nil {
		return err
	}
	if !eligible {
		return errClubInviteInvalid
	}
	if err = tx.QueryRow(ctx, `SELECT `+clubReferralCheckoutStarted, account).Scan(&started); err != nil {
		return err
	}
	if started {
		return errClubInviteTooLate
	}
	if _, err = tx.Exec(ctx, "INSERT INTO club_referral_claims(invitee_id,inviter_id) VALUES($1,$2)", account, inviter); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// Approval and award commit together under the invitee's account lock, which
// also serializes provider confirmations and disputes for the first order.
func awardClubReferral(ctx context.Context, tx pgx.Tx, account, subscription string) error {
	var inviter string
	err := tx.QueryRow(ctx, `WITH first_payment AS (
 SELECT p.id,p.subscription_id FROM payments p JOIN subscriptions s ON s.id=p.subscription_id
 WHERE s.account_id=$1 AND s.kind='club' AND p.status='succeeded' AND p.amount_kopecks>0
 ORDER BY p.created_at,p.id LIMIT 1
 ) UPDATE club_referral_claims c SET source_payment_id=p.id FROM first_payment p
 WHERE c.invitee_id=$1 AND c.source_payment_id IS NULL AND p.subscription_id=$2
 AND NOT EXISTS(SELECT 1 FROM payment_review_events e WHERE e.payment_id=p.id)
 RETURNING c.inviter_id`, account, subscription).Scan(&inviter)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	for _, owner := range []string{account, inviter} {
		id, err := security.NewID()
		if err != nil {
			return err
		}
		if _, err = tx.Exec(ctx, "INSERT INTO club_referral_credits(code,account_id,invitee_id) VALUES($1,$2,$3)", clubReferralCreditPrefix+id, owner, account); err != nil {
			return err
		}
	}
	return nil
}

func checkClubReferralCredit(ctx context.Context, tx pgx.Tx, account, code string) error {
	var reserved *string
	var source string
	var succeeded bool
	err := tx.QueryRow(ctx, `SELECT r.reserved_payment_id,p.id,p.status='succeeded'
 FROM club_referral_credits r JOIN club_referral_claims c USING(invitee_id)
 JOIN payments p ON p.id=c.source_payment_id WHERE r.code=$1 AND r.account_id=$2
 FOR NO KEY UPDATE OF r FOR SHARE OF p`, code, account).Scan(&reserved, &source, &succeeded)
	if errors.Is(err, pgx.ErrNoRows) || err == nil && !succeeded {
		return errors.New("PROMO_INVALID")
	}
	if err != nil {
		return err
	}
	if reserved != nil {
		return errors.New("PROMO_USED")
	}
	// Check review after acquiring the payment lock so a dispute committed
	// while waiting is visible to this transaction.
	var review bool
	if err = tx.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM payment_review_events WHERE payment_id=$1)", source).Scan(&review); err != nil {
		return err
	}
	if review {
		return errors.New("PROMO_INVALID")
	}
	return nil
}

func (a *API) clubInvitation(w http.ResponseWriter, r *http.Request) {
	if !a.accountRequest(w, r) {
		return
	}
	if a.Settings.ClubVerificationToken == "" {
		a.fail(w, http.StatusNotFound, "CLUB_VERIFICATION_DISABLED")
		return
	}
	acc, _, ok := a.session(w, r)
	if !ok {
		return
	}
	var result map[string]any
	var err error
	switch r.PathValue("action") {
	case "link":
		var code string
		code, err = a.Store.createClubInvitation(r.Context(), acc.ID)
		result = map[string]any{"invitation_code": code}
	case "claim":
		var q struct {
			Code string `json:"code"`
		}
		if body(r, &q) != nil {
			a.fail(w, http.StatusBadRequest, errClubInviteInvalid.Error())
			return
		}
		err = a.Store.claimClubInvitation(r.Context(), acc.ID, strings.ToLower(strings.TrimSpace(q.Code)))
		result = map[string]any{"claimed": true}
	default:
		a.fail(w, http.StatusNotFound, "CLUB_INVITE_INVALID")
		return
	}
	if err != nil {
		switch err {
		case errClubInviteInvalid, errClubInviteClaimed, errClubInviteTooLate, errClubInviteNotEligible:
			a.fail(w, http.StatusConflict, err.Error())
		default:
			if err.Error() == "PAYMENT_INVALID" {
				a.fail(w, http.StatusConflict, errClubInviteNotEligible.Error())
			} else {
				a.fail(w, http.StatusServiceUnavailable, "ACCOUNT_UNAVAILABLE")
			}
		}
		return
	}
	respond(w, http.StatusOK, result)
}
