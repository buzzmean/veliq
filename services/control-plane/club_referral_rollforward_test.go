package controlplane

import (
	"context"
	"crypto/md5"
	"fmt"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

const referralRollforwardOwner = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

func referralRollforwardID(kind string, n int) string {
	return fmt.Sprintf("%x", md5.Sum([]byte(fmt.Sprintf("rollforward-%s-%d", kind, n))))
}

// Сохранённый claim и уже оплаченная/подтверждённая подписка моделируют
// завершившиеся callback+approval прежнего CP, который не знает таблиц015.
func seedReferralRollforward(t *testing.T, s *Store, n int) {
	t.Helper()
	ctx := context.Background()
	if _, err := s.DB.Exec(ctx, `
INSERT INTO accounts(id,email,account_type) VALUES(repeat('a',32),'inviter@example.test','club');
INSERT INTO subscriptions(id,account_id,plan_id,kind,seats,paid_until)
 VALUES('owner-sub',repeat('a',32),'club-month','club',2,now()+interval '30 days');
INSERT INTO payments(id,subscription_id,provider,provider_payment_id,amount_kopecks,period_days,status)
 VALUES('owner-pay','owner-sub','fixture','owner-tx',59800,30,'succeeded');
INSERT INTO club_verifications(subscription_id,approved_at) VALUES('owner-sub',now());
INSERT INTO club_referral_links(account_id,code) VALUES(repeat('a',32),'vi-'||repeat('f',32));`); err != nil {
		t.Fatal(err)
	}
	for _, query := range []string{
		`INSERT INTO accounts(id,email,account_type) SELECT md5('rollforward-invitee-'||i),i||'@rollforward.example.test','club' FROM generate_series(1,$1::int) i`,
		`INSERT INTO subscriptions(id,account_id,plan_id,kind,seats,paid_until) SELECT md5('rollforward-sub-'||i),md5('rollforward-invitee-'||i),'club-month','club',2,now()+interval '30 days' FROM generate_series(1,$1::int) i`,
		`INSERT INTO club_referral_claims(invitee_id,inviter_id) SELECT md5('rollforward-invitee-'||i),repeat('a',32) FROM generate_series(1,$1::int) i`,
		`INSERT INTO payments(id,subscription_id,provider,provider_payment_id,amount_kopecks,period_days,status) SELECT md5('rollforward-pay-'||i),md5('rollforward-sub-'||i),'fixture','rollforward-tx-'||i,59800,30,'succeeded' FROM generate_series(1,$1::int) i`,
		`INSERT INTO club_verifications(subscription_id,approved_at) SELECT md5('rollforward-sub-'||i),now() FROM generate_series(1,$1::int) i`,
	} {
		if _, err := s.DB.Exec(ctx, query, n); err != nil {
			t.Fatal(err)
		}
	}
}

func referralRollforwardFinancialSnapshot(t *testing.T, s *Store) string {
	t.Helper()
	var out string
	if err := s.DB.QueryRow(context.Background(), `SELECT jsonb_build_object(
 'payments',(SELECT jsonb_agg(to_jsonb(p) ORDER BY id) FROM payments p),
 'subscriptions',(SELECT jsonb_agg(to_jsonb(s) ORDER BY id) FROM subscriptions s),
 'orders',(SELECT jsonb_agg(to_jsonb(o) ORDER BY payment_id) FROM club_payment_orders o),
 'reviews',(SELECT jsonb_agg(to_jsonb(e) ORDER BY id) FROM payment_review_events e),
 'approvals',(SELECT jsonb_agg(to_jsonb(v) ORDER BY subscription_id) FROM club_verifications v),
 'audit',(SELECT jsonb_agg(to_jsonb(a) ORDER BY id) FROM audit_log a))::text`).Scan(&out); err != nil {
		t.Fatal(err)
	}
	return out
}

func assertReferralRollforwardAwards(t *testing.T, s *Store, n int) {
	t.Helper()
	var claims, credits, correct int
	if err := s.DB.QueryRow(context.Background(), `SELECT
 (SELECT count(*) FROM club_referral_claims WHERE source_payment_id IS NOT NULL),
 (SELECT count(*) FROM club_referral_credits),
 (SELECT count(*) FROM club_referral_credits r JOIN club_referral_claims c USING(invitee_id)
 WHERE r.account_id IN (c.invitee_id,c.inviter_id))`).Scan(&claims, &credits, &correct); err != nil || claims != n || credits != 2*n || correct != 2*n {
		t.Fatal("Неверное число источников или owner-bound наград", claims, credits, correct, err)
	}
}

func referralRollforwardApprove(api *API, sub string) int {
	r := httptest.NewRequest("POST", "/api/v1/club-verifications/"+sub+"/approve", strings.NewReader(`{"operator_id":42}`))
	r.Header.Set("Authorization", "Bearer "+api.Settings.ClubVerificationToken)
	w := httptest.NewRecorder()
	api.Handler().ServeHTTP(w, r)
	return w.Code
}

func TestClubReferralRollforwardNoReplayAndVerifiedReplay(t *testing.T) {
	for _, mode := range []string{"startup-expired-token-off", "verified-replay"} {
		t.Run(mode, func(t *testing.T) {
			api, s, _ := accountAPI(t, false)
			seedReferralRollforward(t, s, 1)
			if mode == "startup-expired-token-off" {
				if _, err := s.DB.Exec(context.Background(), "UPDATE subscriptions SET paid_until=now()-interval '1 day' WHERE id=$1", referralRollforwardID("sub", 1)); err != nil {
					t.Fatal(err)
				}
			} else {
				api.Settings.ClubVerificationToken = strings.Repeat("v", 32)
			}
			before := referralRollforwardFinancialSnapshot(t, s)
			for range 2 {
				if mode == "verified-replay" {
					if status := referralRollforwardApprove(api, referralRollforwardID("sub", 1)); status != 200 {
						t.Fatal("Повтор подтверждения не принят", status)
					}
				} else if err := s.ReconcileExistingClubReferralAwards(context.Background()); err != nil {
					t.Fatal(err)
				}
				assertReferralRollforwardAwards(t, s, 1)
				if referralRollforwardFinancialSnapshot(t, s) != before {
					t.Fatal("Восстановление изменило финансы, право, approval или audit")
				}
			}
		})
	}
}

func TestClubReferralRollforwardPagesAndGuards(t *testing.T) {
	t.Run("more-than129-and-legacy-blank-kind", func(t *testing.T) {
		s := codeStore(t)
		seedReferralRollforward(t, s, 130)
		if _, err := s.DB.Exec(context.Background(), "UPDATE accounts SET account_type='' WHERE id=$1", referralRollforwardID("invitee", 1)); err != nil {
			t.Fatal(err)
		}
		before := referralRollforwardFinancialSnapshot(t, s)
		for range 2 {
			if err := s.ReconcileExistingClubReferralAwards(context.Background()); err != nil {
				t.Fatal(err)
			}
			assertReferralRollforwardAwards(t, s, 130)
		}
		if referralRollforwardFinancialSnapshot(t, s) != before {
			t.Fatal("Постраничное восстановление изменило финансовые записи")
		}
	})
	t.Run("no-historical-claims-or-ineligible-awards", func(t *testing.T) {
		s := codeStore(t)
		seedReferralRollforward(t, s, 9)
		ctx := context.Background()
		for _, statement := range []struct {
			query string
			args  []any
		}{
			{"DELETE FROM club_referral_claims WHERE invitee_id=$1", []any{referralRollforwardID("invitee", 1)}},
			{"UPDATE club_verifications SET approved_at=NULL WHERE subscription_id=$1", []any{referralRollforwardID("sub", 2)}},
			{"UPDATE payments SET status='pending' WHERE id=$1", []any{referralRollforwardID("pay", 3)}},
			{"UPDATE payments SET status='canceled' WHERE id=$1", []any{referralRollforwardID("pay", 4)}},
			{"INSERT INTO payment_review_events(payment_id,provider_status) VALUES($1,'CHARGEBACKED')", []any{referralRollforwardID("pay", 5)}},
			{"UPDATE accounts SET disabled=true WHERE id=$1", []any{referralRollforwardID("invitee", 6)}},
			{"DELETE FROM payments WHERE id=$1", []any{referralRollforwardID("pay", 7)}},
			{"UPDATE club_verifications SET approved_at=NULL WHERE subscription_id=$1", []any{referralRollforwardID("sub", 8)}},
			{"UPDATE accounts SET account_type='player' WHERE id=$1", []any{referralRollforwardID("invitee", 9)}},
		} {
			if _, err := s.DB.Exec(ctx, statement.query, statement.args...); err != nil {
				t.Fatal(err)
			}
		}
		// Поздний clean платёж не заменяет reviewed первый; approval другой
		// подписки того же аккаунта не подтверждает первую.
		for _, n := range []int{5, 8} {
			if _, err := s.DB.Exec(ctx, `INSERT INTO subscriptions(id,account_id,plan_id,kind,seats,paid_until)
 SELECT $1,account_id,plan_id,kind,seats,paid_until FROM subscriptions WHERE id=$2`, referralRollforwardID("later-sub", n), referralRollforwardID("sub", n)); err != nil {
				t.Fatal(err)
			}
			if _, err := s.DB.Exec(ctx, `INSERT INTO payments(id,subscription_id,provider,provider_payment_id,amount_kopecks,period_days,status,created_at)
 VALUES($1,$2,'fixture',$1,59800,30,'succeeded',now()+interval '1 second')`, referralRollforwardID("later-pay", n), referralRollforwardID("later-sub", n)); err != nil {
				t.Fatal(err)
			}
			if _, err := s.DB.Exec(ctx, "INSERT INTO club_verifications(subscription_id,approved_at) VALUES($1,now())", referralRollforwardID("later-sub", n)); err != nil {
				t.Fatal(err)
			}
		}
		before := referralRollforwardFinancialSnapshot(t, s)
		if err := s.ReconcileExistingClubReferralAwards(ctx); err != nil {
			t.Fatal(err)
		}
		assertReferralRollforwardAwards(t, s, 0)
		var claims int
		if err := s.DB.QueryRow(ctx, "SELECT count(*) FROM club_referral_claims").Scan(&claims); err != nil || claims != 8 || before != referralRollforwardFinancialSnapshot(t, s) {
			t.Fatal("Восстановление создало исторический claim или изменило финансы", claims, err)
		}
	})
}

func TestClubReferralRollforwardConcurrentApprovalAndStartup(t *testing.T) {
	api, s, _ := accountAPI(t, false)
	api.Settings.ClubVerificationToken = strings.Repeat("v", 32)
	seedReferralRollforward(t, s, 1)
	before := referralRollforwardFinancialSnapshot(t, s)
	var wg sync.WaitGroup
	errors := make(chan error, 8)
	for i := range 8 {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			if i%2 == 0 {
				errors <- s.ReconcileExistingClubReferralAwards(context.Background())
			} else if status := referralRollforwardApprove(api, referralRollforwardID("sub", 1)); status != 200 {
				errors <- fmt.Errorf("approval HTTP%d", status)
			} else {
				errors <- nil
			}
		}(i)
	}
	wg.Wait()
	close(errors)
	for err := range errors {
		if err != nil {
			t.Fatal(err)
		}
	}
	assertReferralRollforwardAwards(t, s, 1)
	if referralRollforwardFinancialSnapshot(t, s) != before {
		t.Fatal("Конкурентное восстановление изменило право или повторило audit")
	}
}

func TestClubReferralRollforwardCancellationAndCommitFailure(t *testing.T) {
	s := codeStore(t)
	seedReferralRollforward(t, s, 1)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := s.ReconcileExistingClubReferralAwards(ctx); err == nil {
		t.Fatal("Отменённый запуск принят")
	}
	assertReferralRollforwardAwards(t, s, 0)
	if _, err := s.DB.Exec(context.Background(), `CREATE FUNCTION reject_rollforward_commit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'fixture commit failure'; END $$;
 CREATE CONSTRAINT TRIGGER reject_rollforward_commit AFTER INSERT ON club_referral_credits DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION reject_rollforward_commit()`); err != nil {
		t.Fatal(err)
	}
	before := referralRollforwardFinancialSnapshot(t, s)
	if err := s.ReconcileExistingClubReferralAwards(context.Background()); err == nil {
		t.Fatal("Ошибка commit не возвращена")
	}
	assertReferralRollforwardAwards(t, s, 0)
	if before != referralRollforwardFinancialSnapshot(t, s) {
		t.Fatal("Ошибка commit изменила финансовые записи")
	}
	if _, err := s.DB.Exec(context.Background(), "DROP TRIGGER reject_rollforward_commit ON club_referral_credits"); err != nil {
		t.Fatal(err)
	}
	if err := s.ReconcileExistingClubReferralAwards(context.Background()); err != nil {
		t.Fatal(err)
	}
	assertReferralRollforwardAwards(t, s, 1)
}

func TestClubReferralRollforwardReviewAfterAccountWaitWithRRDefault(t *testing.T) {
	for _, mode := range []string{"startup", "verified-replay"} {
		t.Run(mode, func(t *testing.T) {
			api, base, _ := accountAPI(t, false)
			api.Settings.ClubVerificationToken = strings.Repeat("v", 32)
			seedReferralRollforward(t, base, 1)
			cfg := base.DB.Config()
			cfg.ConnConfig.RuntimeParams["default_transaction_isolation"] = "repeatable read"
			pool, err := pgxpool.NewWithConfig(context.Background(), cfg)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(pool.Close)
			s := &Store{pool}
			api.Store = s
			observer := accountLockObserver(t, s)
			ctx := context.Background()
			barrier, err := observer.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer barrier.Rollback(ctx)
			if _, err = barrier.Exec(ctx, "SELECT id FROM accounts WHERE id=$1 FOR NO KEY UPDATE", referralRollforwardID("invitee", 1)); err != nil {
				t.Fatal(err)
			}
			done := make(chan error, 1)
			go func() {
				if mode == "startup" {
					done <- s.ReconcileExistingClubReferralAwards(ctx)
				} else if status := referralRollforwardApprove(api, referralRollforwardID("sub", 1)); status != 200 {
					done <- fmt.Errorf("approval HTTP%d", status)
				} else {
					done <- nil
				}
			}()
			waitAccountLocks(t, observer, []string{"SELECT id FROM accounts%FOR NO KEY UPDATE", "SELECT a.id FROM subscriptions%FOR NO KEY UPDATE OF a"}, 1, nil)
			if _, err = barrier.Exec(ctx, "INSERT INTO payment_review_events(payment_id,provider_status) VALUES($1,'DISPUTED')", referralRollforwardID("pay", 1)); err != nil {
				t.Fatal(err)
			}
			if err = barrier.Commit(ctx); err != nil {
				t.Fatal(err)
			}
			select {
			case err = <-done:
				if err != nil {
					t.Fatal(err)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("Ожидание account lock не завершилось")
			}
			assertReferralRollforwardAwards(t, s, 0)
		})
	}
}

func TestClubReferralRollforwardPreservesReservedInvoiceAndReviewHold(t *testing.T) {
	s := codeStore(t)
	seedReferralRollforward(t, s, 2)
	ctx := context.Background()
	if _, err := s.DB.Exec(ctx, "UPDATE club_verifications SET approved_at=NULL WHERE subscription_id=$1", referralRollforwardID("sub", 2)); err != nil {
		t.Fatal(err)
	}
	if err := s.ReconcileExistingClubReferralAwards(ctx); err != nil {
		t.Fatal(err)
	}
	invitee := Account{ID: referralRollforwardID("invitee", 1)}
	sub := Subscription{ID: referralRollforwardID("sub", 1), PlanID: "club-month", Kind: "club", Seats: 2}
	plan := Plan{ID: "club-month", Kind: "club", Title: "Fixture", PricePerSeatRub: 299, PeriodDays: 30, MaxSeats: 500}
	view, err := s.clubReferrals(ctx, invitee.ID)
	if err != nil || len(view.Credits) != 1 {
		t.Fatal("Первая награда отсутствует", err)
	}
	order := reserveFixture(t, s, invitee, sub, plan, 1, view.Credits[0].Code, time.Now())
	if _, err = s.DB.Exec(ctx, "INSERT INTO payment_review_events(payment_id,provider_status) VALUES($1,'CHARGEBACKED')", referralRollforwardID("pay", 1)); err != nil {
		t.Fatal(err)
	}
	if _, err = s.DB.Exec(ctx, "UPDATE club_verifications SET approved_at=now() WHERE subscription_id=$1", referralRollforwardID("sub", 2)); err != nil {
		t.Fatal(err)
	}
	var existingCredits string
	if err = s.DB.QueryRow(ctx, "SELECT jsonb_agg(to_jsonb(c) ORDER BY code)::text FROM club_referral_credits c WHERE invitee_id=$1", invitee.ID).Scan(&existingCredits); err != nil {
		t.Fatal(err)
	}
	before := referralRollforwardFinancialSnapshot(t, s)
	if err = s.ReconcileExistingClubReferralAwards(ctx); err != nil {
		t.Fatal(err)
	}
	assertReferralRollforwardAwards(t, s, 2)
	var afterCredits string
	if err = s.DB.QueryRow(ctx, "SELECT jsonb_agg(to_jsonb(c) ORDER BY code)::text FROM club_referral_credits c WHERE invitee_id=$1", invitee.ID).Scan(&afterCredits); err != nil || existingCredits != afterCredits || before != referralRollforwardFinancialSnapshot(t, s) {
		t.Fatal("Восстановление переписало резерв, invoice или финансовые условия", err)
	}
	ownerView, err := s.clubReferrals(ctx, referralRollforwardOwner)
	if err != nil {
		t.Fatal(err)
	}
	held := 0
	for _, credit := range ownerView.Credits {
		if credit.State == "held" {
			held++
		}
	}
	if held != 1 {
		t.Fatal("Source review перестал удерживать неиспользованную награду", held)
	}
	var reserved string
	if err = s.DB.QueryRow(ctx, "SELECT reserved_payment_id FROM club_referral_credits WHERE code=$1", view.Credits[0].Code).Scan(&reserved); err != nil || reserved != order.ID {
		t.Fatal("Резерв кредита освобождён", err)
	}
}
