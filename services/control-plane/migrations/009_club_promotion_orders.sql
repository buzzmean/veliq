-- Candidate 009 for the verified isolated baseline only; production next version UNKNOWN.
-- No campaign activation, price change or rewrite of an existing payment.
DO $$ BEGIN
 IF NOT EXISTS(SELECT 1 FROM schema_migrations WHERE version=9) THEN
 CREATE TABLE club_promotion_entitlements (
  account_id text PRIMARY KEY REFERENCES accounts(id),
  promotion_id text NOT NULL REFERENCES promotions(id),
  club_reference text UNIQUE,
  initial_subscription_id text REFERENCES subscriptions(id),
  initial_seats integer CHECK(initial_seats>0),
  review_required boolean NOT NULL DEFAULT false,
  starts_at timestamptz,
  ends_at timestamptz,
  allocated_until_seconds bigint NOT NULL DEFAULT 0 CHECK(allocated_until_seconds BETWEEN 0 AND 7776000),
  discount_numerator bigint NOT NULL DEFAULT 0 CHECK(discount_numerator>=0),
  discount_kopecks bigint NOT NULL DEFAULT 0 CHECK(discount_kopecks>=0),
  CHECK((starts_at IS NULL AND ends_at IS NULL) OR ends_at=starts_at+interval '2160 hours')
 );
 -- Missing historical T0/cohort/coverage is UNKNOWN. Never infer it from created_at.
 INSERT INTO club_promotion_entitlements(account_id,promotion_id,club_reference,review_required)
 SELECT r.account_id,r.promotion_id,a.club_reference,true
 FROM promotion_reservations r JOIN promotions p ON p.id=r.promotion_id
 LEFT JOIN promotion_club_approvals a ON a.account_id=r.account_id WHERE p.kind='club-launch';
 CREATE TABLE club_payment_orders (
  payment_id text PRIMARY KEY REFERENCES payments(id),
  account_id text NOT NULL REFERENCES accounts(id),
  idempotency_key text NOT NULL,
  request_hash text NOT NULL,
  snapshot jsonb NOT NULL,
  entitlement_account_id text REFERENCES club_promotion_entitlements(account_id),
  benefit_from_seconds bigint NOT NULL DEFAULT 0,
  benefit_to_seconds bigint NOT NULL DEFAULT 0,
  state text NOT NULL DEFAULT 'open' CHECK(state IN ('open','consumed')),
  redirect_url text NOT NULL DEFAULT '',
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE(account_id,idempotency_key),
  CHECK(benefit_from_seconds>=0 AND benefit_to_seconds>=benefit_from_seconds AND benefit_to_seconds<=7776000)
 );
 CREATE UNIQUE INDEX club_one_unresolved_promo_order ON club_payment_orders(account_id)
 WHERE state='open' AND entitlement_account_id IS NOT NULL;
 CREATE FUNCTION club_order_immutable() RETURNS trigger LANGUAGE plpgsql AS $fn$
 BEGIN
 IF NEW.payment_id<>OLD.payment_id OR NEW.account_id<>OLD.account_id OR NEW.idempotency_key<>OLD.idempotency_key
 OR NEW.request_hash<>OLD.request_hash OR NEW.snapshot<>OLD.snapshot
 OR NEW.entitlement_account_id IS DISTINCT FROM OLD.entitlement_account_id
 OR NEW.benefit_from_seconds<>OLD.benefit_from_seconds OR NEW.benefit_to_seconds<>OLD.benefit_to_seconds
 OR NEW.created_at<>OLD.created_at OR (OLD.state='consumed' AND NEW.state<>'consumed') THEN
 RAISE EXCEPTION 'immutable club order'; END IF;
 RETURN NEW;
 END $fn$;
 CREATE TRIGGER club_order_immutable BEFORE UPDATE ON club_payment_orders FOR EACH ROW EXECUTE FUNCTION club_order_immutable();
 CREATE FUNCTION club_payment_terms_immutable() RETURNS trigger LANGUAGE plpgsql AS $fn$
 BEGIN
 IF EXISTS(SELECT 1 FROM club_payment_orders WHERE payment_id=OLD.id) AND
 (NEW.subscription_id<>OLD.subscription_id OR NEW.provider<>OLD.provider OR NEW.amount_kopecks<>OLD.amount_kopecks OR NEW.period_days<>OLD.period_days) THEN
 RAISE EXCEPTION 'immutable club payment terms'; END IF;
 RETURN NEW;
 END $fn$;
 CREATE TRIGGER club_payment_terms_immutable BEFORE UPDATE ON payments FOR EACH ROW EXECUTE FUNCTION club_payment_terms_immutable();
 INSERT INTO schema_migrations(version) VALUES(9);
 END IF;
END $$;
