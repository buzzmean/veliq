-- Additive only: no historical payments, subscriptions, grants or campaigns change.
DO $$ BEGIN
 IF NOT EXISTS(SELECT 1 FROM schema_migrations WHERE version=14) THEN
  CREATE TABLE personal_payment_orders (
   payment_id text PRIMARY KEY REFERENCES payments(id),
   account_id text NOT NULL REFERENCES accounts(id),
   idempotency_key text NOT NULL CHECK(idempotency_key ~ '^[a-zA-Z0-9_-]{16,96}$'),
   request_hash text NOT NULL CHECK(request_hash ~ '^[a-f0-9]{64}$'),
   snapshot jsonb NOT NULL CHECK(jsonb_typeof(snapshot)='object' AND octet_length(snapshot::text)<=4096),
   state text NOT NULL DEFAULT 'open' CHECK(state IN ('open','consumed')),
   redirect_url text NOT NULL DEFAULT '' CHECK(octet_length(redirect_url)<=4096),
   created_at timestamptz NOT NULL DEFAULT now(),
   UNIQUE(account_id,idempotency_key)
  );
  CREATE UNIQUE INDEX personal_one_open_order ON personal_payment_orders(account_id) WHERE state='open';
  CREATE FUNCTION personal_order_immutable() RETURNS trigger LANGUAGE plpgsql AS $fn$
  BEGIN
   IF NEW.payment_id<>OLD.payment_id OR NEW.account_id<>OLD.account_id OR NEW.idempotency_key<>OLD.idempotency_key
    OR NEW.request_hash<>OLD.request_hash OR NEW.snapshot<>OLD.snapshot OR NEW.created_at<>OLD.created_at
    OR (OLD.state='consumed' AND NEW.state<>'consumed')
    OR (OLD.redirect_url<>'' AND NEW.redirect_url<>OLD.redirect_url) THEN
    RAISE EXCEPTION 'immutable personal order';
   END IF;
   RETURN NEW;
  END $fn$;
  CREATE TRIGGER personal_order_immutable BEFORE UPDATE ON personal_payment_orders FOR EACH ROW EXECUTE FUNCTION personal_order_immutable();
  CREATE FUNCTION personal_payment_terms_immutable() RETURNS trigger LANGUAGE plpgsql AS $fn$
  BEGIN
   IF EXISTS(SELECT 1 FROM personal_payment_orders WHERE payment_id=OLD.id) AND
    (NEW.subscription_id<>OLD.subscription_id OR NEW.provider<>OLD.provider OR NEW.amount_kopecks<>OLD.amount_kopecks
     OR NEW.period_days<>OLD.period_days OR NEW.reference<>OLD.reference OR NEW.created_at<>OLD.created_at) THEN
    RAISE EXCEPTION 'immutable personal payment terms';
   END IF;
   RETURN NEW;
  END $fn$;
  CREATE TRIGGER personal_payment_terms_immutable BEFORE UPDATE ON payments FOR EACH ROW EXECUTE FUNCTION personal_payment_terms_immutable();
  INSERT INTO schema_migrations(version) VALUES(14);
 END IF;
END $$;
