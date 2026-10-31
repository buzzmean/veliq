-- Additive: accounts, email login, subscriptions and payments. Existing codes,
-- slots and devices are untouched; a code without a subscription keeps its own expiry.
DO $$ BEGIN
 IF NOT EXISTS(SELECT 1 FROM schema_migrations WHERE version=4) THEN
  CREATE TABLE accounts(id text PRIMARY KEY, email text NOT NULL UNIQUE CHECK(email=lower(email) AND length(email) BETWEEN 3 AND 254), disabled boolean NOT NULL DEFAULT false, created_at timestamptz NOT NULL DEFAULT now());
  CREATE TABLE login_codes(email text PRIMARY KEY, code_hash bytea NOT NULL CHECK(octet_length(code_hash)=32), expires_at timestamptz NOT NULL, attempts integer NOT NULL DEFAULT 0, sent_at timestamptz NOT NULL DEFAULT now());
  CREATE TABLE account_sessions(token_hash bytea PRIMARY KEY CHECK(octet_length(token_hash)=32), account_id text NOT NULL REFERENCES accounts(id), expires_at timestamptz NOT NULL, created_at timestamptz NOT NULL DEFAULT now());
  CREATE INDEX account_sessions_expiry ON account_sessions(expires_at);
  CREATE TABLE subscriptions(id text PRIMARY KEY, account_id text NOT NULL REFERENCES accounts(id), plan_id text NOT NULL, kind text NOT NULL CHECK(kind IN ('player','club')), seats integer NOT NULL CHECK(seats BETWEEN 1 AND 10000), paid_until timestamptz, auto_renew boolean NOT NULL DEFAULT false, created_at timestamptz NOT NULL DEFAULT now());
  CREATE INDEX subscriptions_account ON subscriptions(account_id);
  ALTER TABLE activation_codes ADD COLUMN subscription_id text REFERENCES subscriptions(id);
  CREATE UNIQUE INDEX activation_codes_subscription ON activation_codes(subscription_id) WHERE subscription_id IS NOT NULL;
  CREATE INDEX activation_slots_device ON activation_slots(device_id);
  CREATE TABLE payments(id text PRIMARY KEY, subscription_id text NOT NULL REFERENCES subscriptions(id), provider text NOT NULL, provider_payment_id text NOT NULL, amount_kopecks bigint NOT NULL CHECK(amount_kopecks>=0), period_days integer NOT NULL CHECK(period_days BETWEEN 1 AND 400), status text NOT NULL CHECK(status IN ('pending','succeeded','canceled')), reference text NOT NULL DEFAULT '', created_at timestamptz NOT NULL DEFAULT now(), UNIQUE(provider,provider_payment_id));
  CREATE INDEX payments_subscription ON payments(subscription_id);
  INSERT INTO schema_migrations(version) VALUES(4);
 END IF;
END $$;
