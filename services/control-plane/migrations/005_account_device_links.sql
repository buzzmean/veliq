-- Additive browser approval and revocable club image credentials. No device,
-- code, certificate or activation slot is replaced by this migration.
DO $$ BEGIN
 IF NOT EXISTS(SELECT 1 FROM schema_migrations WHERE version=5) THEN
  ALTER TABLE accounts ADD COLUMN account_type text NOT NULL DEFAULT '' CHECK(account_type IN ('','player','club'));
  ALTER TABLE accounts ADD COLUMN display_name text NOT NULL DEFAULT '' CHECK(length(display_name)<=80);
  CREATE TABLE account_device_links(
   id text PRIMARY KEY CHECK(id ~ '^[a-f0-9]{32}$'), secret_hash bytea NOT NULL CHECK(octet_length(secret_hash)=32),
   mode text NOT NULL CHECK(mode IN ('device','image')), name text NOT NULL CHECK(length(name) BETWEEN 1 AND 128),
   device_id text NOT NULL, machine_hash text NOT NULL, public_key text NOT NULL,
   bootstrap_hash bytea, expires_at timestamptz NOT NULL,
   account_id text REFERENCES accounts(id), subscription_id text REFERENCES subscriptions(id), completed boolean NOT NULL DEFAULT false,
   created_at timestamptz NOT NULL DEFAULT now());
  CREATE TABLE account_device_bindings(device_id text PRIMARY KEY REFERENCES devices(id), subscription_id text NOT NULL REFERENCES subscriptions(id));
  CREATE INDEX account_device_links_expiry ON account_device_links(expires_at);
  CREATE TABLE club_bootstraps(
   id text PRIMARY KEY CHECK(id ~ '^[a-f0-9]{32}$'), secret_hash bytea NOT NULL CHECK(octet_length(secret_hash)=32),
   subscription_id text NOT NULL REFERENCES subscriptions(id), account_id text NOT NULL REFERENCES accounts(id),
   name text NOT NULL CHECK(length(name) BETWEEN 1 AND 128), expires_at timestamptz NOT NULL, revoked boolean NOT NULL DEFAULT false,
   created_at timestamptz NOT NULL DEFAULT now());
  CREATE INDEX club_bootstraps_subscription ON club_bootstraps(subscription_id);
  INSERT INTO schema_migrations(version) VALUES(5);
 END IF;
END $$;
