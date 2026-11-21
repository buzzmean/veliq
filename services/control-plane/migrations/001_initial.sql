CREATE TABLE IF NOT EXISTS schema_migrations(version integer PRIMARY KEY, applied_at timestamptz NOT NULL DEFAULT now());
CREATE TABLE IF NOT EXISTS users(id text PRIMARY KEY, name text NOT NULL, created_at timestamptz NOT NULL DEFAULT now());
CREATE TABLE IF NOT EXISTS devices(id text PRIMARY KEY, user_id text NOT NULL REFERENCES users(id), name text NOT NULL, public_key text NOT NULL UNIQUE, revoked boolean NOT NULL DEFAULT false, created_at timestamptz NOT NULL DEFAULT now());
CREATE TABLE IF NOT EXISTS relay_nodes(id text PRIMARY KEY, metadata jsonb NOT NULL, heartbeat_token_hash bytea, healthy boolean NOT NULL DEFAULT false, heartbeat_at timestamptz);
CREATE TABLE IF NOT EXISTS application_profiles(id text PRIMARY KEY, profile jsonb NOT NULL);
CREATE TABLE IF NOT EXISTS config_versions(version bigserial PRIMARY KEY, document bytea NOT NULL, generated_at timestamptz NOT NULL, expires_at timestamptz NOT NULL);
CREATE TABLE IF NOT EXISTS audit_log(id bigserial PRIMARY KEY, actor text NOT NULL, action text NOT NULL, entity_id text NOT NULL, created_at timestamptz NOT NULL DEFAULT now());
CREATE TABLE IF NOT EXISTS auth_nonces(device_id text NOT NULL REFERENCES devices(id), nonce text NOT NULL, expires_at timestamptz NOT NULL, PRIMARY KEY(device_id,nonce));
CREATE INDEX IF NOT EXISTS auth_nonces_expiry ON auth_nonces(expires_at);
INSERT INTO users(id,name) VALUES('owner','Development owner') ON CONFLICT DO NOTHING;
INSERT INTO schema_migrations(version) VALUES(1) ON CONFLICT DO NOTHING;

ALTER TABLE relay_nodes ADD COLUMN IF NOT EXISTS heartbeat_token_hash bytea;

ALTER TABLE devices ADD COLUMN IF NOT EXISTS last_authenticated_at timestamptz;

-- Complete revocation publication scales with revoked devices, not all registrations.
CREATE INDEX IF NOT EXISTS devices_revoked_ids ON devices(id) WHERE revoked;
