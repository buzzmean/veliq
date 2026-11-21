CREATE TABLE IF NOT EXISTS activation_codes(
 id text PRIMARY KEY, code_hash bytea NOT NULL UNIQUE CHECK(octet_length(code_hash)=32),
 kind text NOT NULL CHECK(kind IN ('club','personal')), seat_limit integer NOT NULL CHECK(seat_limit BETWEEN 1 AND 10000),
 name text NOT NULL, expires_at timestamptz NOT NULL, revoked boolean NOT NULL DEFAULT false, created_at timestamptz NOT NULL DEFAULT now());
CREATE TABLE IF NOT EXISTS activation_slots(
 code_id text NOT NULL REFERENCES activation_codes(id), machine_hash text NOT NULL CHECK(machine_hash ~ '^[a-f0-9]{64}$'),
 device_id text NOT NULL REFERENCES devices(id), disabled boolean NOT NULL DEFAULT false, updated_at timestamptz NOT NULL DEFAULT now(),
 PRIMARY KEY(code_id,machine_hash));
CREATE TABLE IF NOT EXISTS activation_policy(singleton boolean PRIMARY KEY CHECK(singleton), hardware_salt bytea NOT NULL CHECK(octet_length(hardware_salt)=32));
INSERT INTO schema_migrations(version) VALUES(2) ON CONFLICT DO NOTHING;
