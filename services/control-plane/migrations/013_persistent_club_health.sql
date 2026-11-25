-- Additive to I091 (9-11) and cabinet device details (12).
-- No notification outbox, identity/activation rewrites or destructive rollback.
DO $$
BEGIN
 IF NOT EXISTS (SELECT 1 FROM schema_migrations WHERE version=13) THEN
  CREATE TABLE club_health_persistent_devices (
   device_id text PRIMARY KEY REFERENCES devices(id) ON DELETE CASCADE,
   account_id text NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
   pc text NOT NULL DEFAULT '', software_version text NOT NULL DEFAULT '',
   source text NOT NULL DEFAULT '', last_seen timestamptz NOT NULL DEFAULT now(),
   missing_since timestamptz, discarded bigint NOT NULL DEFAULT 0 CHECK(discarded>=0)
  );
  CREATE TABLE club_health_persistent_events (
   device_id text NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
   event_id text NOT NULL CHECK(event_id ~ '^[a-f0-9]{32}$'),
   account_id text NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
   observed_at timestamptz NOT NULL,
   received_at timestamptz NOT NULL DEFAULT now(),
   summary jsonb NOT NULL CHECK(octet_length(summary::text)<=4096),
   PRIMARY KEY(device_id,event_id)
  );
  CREATE INDEX club_health_persistent_time ON club_health_persistent_events(observed_at);
  CREATE INDEX club_health_persistent_account ON club_health_persistent_events(account_id,received_at DESC);
  INSERT INTO schema_migrations(version) VALUES(13);
 END IF;
END $$;
