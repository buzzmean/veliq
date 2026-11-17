-- Perpetual owner grants are separate from payments. Existing subscriptions stay finite.
DO $$ BEGIN
 IF NOT EXISTS(SELECT 1 FROM schema_migrations WHERE version=6) THEN
  ALTER TABLE subscriptions ADD COLUMN lifetime boolean NOT NULL DEFAULT false;
  INSERT INTO schema_migrations(version) VALUES(6);
 END IF;
END $$;
