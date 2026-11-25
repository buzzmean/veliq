DO $$ BEGIN
 IF NOT EXISTS (SELECT 1 FROM schema_migrations WHERE version=10) THEN
  ALTER TABLE subscriptions ADD COLUMN trial_until timestamptz
    CHECK (trial_until IS NULL OR (kind='player' AND seats=1));

  CREATE TABLE account_trial_offers (
    account_id text PRIMARY KEY REFERENCES accounts(id) ON DELETE CASCADE,
    code text NOT NULL UNIQUE CHECK (code ~ '^[a-f0-9]{32}$')
  );
  INSERT INTO schema_migrations(version) VALUES(10);
 END IF;
END $$;
