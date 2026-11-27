-- Additive TEST-stage capability. Existing devices/rights/slots remain unchanged.
DO $$ BEGIN
 IF NOT EXISTS(SELECT 1 FROM schema_migrations WHERE version=16) THEN
  ALTER TABLE subscriptions ADD COLUMN personal_optimization_lease_stage boolean NOT NULL DEFAULT false;
  ALTER TABLE devices ADD COLUMN personal_optimization_lease_v1 boolean NOT NULL DEFAULT false;
  ALTER TABLE account_device_links ADD COLUMN personal_optimization_lease_v1 boolean NOT NULL DEFAULT false;
  CREATE TABLE personal_optimization_leases(
   account_id text PRIMARY KEY REFERENCES accounts(id),
   device_id text NOT NULL REFERENCES devices(id),
   lease_id text NOT NULL CHECK(lease_id ~ '^[a-f0-9]{32}$'),
   expires_at timestamptz NOT NULL
  );
  INSERT INTO schema_migrations(version) VALUES(16);
 END IF;
END $$;
