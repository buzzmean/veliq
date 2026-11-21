-- Additive compatibility: preserve every code, slot, device and security record.
-- The schema history remains after the temporary runtime feature is retired.
DO $$ BEGIN
 IF NOT EXISTS(SELECT 1 FROM schema_migrations WHERE version=3) THEN
  ALTER TABLE activation_codes DROP CONSTRAINT activation_codes_kind_check;
  ALTER TABLE activation_codes ADD CONSTRAINT activation_codes_kind_check CHECK(kind IN ('club','personal','test'));
  ALTER TABLE activation_codes ADD CONSTRAINT activation_test_bounds CHECK(kind<>'test' OR (seat_limit=2 AND expires_at<=created_at+interval '14 days'));
  INSERT INTO schema_migrations(version) VALUES(3);
 END IF;
END $$;
