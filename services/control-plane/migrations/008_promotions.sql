-- Additive only. No campaign, code or approval is activated by a migration.
DO $$ BEGIN
 IF NOT EXISTS(SELECT 1 FROM schema_migrations WHERE version=8) THEN
  CREATE TABLE promotions(
    id text PRIMARY KEY,
    code_hash bytea NOT NULL UNIQUE CHECK(octet_length(code_hash)=32),
    kind text NOT NULL UNIQUE CHECK(kind IN ('owner-test','club-launch')),
    account_id text REFERENCES accounts(id),
    discount integer NOT NULL,
    capacity integer NOT NULL,
    enabled boolean NOT NULL DEFAULT false,
    created_at timestamptz NOT NULL DEFAULT now(),
    CHECK((kind='owner-test' AND account_id IS NOT NULL AND discount=99 AND capacity=1)
       OR (kind='club-launch' AND account_id IS NULL AND discount=30 AND capacity=20))
  );
  -- Independent administrative verification, never granted by self-service profile.
  CREATE TABLE promotion_club_approvals(
    account_id text PRIMARY KEY REFERENCES accounts(id),
    club_reference text NOT NULL UNIQUE CHECK(club_reference ~ '^[a-zA-Z0-9_-]{8,64}$'),
    approved_at timestamptz NOT NULL DEFAULT now()
  );
  CREATE TABLE promotion_reservations(
    id text PRIMARY KEY,
    promotion_id text NOT NULL REFERENCES promotions(id),
    account_id text NOT NULL REFERENCES accounts(id),
    payment_id text NOT NULL UNIQUE REFERENCES payments(id),
    state text NOT NULL DEFAULT 'reserved' CHECK(state IN ('reserved','redeemed')),
    created_at timestamptz NOT NULL DEFAULT now(),
    redeemed_at timestamptz,
    UNIQUE(promotion_id,account_id)
  );
  INSERT INTO schema_migrations(version) VALUES(8);
 END IF;
END $$;
