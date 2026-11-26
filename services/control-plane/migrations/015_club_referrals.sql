-- Дополнение к схемам устройств12, диагностики13 и персональных заказов14.
-- Существующие платежи, оплаченные права, устройства и диагностика не изменяются.
DO $$ BEGIN
 IF NOT EXISTS (SELECT 1 FROM schema_migrations WHERE version=15) THEN
  CREATE TABLE club_referral_links (
    account_id text PRIMARY KEY REFERENCES accounts(id),
    code text NOT NULL UNIQUE CHECK(code ~ '^vi-[0-9a-f]{32}$')
  );
  CREATE TABLE club_referral_claims (
    invitee_id text PRIMARY KEY REFERENCES accounts(id),
    inviter_id text NOT NULL REFERENCES club_referral_links(account_id),
    source_payment_id text UNIQUE REFERENCES payments(id),
    CHECK(invitee_id<>inviter_id)
  );
  CREATE TABLE club_referral_credits (
    code text PRIMARY KEY CHECK(code ~ '^vr-[0-9a-f]{32}$'),
    account_id text NOT NULL REFERENCES accounts(id),
    invitee_id text NOT NULL REFERENCES club_referral_claims(invitee_id),
    reserved_payment_id text UNIQUE REFERENCES payments(id),
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE(account_id,invitee_id)
  );

  INSERT INTO schema_migrations(version) VALUES(15);
 END IF;
END $$;
