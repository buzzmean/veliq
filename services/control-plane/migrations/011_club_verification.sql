DO $$ BEGIN
 IF NOT EXISTS (SELECT 1 FROM schema_migrations WHERE version=11) THEN
  CREATE TABLE club_verifications (
    subscription_id text PRIMARY KEY REFERENCES subscriptions(id) ON DELETE CASCADE,
    notified_at timestamptz,
    approved_at timestamptz
  );

  CREATE VIEW club_verification_status AS
  SELECT s.id AS subscription_id,s.seats,v.notified_at,
    CASE
      WHEN a.disabled THEN 'disabled'
      WHEN v.approved_at IS NOT NULL AND s.paid_until>now() THEN 'verified'
      WHEN v.approved_at IS NOT NULL THEN 'expired'
      WHEN s.paid_until>now() AND EXISTS(
        SELECT 1 FROM payments p WHERE p.subscription_id=s.id
          AND p.status='succeeded' AND p.amount_kopecks>0
          AND NOT EXISTS(SELECT 1 FROM payment_review_events e WHERE e.payment_id=p.id)
      ) THEN 'pending'
      ELSE 'awaiting_payment'
    END AS state
  FROM club_verifications v JOIN subscriptions s ON s.id=v.subscription_id
  JOIN accounts a ON a.id=s.account_id
  WHERE s.kind='club';

  INSERT INTO schema_migrations(version) VALUES(11);
 END IF;
END $$;
