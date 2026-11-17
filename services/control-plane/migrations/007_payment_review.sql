-- Additive only. The existing payment amount/period remain the credit authority.
DO $$ BEGIN
 IF NOT EXISTS(SELECT 1 FROM schema_migrations WHERE version=7) THEN
  ALTER TABLE payments ADD COLUMN last_checked_at timestamptz;
  CREATE TABLE payment_review_events (
   id bigserial PRIMARY KEY,
   payment_id text NOT NULL REFERENCES payments(id),
   provider_status text NOT NULL,
   refund_id text NOT NULL DEFAULT '',
   refund_status text NOT NULL DEFAULT '',
   refunded_kopecks bigint NOT NULL DEFAULT 0,
   received_at timestamptz NOT NULL DEFAULT now(),
   UNIQUE(payment_id, provider_status, refund_id, refund_status, refunded_kopecks)
  );
  INSERT INTO schema_migrations(version) VALUES(7);
 END IF;
END $$;
