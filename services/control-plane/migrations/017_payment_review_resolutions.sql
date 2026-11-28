-- A resolution acknowledges evidence, never changes financial credit or access.
DO $$ BEGIN
 IF NOT EXISTS(SELECT 1 FROM schema_migrations WHERE version=17) THEN
  CREATE TABLE payment_review_resolutions (
   payment_id text NOT NULL REFERENCES payments(id),
   through_event_id bigint NOT NULL REFERENCES payment_review_events(id),
   evidence_sha256 text NOT NULL CHECK(evidence_sha256 ~ '^[0-9a-f]{64}$'),
   outcome text NOT NULL CHECK(outcome='review_completed_no_access_change'),
   reviewed_refund_kopecks bigint NOT NULL CHECK(reviewed_refund_kopecks>0),
   created_at timestamptz NOT NULL DEFAULT now(),
   PRIMARY KEY(payment_id,through_event_id)
  );
  INSERT INTO schema_migrations(version) VALUES(17);
 END IF;
END $$;
CREATE OR REPLACE FUNCTION payment_review_required(payment text) RETURNS boolean
 LANGUAGE sql STABLE AS $$
 SELECT EXISTS(SELECT 1 FROM payment_review_events e WHERE e.payment_id=payment
  AND e.id>coalesce((SELECT max(r.through_event_id) FROM payment_review_resolutions r WHERE r.payment_id=payment),0))
$$;
CREATE OR REPLACE FUNCTION payment_review_resolution_immutable() RETURNS trigger
 LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'PAYMENT_REVIEW_RESOLUTION_IMMUTABLE'; END $$;
DROP TRIGGER IF EXISTS payment_review_resolution_immutable ON payment_review_resolutions;
CREATE TRIGGER payment_review_resolution_immutable BEFORE UPDATE OR DELETE ON payment_review_resolutions
 FOR EACH ROW EXECUTE FUNCTION payment_review_resolution_immutable();
