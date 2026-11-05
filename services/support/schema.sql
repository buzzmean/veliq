-- Separate support database. Never apply to the control-plane database.
CREATE TABLE IF NOT EXISTS support_visitors (
 id text PRIMARY KEY, expires_at timestamptz NOT NULL
);
CREATE TABLE IF NOT EXISTS support_tickets (
 id text PRIMARY KEY, visitor text NOT NULL REFERENCES support_visitors(id),
 status text NOT NULL CHECK (status IN ('queued','assigned','resolved')),
 operator_id bigint NOT NULL DEFAULT 0, revision bigint NOT NULL DEFAULT 1,
 created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now(),
 CHECK ((status='assigned' AND operator_id>0) OR (status='queued' AND operator_id=0) OR status='resolved')
);
CREATE UNIQUE INDEX IF NOT EXISTS support_one_active ON support_tickets(visitor) WHERE status <> 'resolved';
CREATE INDEX IF NOT EXISTS support_visitor_history ON support_tickets(visitor,created_at DESC);
CREATE TABLE IF NOT EXISTS support_messages (
 id bigserial PRIMARY KEY, ticket text NOT NULL REFERENCES support_tickets(id) ON DELETE CASCADE,
 role text NOT NULL CHECK(role IN ('visitor','operator','system')), body text NOT NULL,
 created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS support_messages_ticket ON support_messages(ticket,id);
CREATE TABLE IF NOT EXISTS support_requests (
 visitor text NOT NULL REFERENCES support_visitors(id), key text NOT NULL, digest text NOT NULL,
 ticket text NOT NULL, created_at timestamptz NOT NULL DEFAULT now(), PRIMARY KEY(visitor,key)
);
CREATE TABLE IF NOT EXISTS support_outbox (
 id bigserial PRIMARY KEY, ticket text NOT NULL REFERENCES support_tickets(id) ON DELETE CASCADE,
 body text NOT NULL, attempts integer NOT NULL DEFAULT 0,
 next_at timestamptz NOT NULL DEFAULT now(), sent_at timestamptz
);
CREATE TABLE IF NOT EXISTS support_telegram_messages (
 chat_id bigint NOT NULL, message_id bigint NOT NULL,
 ticket text NOT NULL REFERENCES support_tickets(id) ON DELETE CASCADE, PRIMARY KEY(chat_id,message_id)
);
CREATE TABLE IF NOT EXISTS support_updates (id bigint PRIMARY KEY, created_at timestamptz NOT NULL DEFAULT now());
CREATE TABLE IF NOT EXISTS support_worker (id integer PRIMARY KEY CHECK(id=1), offset_id bigint NOT NULL DEFAULT 0);
INSERT INTO support_worker(id) VALUES(1) ON CONFLICT DO NOTHING;
CREATE TABLE IF NOT EXISTS support_limits (
 key text PRIMARY KEY, count integer NOT NULL, expires_at timestamptz NOT NULL
);
