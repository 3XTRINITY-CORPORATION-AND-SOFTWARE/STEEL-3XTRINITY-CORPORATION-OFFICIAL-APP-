CREATE TABLE IF NOT EXISTS fabric_event_inbox (
  event_id text PRIMARY KEY,
  source_node text NOT NULL,
  source_sequence bigint NOT NULL CHECK (source_sequence > 0),
  content_digest char(64) NOT NULL CHECK (content_digest ~ '^[0-9a-f]{64}$'),
  received_at timestamptz NOT NULL DEFAULT now(),
  expires_at timestamptz NOT NULL,
  CONSTRAINT fabric_event_source_sequence_unique UNIQUE (source_node, source_sequence)
);
CREATE INDEX IF NOT EXISTS fabric_event_inbox_expiry_idx ON fabric_event_inbox (expires_at);
