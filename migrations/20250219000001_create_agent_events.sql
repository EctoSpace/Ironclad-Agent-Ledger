CREATE TABLE agent_events (
    id          BIGSERIAL PRIMARY KEY,
    sequence    BIGINT NOT NULL UNIQUE,
    previous_hash VARCHAR(64) NOT NULL,
    content_hash  VARCHAR(64) NOT NULL,
    payload     JSONB NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX idx_agent_events_sequence ON agent_events (sequence);
CREATE INDEX idx_agent_events_created_at ON agent_events (created_at);
CREATE INDEX idx_agent_events_content_hash ON agent_events (content_hash);

COMMENT ON TABLE agent_events IS 'Append-only ledger; no UPDATE/DELETE. previous_hash links to prior row content_hash.';
COMMENT ON COLUMN agent_events.sequence IS 'Strict ordering; genesis = 0.';
COMMENT ON COLUMN agent_events.previous_hash IS 'SHA-256 hex (64 chars) of previous row content. Genesis uses constant.';
COMMENT ON COLUMN agent_events.content_hash IS 'SHA-256 hex of this event (previous_hash || sequence || payload).';

CREATE OR REPLACE FUNCTION prevent_updates()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
  RAISE EXCEPTION 'agent_events is append-only; UPDATE and DELETE are not allowed.';
END;
$$;

CREATE TRIGGER agent_events_immutable
  BEFORE UPDATE OR DELETE ON agent_events
  FOR EACH ROW
  EXECUTE PROCEDURE prevent_updates();
