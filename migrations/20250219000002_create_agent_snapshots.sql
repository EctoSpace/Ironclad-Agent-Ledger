CREATE TABLE agent_snapshots (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    sequence    BIGINT NOT NULL UNIQUE,
    state_hash  VARCHAR(64) NOT NULL,
    payload     JSONB NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX idx_agent_snapshots_sequence ON agent_snapshots (sequence);
CREATE INDEX idx_agent_snapshots_created_at ON agent_snapshots (created_at);

COMMENT ON TABLE agent_snapshots IS 'Checkpoints at sequence; state_hash verifies payload.';
COMMENT ON COLUMN agent_snapshots.sequence IS 'Last replayed event_sequence for this snapshot.';
COMMENT ON COLUMN agent_snapshots.state_hash IS 'SHA-256 hex of canonical snapshot payload.';
