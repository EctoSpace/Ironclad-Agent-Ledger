ALTER TABLE agent_sessions ADD COLUMN IF NOT EXISTS session_public_key VARCHAR(128);

CREATE TABLE IF NOT EXISTS agent_event_signatures (
    event_id BIGINT PRIMARY KEY REFERENCES agent_events(id),
    content_hash VARCHAR(64) NOT NULL,
    signature VARCHAR(128) NOT NULL,
    public_key VARCHAR(128) NOT NULL
);
