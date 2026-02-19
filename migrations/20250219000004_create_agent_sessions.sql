CREATE TABLE agent_sessions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    goal TEXT NOT NULL,
    goal_hash VARCHAR(64),
    status VARCHAR(16) NOT NULL DEFAULT 'running' CHECK (status IN ('running','completed','failed','aborted')),
    llm_backend VARCHAR(32),
    llm_model VARCHAR(128),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    finished_at TIMESTAMPTZ
);
