ALTER TABLE agent_events ADD COLUMN session_id UUID REFERENCES agent_sessions(id);
CREATE INDEX idx_agent_events_session_id ON agent_events(session_id);
