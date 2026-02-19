const DEFAULT_DATABASE_URL: &str = "postgres://ironclad:ironclad@localhost:5432/ironclad";

pub fn database_url() -> Result<String, std::env::VarError> {
    match std::env::var("DATABASE_URL") {
        Ok(s) => Ok(s),
        Err(std::env::VarError::NotPresent) => Ok(DEFAULT_DATABASE_URL.to_string()),
        Err(e) => Err(e),
    }
}

pub fn ollama_base_url() -> String {
    std::env::var("OLLAMA_BASE_URL").unwrap_or_else(|_| "http://localhost:11434".to_string())
}

pub fn ollama_model() -> String {
    std::env::var("OLLAMA_MODEL").unwrap_or_else(|_| "mistral".to_string())
}

/// Number of steps between auto-snapshots. Env: AGENT_SNAPSHOT_INTERVAL, default 50.
pub fn snapshot_interval() -> u32 {
    std::env::var("AGENT_SNAPSHOT_INTERVAL")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(50)
}

/// LLM backend name: ollama, openai, or anthropic. Env: LLM_BACKEND, default ollama.
pub fn llm_backend() -> String {
    std::env::var("LLM_BACKEND").unwrap_or_else(|_| "ollama".to_string())
}

/// Guard LLM backend (for Phase 3). Env: GUARD_LLM_BACKEND.
pub fn guard_llm_backend() -> Option<String> {
    std::env::var("GUARD_LLM_BACKEND").ok()
}

/// Guard LLM model. Env: GUARD_LLM_MODEL.
pub fn guard_llm_model() -> Option<String> {
    std::env::var("GUARD_LLM_MODEL").ok()
}

/// Optional token for Observer dashboard auth. Env: OBSERVER_TOKEN.
/// If set, all dashboard/API requests must include it (Bearer header or ?token=).
pub fn observer_token() -> Option<String> {
    std::env::var("OBSERVER_TOKEN").ok().filter(|s| !s.is_empty())
}

/// Consecutive LLM errors before aborting the session. Env: AGENT_LLM_ERROR_LIMIT, default 5.
pub fn llm_error_limit() -> u32 {
    std::env::var("AGENT_LLM_ERROR_LIMIT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(5)
}

/// Consecutive Guard denials before aborting the session. Env: AGENT_GUARD_DENIAL_LIMIT, default 3.
pub fn guard_denial_limit() -> u32 {
    std::env::var("AGENT_GUARD_DENIAL_LIMIT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(3)
}

/// Max cognitive loop steps. Env: AGENT_MAX_STEPS, default 20.
pub fn max_steps() -> u32 {
    std::env::var("AGENT_MAX_STEPS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(20)
}
