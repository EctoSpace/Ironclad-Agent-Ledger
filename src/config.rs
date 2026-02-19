use std::sync::OnceLock;

const DEFAULT_DATABASE_URL: &str = "postgres://ironclad:ironclad@localhost:5432/ironclad";

static OBSERVER_TOKEN_CACHE: OnceLock<String> = OnceLock::new();

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

/// When true, guard is required and GUARD_LLM_BACKEND / GUARD_LLM_MODEL must be set.
/// Env: GUARD_REQUIRED, default TRUE. Set GUARD_REQUIRED=false only for development.
/// In production, a guard running the same model class as the primary is not a real guard.
pub fn guard_required() -> bool {
    std::env::var("GUARD_REQUIRED")
        .ok()
        .and_then(|s| match s.to_lowercase().as_str() {
            "0" | "false" | "no" => Some(false),
            _ => s.parse().ok(),
        })
        .unwrap_or(true)
}

/// Guard LLM backend (for guard-worker). Env: GUARD_LLM_BACKEND. Required when GUARD_REQUIRED=true.
pub fn guard_llm_backend() -> Option<String> {
    std::env::var("GUARD_LLM_BACKEND").ok().filter(|s| !s.is_empty())
}

/// Guard LLM model. Env: GUARD_LLM_MODEL. Required when GUARD_REQUIRED=true.
pub fn guard_llm_model() -> Option<String> {
    std::env::var("GUARD_LLM_MODEL").ok().filter(|s| !s.is_empty())
}

/// Returns an error if guard is required but GUARD_LLM_BACKEND or GUARD_LLM_MODEL are unset.
pub fn ensure_guard_config() -> Result<(), String> {
    if !guard_required() {
        return Ok(());
    }
    let missing: Vec<&str> = [
        guard_llm_backend().is_none().then_some("GUARD_LLM_BACKEND"),
        guard_llm_model().is_none().then_some("GUARD_LLM_MODEL"),
    ]
    .into_iter()
    .flatten()
    .collect();
    if missing.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "GUARD_REQUIRED is set but {} are unset. Set them for production mode.",
            missing.join(" and ")
        ))
    }
}

/// Token for Observer dashboard auth. Env: OBSERVER_TOKEN.
/// If unset, a 32-byte hex token is generated and printed to stdout for this process.
/// All dashboard/API requests must include it (Bearer header or ?token=).
pub fn observer_token() -> String {
    OBSERVER_TOKEN_CACHE
        .get_or_init(|| {
            std::env::var("OBSERVER_TOKEN")
                .ok()
                .filter(|s| !s.is_empty())
                .unwrap_or_else(|| {
                    let token = hex::encode(rand::random::<[u8; 32]>());
                    println!(
                        "⚠️  No OBSERVER_TOKEN set. Generated token for this session: {}",
                        token
                    );
                    println!("    Dashboard: http://localhost:3000?token={}", token);
                    token
                })
        })
        .clone()
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

/// Directory for encrypted session key files. Env: IRONCLAD_DATA_DIR, default `.ironclad/keys`.
pub fn session_key_dir() -> std::path::PathBuf {
    let base = std::env::var("IRONCLAD_DATA_DIR")
        .unwrap_or_else(|_| ".ironclad".to_string());
    std::path::PathBuf::from(base).join("keys")
}

/// Max approximate token budget per session (character count / 4 estimate).
/// Env: AGENT_TOKEN_BUDGET_MAX. Default: unlimited (None).
pub fn token_budget_max() -> Option<u64> {
    std::env::var("AGENT_TOKEN_BUDGET_MAX")
        .ok()
        .and_then(|s| s.parse().ok())
}

/// Max cognitive loop steps. Env: AGENT_MAX_STEPS, default 20.
pub fn max_steps() -> u32 {
    std::env::var("AGENT_MAX_STEPS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(20)
}

// ── Webhook / SIEM egress ──────────────────────────────────────────────────────

/// Configuration for outbound webhook / SIEM egress.
/// Set `WEBHOOK_URL` to enable; `WEBHOOK_BEARER_TOKEN` and `SIEM_FORMAT` are optional.
#[derive(Clone, Debug)]
pub struct WebhookConfig {
    /// Full URL to POST security events to (e.g. Slack, Splunk HEC, custom SIEM endpoint).
    pub url: String,
    /// Optional `Authorization: Bearer <token>` header value.
    pub bearer_token: Option<String>,
    /// Output format: `json` (default), `cef` (ArcSight CEF), or `leef` (IBM LEEF).
    pub siem_format: String,
}

/// Returns `Some(WebhookConfig)` when `WEBHOOK_URL` is set, otherwise `None` (egress disabled).
pub fn webhook_config() -> Option<WebhookConfig> {
    let url = std::env::var("WEBHOOK_URL").ok().filter(|s| !s.is_empty())?;
    let bearer_token = std::env::var("WEBHOOK_BEARER_TOKEN")
        .ok()
        .filter(|s| !s.is_empty());
    let siem_format = std::env::var("SIEM_FORMAT")
        .ok()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "json".to_string());
    Some(WebhookConfig { url, bearer_token, siem_format })
}
