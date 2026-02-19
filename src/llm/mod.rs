mod ollama;
mod openai;
mod anthropic;

pub use ollama::OllamaBackend;
pub use openai::OpenAiBackend;
pub use anthropic::AnthropicBackend;

use async_trait::async_trait;
use crate::intent::ProposedIntent;
use crate::schema::{EventPayload, RestoredState};

pub const DEFAULT_SYSTEM_PROMPT: &str = r#"You are a security-audit agent. Your response must be exactly one JSON object with no surrounding text.

Goal: Achieve the user's current goal (stated at the start of the user message).

Allowed actions and params:
- run_command: params.command (string) — run a single shell command
- read_file: params.path (string) — read a file path
- http_get: params.url (string) — fetch a URL
- complete: no params or empty params — finish the audit

Security rules:
- Propose only actions necessary for the stated goal.
- Do not run destructive or off-goal commands.

Anti-loop rule:
- Do not repeat the same action with the same parameters. If an action did not advance the goal, try a different action or complete with your findings.

Output format (JSON only):
{"action": "<action>", "params": {...}}
You may optionally include "justification" and "reasoning" strings.
When you complete, include in params an optional \"findings\" array. Each finding must have \"severity\", \"title\", \"evidence\", \"recommendation\", and for high/critical must include \"evidence_sequence\" (array of ledger sequence numbers of observations that support this finding) and \"evidence_quotes\" (array of exact substrings from those observations).

Example for step 1 (reading a file):
{\"action\": \"read_file\", \"params\": {\"path\": \"server_config.txt\"}, \"reasoning\": \"Reading config to inspect settings.\"}"#;

/// Few-shot examples injected during the first steps to anchor weaker models
/// and prevent them from producing off-format or looping output.
pub fn few_shot_examples() -> &'static str {
    r#"
--- FEW-SHOT EXAMPLES (follow this exact format) ---

Example 1 — reading a file:
User: "Current goal: Audit server_config.txt\n\nRecent events:\n  [genesis] initialized"
Assistant: {"action":"read_file","params":{"path":"server_config.txt"},"justification":"Need to inspect server configuration for audit findings.","reasoning":"The goal is to audit server_config.txt, so reading it is the first logical step."}

Example 2 — running a command:
User: "Current goal: Check open ports\n\nRecent events:\n  [observation] file contents: ..."
Assistant: {"action":"run_command","params":{"command":"ss -tlnp"},"justification":"Listing TCP listening ports to identify exposed services.","reasoning":"After reading config, enumerating listening ports confirms which services are active."}

Example 3 — completing the audit:
User: "Current goal: Audit server_config.txt\n\nRecent events:\n  [observation] port 22 open"
Assistant: {"action":"complete","params":{"findings":[{"severity":"medium","title":"SSH exposed","evidence":"port 22 open","recommendation":"Restrict SSH access via firewall rules."}]},"justification":"All planned checks done.","reasoning":"Sufficient evidence gathered to produce findings."}

--- END EXAMPLES ---
"#
}

pub fn state_to_prompt(state: &RestoredState, max_events: usize) -> String {
    let mut out = String::new();
    if let Some(obj) = state.snapshot_payload.as_object() {
        if let Some(c) = obj.get("event_count").and_then(|v| v.as_u64()) {
            out.push_str(&format!("Event count: {}\n", c));
        }
        if let Some(s) = obj.get("last_sequence").and_then(|v| v.as_i64()) {
            out.push_str(&format!("Last sequence: {}\n", s));
        }
    }
    out.push_str("\nRecent events:\n");
    let start = state
        .replayed_events
        .len()
        .saturating_sub(max_events);
    for ev in state.replayed_events.iter().skip(start) {
        match &ev.payload {
            EventPayload::Genesis { message } => {
                out.push_str(&format!("  [genesis] {}\n", message));
            }
            EventPayload::Thought { content } => {
                out.push_str(&format!("  [thought] {}\n", content));
            }
            EventPayload::Action { name, params } => {
                out.push_str(&format!("  [action] {} {:?}\n", name, params));
            }
            EventPayload::Observation { content } => {
                let trunc = if content.len() > 200 {
                    let mut b = 200;
                    while b > 0 && !content.is_char_boundary(b) {
                        b -= 1;
                    }
                    format!("{}...", &content[..b])
                } else {
                    content.clone()
                };
                out.push_str(&format!("  [observation] {}\n", trunc));
            }
            EventPayload::ApprovalRequired { .. } | EventPayload::ApprovalDecision { .. } => {
                out.push_str("  [approval]\n");
            }
        }
    }
    out.push_str("\nPropose the next action as a single JSON object (action + params only).");
    out
}

pub fn strip_markdown_fences(s: &str) -> &str {
    let s = s.trim();
    if !s.starts_with("```") {
        return s;
    }
    let after_open = s.trim_start_matches('`');
    let after_lang = after_open
        .trim_start_matches("json")
        .trim_start_matches("JSON")
        .trim_start_matches('\n')
        .trim_start_matches('\r');
    match after_lang.rfind("```") {
        Some(end) => after_lang[..end].trim(),
        None => after_lang.trim(),
    }
}

#[async_trait]
pub trait LlmBackend: Send + Sync {
    async fn propose(&self, system: &str, user: &str) -> Result<ProposedIntent, LlmError>;
    async fn raw_call(&self, system: &str, user: &str) -> Result<String, LlmError>;
    fn backend_name(&self) -> &str;
    fn model_name(&self) -> &str;
    async fn ensure_ready(&self, client: &reqwest::Client) -> Result<(), LlmError> {
        let _ = client;
        Ok(())
    }
}

pub fn backend_from_env(client: &reqwest::Client) -> Result<Box<dyn LlmBackend>, LlmError> {
    let name = crate::config::llm_backend();
    match name.as_str() {
        "ollama" => Ok(Box::new(OllamaBackend::from_env(client))),
        "openai" => Ok(Box::new(OpenAiBackend::from_env(client))),
        "anthropic" => Ok(Box::new(AnthropicBackend::from_env(client))),
        _ => Err(LlmError::UnsupportedBackend(name)),
    }
}

/// Creates a Guard LLM backend from environment variables.
///
/// Reads `GUARD_LLM_BACKEND` (default: same as `LLM_BACKEND`) and
/// `GUARD_LLM_MODEL` to allow the guard to run on a separate, isolated model.
pub fn guard_backend_from_env(client: &reqwest::Client) -> Result<Box<dyn LlmBackend>, LlmError> {
    let name = crate::config::guard_llm_backend()
        .unwrap_or_else(crate::config::llm_backend);
    let guard_model = crate::config::guard_llm_model();

    match name.as_str() {
        "ollama" => {
            let mut backend = OllamaBackend::from_env(client);
            if let Some(model) = guard_model {
                backend.override_model(model);
            }
            Ok(Box::new(backend))
        }
        "openai" => {
            let mut backend = OpenAiBackend::from_env(client);
            if let Some(model) = guard_model {
                backend.override_model(model);
            }
            Ok(Box::new(backend))
        }
        "anthropic" => {
            let mut backend = AnthropicBackend::from_env(client);
            if let Some(model) = guard_model {
                backend.override_model(model);
            }
            Ok(Box::new(backend))
        }
        _ => Err(LlmError::UnsupportedBackend(name)),
    }
}

#[derive(Debug)]
pub enum LlmError {
    Http(reqwest::Error),
    HttpStatus(u16, String),
    EmptyResponse,
    InvalidJson(serde_json::Error),
    UnsupportedBackend(String),
    Setup(String),
}

impl std::fmt::Display for LlmError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LlmError::Http(e) => write!(f, "http: {}", e),
            LlmError::HttpStatus(code, body) => write!(f, "http status {}: {}", code, body),
            LlmError::EmptyResponse => write!(f, "empty response"),
            LlmError::InvalidJson(e) => write!(f, "invalid json: {}", e),
            LlmError::UnsupportedBackend(name) => write!(f, "unsupported LLM backend: {}", name),
            LlmError::Setup(msg) => write!(f, "setup: {}", msg),
        }
    }
}

impl std::error::Error for LlmError {}
