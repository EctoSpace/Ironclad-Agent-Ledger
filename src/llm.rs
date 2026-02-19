use crate::intent::ProposedIntent;
use crate::schema::{EventPayload, RestoredState};
use serde::{Deserialize, Serialize};

const SYSTEM_PROMPT: &str = "You are a security-audit agent. Respond only with valid JSON. \
Allowed actions: run_command, read_file, http_get, complete. \
For run_command put the shell command in params.command. \
For read_file put the file path in params.path. \
For http_get put the URL in params.url. \
For complete use no params or empty params. \
Respond with exactly one JSON object: {\"action\": \"<action>\", \"params\": {...}}.";

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
        }
    }
    out.push_str("\nPropose the next action as a single JSON object (action + params only).");
    out
}

#[derive(Debug, Serialize)]
struct ChatRequest {
    model: String,
    messages: Vec<ChatMessage>,
    stream: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    format: Option<String>,
}

#[derive(Debug, Serialize)]
struct ChatMessage {
    role: String,
    content: String,
}

#[derive(Debug, Deserialize)]
struct ChatResponse {
    #[serde(alias = "message")]
    message: Option<ChatResponseMessage>,
    #[serde(alias = "response")]
    response: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ChatResponseMessage {
    content: Option<String>,
}

pub async fn propose_intent(
    state: &RestoredState,
    client: &reqwest::Client,
    base_url: &str,
    model: &str,
) -> Result<ProposedIntent, LlmError> {
    let user_content = state_to_prompt(state, 50);
    let url = format!("{}/api/chat", base_url.trim_end_matches('/'));
    let body = ChatRequest {
        model: model.to_string(),
        messages: vec![
            ChatMessage {
                role: "system".to_string(),
                content: SYSTEM_PROMPT.to_string(),
            },
            ChatMessage {
                role: "user".to_string(),
                content: user_content,
            },
        ],
        stream: false,
        format: Some("json".to_string()),
    };

    let response = client
        .post(&url)
        .json(&body)
        .send()
        .await
        .map_err(LlmError::Http)?;

    if !response.status().is_success() {
        let status = response.status();
        let text = response.text().await.unwrap_or_default();
        return Err(LlmError::HttpStatus(status.as_u16(), text));
    }

    let chat: ChatResponse = response.json().await.map_err(LlmError::Http)?;
    let raw = chat
        .message
        .and_then(|m| m.content)
        .or(chat.response)
        .ok_or(LlmError::EmptyResponse)?;

    let json_str = strip_markdown_fences(raw.trim());
    let intent: ProposedIntent = serde_json::from_str(json_str).map_err(LlmError::InvalidJson)?;
    Ok(intent)
}

fn strip_markdown_fences(s: &str) -> &str {
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

#[derive(Debug)]
pub enum LlmError {
    Http(reqwest::Error),
    HttpStatus(u16, String),
    EmptyResponse,
    InvalidJson(serde_json::Error),
}

impl std::fmt::Display for LlmError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LlmError::Http(e) => write!(f, "http: {}", e),
            LlmError::HttpStatus(code, body) => write!(f, "http status {}: {}", code, body),
            LlmError::EmptyResponse => write!(f, "empty response"),
            LlmError::InvalidJson(e) => write!(f, "invalid json: {}", e),
        }
    }
}

impl std::error::Error for LlmError {}
