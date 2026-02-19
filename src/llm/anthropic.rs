use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use super::{strip_markdown_fences, LlmError, LlmBackend};
use crate::intent::ProposedIntent;

#[derive(Debug, Serialize)]
struct ChatRequest {
    model: String,
    max_tokens: u32,
    system: String,
    messages: Vec<ChatMessage>,
}

#[derive(Debug, Serialize)]
struct ChatMessage {
    role: String,
    content: String,
}

#[derive(Debug, Deserialize)]
struct ChatResponse {
    content: Vec<ContentBlock>,
}

#[derive(Debug, Deserialize)]
struct ContentBlock {
    #[serde(rename = "type")]
    _block_type: String,
    text: Option<String>,
}

pub struct AnthropicBackend {
    base_url: String,
    model: String,
    api_key: String,
    client: reqwest::Client,
}

impl AnthropicBackend {
    pub fn from_env(client: &reqwest::Client) -> Self {
        let base_url = std::env::var("ANTHROPIC_BASE_URL")
            .unwrap_or_else(|_| "https://api.anthropic.com".to_string());
        let model = std::env::var("ANTHROPIC_MODEL")
            .unwrap_or_else(|_| "claude-3-5-sonnet-20241022".to_string());
        let api_key = std::env::var("ANTHROPIC_API_KEY").unwrap_or_default();
        Self {
            base_url,
            model,
            api_key,
            client: client.clone(),
        }
    }

    pub fn override_model(&mut self, model: String) {
        self.model = model;
    }
}

#[async_trait]
impl LlmBackend for AnthropicBackend {
    async fn propose(&self, system: &str, user: &str) -> Result<ProposedIntent, LlmError> {
        let raw = self.raw_call(system, user).await?;
        let json_str = strip_markdown_fences(raw.trim());
        let intent: ProposedIntent = serde_json::from_str(json_str).map_err(LlmError::InvalidJson)?;
        Ok(intent)
    }

    async fn raw_call(&self, system: &str, user: &str) -> Result<String, LlmError> {
        let url = format!("{}/v1/messages", self.base_url.trim_end_matches('/'));
        let body = ChatRequest {
            model: self.model.clone(),
            max_tokens: 4096,
            system: system.to_string(),
            messages: vec![ChatMessage {
                role: "user".to_string(),
                content: user.to_string(),
            }],
        };

        let mut req = self.client.post(&url).json(&body);
        if !self.api_key.is_empty() {
            req = req.header("x-api-key", &self.api_key);
            req = req.header("anthropic-version", "2023-06-01");
        }
        let response = req.send().await.map_err(LlmError::Http)?;

        if !response.status().is_success() {
            let status = response.status();
            let text = response.text().await.unwrap_or_default();
            return Err(LlmError::HttpStatus(status.as_u16(), text));
        }

        let chat: ChatResponse = response.json().await.map_err(LlmError::Http)?;
        let raw = chat
            .content
            .first()
            .and_then(|b| b.text.clone())
            .ok_or(LlmError::EmptyResponse)?;
        Ok(raw)
    }

    fn backend_name(&self) -> &str {
        "anthropic"
    }

    fn model_name(&self) -> &str {
        &self.model
    }
}
