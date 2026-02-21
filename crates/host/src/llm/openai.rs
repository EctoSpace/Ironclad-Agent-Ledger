use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use super::{strip_markdown_fences, LlmError, LlmBackend};
use crate::intent::ProposedIntent;

#[derive(Debug, Serialize)]
struct ChatRequest {
    model: String,
    messages: Vec<ChatMessage>,
}

#[derive(Debug, Serialize)]
struct ChatMessage {
    role: String,
    content: String,
}

#[derive(Debug, Deserialize)]
struct ChatResponse {
    choices: Vec<Choice>,
}

#[derive(Debug, Deserialize)]
struct Choice {
    message: ChoiceMessage,
}

#[derive(Debug, Deserialize)]
struct ChoiceMessage {
    content: Option<String>,
}

pub struct OpenAiBackend {
    base_url: String,
    model: String,
    api_key: String,
    client: reqwest::Client,
}

impl OpenAiBackend {
    pub fn from_env(client: &reqwest::Client) -> Self {
        let base_url = std::env::var("OPENAI_BASE_URL")
            .unwrap_or_else(|_| "https://api.openai.com".to_string());
        let model = std::env::var("OPENAI_MODEL")
            .unwrap_or_else(|_| "gpt-4o-mini".to_string());
        let api_key = std::env::var("OPENAI_API_KEY").unwrap_or_default();
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
impl LlmBackend for OpenAiBackend {
    async fn propose(&self, system: &str, user: &str) -> Result<ProposedIntent, LlmError> {
        let raw = self.raw_call(system, user).await?;
        let json_str = strip_markdown_fences(raw.trim());
        let intent: ProposedIntent = serde_json::from_str(json_str).map_err(LlmError::InvalidJson)?;
        Ok(intent)
    }

    async fn raw_call(&self, system: &str, user: &str) -> Result<String, LlmError> {
        let url = format!("{}/v1/chat/completions", self.base_url.trim_end_matches('/'));
        let body = ChatRequest {
            model: self.model.clone(),
            messages: vec![
                ChatMessage {
                    role: "system".to_string(),
                    content: system.to_string(),
                },
                ChatMessage {
                    role: "user".to_string(),
                    content: user.to_string(),
                },
            ],
        };

        let mut req = self.client.post(&url).json(&body);
        if !self.api_key.is_empty() {
            req = req.header("Authorization", format!("Bearer {}", self.api_key));
        }
        let response = req.send().await.map_err(LlmError::Http)?;

        if !response.status().is_success() {
            let status = response.status();
            let text = response.text().await.unwrap_or_default();
            return Err(LlmError::HttpStatus(status.as_u16(), text));
        }

        let chat: ChatResponse = response.json().await.map_err(LlmError::Http)?;
        let raw = chat
            .choices
            .first()
            .and_then(|c| c.message.content.clone())
            .ok_or(LlmError::EmptyResponse)?;
        Ok(raw)
    }

    fn backend_name(&self) -> &str {
        "openai"
    }

    fn model_name(&self) -> &str {
        &self.model
    }
}
