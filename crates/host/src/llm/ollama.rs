use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use super::{strip_markdown_fences, LlmError, LlmBackend};
use crate::intent::ProposedIntent;

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

pub struct OllamaBackend {
    base_url: String,
    model: String,
    client: reqwest::Client,
}

impl OllamaBackend {
    pub fn from_env(client: &reqwest::Client) -> Self {
        let base_url = std::env::var("OLLAMA_BASE_URL").unwrap_or_else(|_| "http://localhost:11434".to_string());
        let model = std::env::var("OLLAMA_MODEL").unwrap_or_else(|_| "mistral".to_string());
        Self {
            base_url,
            model,
            client: client.clone(),
        }
    }

    pub fn override_model(&mut self, model: String) {
        self.model = model;
    }
}

#[async_trait]
impl LlmBackend for OllamaBackend {
    async fn propose(&self, system: &str, user: &str) -> Result<ProposedIntent, LlmError> {
        let url = format!("{}/api/chat", self.base_url.trim_end_matches('/'));
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
            stream: false,
            format: Some("json".to_string()),
        };

        let response = self.client
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

    async fn raw_call(&self, system: &str, user: &str) -> Result<String, LlmError> {
        let url = format!("{}/api/chat", self.base_url.trim_end_matches('/'));
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
            stream: false,
            format: None,
        };

        let response = self.client
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
        Ok(raw.trim().to_string())
    }

    fn backend_name(&self) -> &str {
        "ollama"
    }

    fn model_name(&self) -> &str {
        &self.model
    }

    async fn ensure_ready(&self, client: &reqwest::Client) -> Result<(), LlmError> {
        crate::ollama::ensure_ollama_ready(&self.base_url, &self.model, client)
            .await
            .map_err(|e| LlmError::Setup(e.to_string()))
    }
}
