use serde::Deserialize;
use tokio::process::Command;

#[derive(Debug, Deserialize)]
struct TagsResponse {
    models: Option<Vec<ModelInfo>>,
}

#[derive(Debug, Deserialize)]
struct ModelInfo {
    name: Option<String>,
}

pub async fn ensure_ollama_ready(
    base_url: &str,
    model: &str,
    client: &reqwest::Client,
) -> Result<(), OllamaSetupError> {
    let url = format!("{}/api/tags", base_url.trim_end_matches('/'));
    let response = client.get(&url).send().await.map_err(|e| {
        OllamaSetupError::OllamaNotRunning(format!("cannot reach {}: {}", url, e))
    })?;

    if !response.status().is_success() {
        return Err(OllamaSetupError::OllamaNotRunning(format!(
            "{} returned {}",
            url,
            response.status()
        )));
    }

    let body = response.text().await.map_err(OllamaSetupError::Http)?;
    let tags: TagsResponse = serde_json::from_str(&body).map_err(OllamaSetupError::Parse)?;
    let models = tags.models.unwrap_or_default();

    let has_model = models.iter().any(|m| {
        m.name
            .as_deref()
            .map(|n| n == model || n.starts_with(&format!("{}:", model)))
            .unwrap_or(false)
    });

    if has_model {
        return Ok(());
    }

    let output = Command::new("ollama")
        .arg("pull")
        .arg(model)
        .output()
        .await
        .map_err(|e| OllamaSetupError::PullFailed(format!("failed to run ollama pull: {}", e)))?;

    if !output.status.success() {
        return Err(OllamaSetupError::PullFailed(format!(
            "ollama pull {} exited with {:?}",
            model, output.status
        )));
    }

    Ok(())
}

#[derive(Debug)]
pub enum OllamaSetupError {
    OllamaNotRunning(String),
    Http(reqwest::Error),
    Parse(serde_json::Error),
    PullFailed(String),
}

impl std::fmt::Display for OllamaSetupError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OllamaSetupError::OllamaNotRunning(msg) => write!(f, "Ollama not running: {}", msg),
            OllamaSetupError::Http(e) => write!(f, "http: {}", e),
            OllamaSetupError::Parse(e) => write!(f, "parse: {}", e),
            OllamaSetupError::PullFailed(msg) => write!(f, "pull failed: {}", msg),
        }
    }
}

impl std::error::Error for OllamaSetupError {}
