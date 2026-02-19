use crate::intent::ProposedIntent;
use crate::llm::{LlmBackend, LlmError};

const GUARD_SYSTEM: &str = "You are a guard. Given an audit goal and a proposed action (as JSON), reply with exactly one line: either \"ALLOW\" or \"DENY: <reason>\" if the action is off-goal or unsafe. No other output.";

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum GuardDecision {
    Allow,
    Deny { reason: String },
}

pub struct Guard {
    backend: Box<dyn LlmBackend>,
}

impl Guard {
    pub fn new(backend: Box<dyn LlmBackend>) -> Self {
        Self { backend }
    }

    /// Creates a Guard using the environment-configured guard backend
    /// (`GUARD_LLM_BACKEND` / `GUARD_LLM_MODEL`), falling back to the
    /// primary LLM backend if those variables are unset.
    pub fn from_env(client: &reqwest::Client) -> Result<Self, LlmError> {
        let backend = crate::llm::guard_backend_from_env(client)?;
        Ok(Self { backend })
    }

    pub async fn evaluate(
        &self,
        goal: &str,
        proposed: &ProposedIntent,
    ) -> Result<GuardDecision, LlmError> {
        let user = format!(
            "Goal: {}\nProposed action: {}",
            goal,
            serde_json::to_string(proposed).unwrap_or_else(|_| "{}".to_string())
        );
        let raw = self.backend.raw_call(GUARD_SYSTEM, &user).await?;
        let raw = raw.trim();
        if raw.to_uppercase().starts_with("ALLOW") {
            return Ok(GuardDecision::Allow);
        }
        if raw.to_uppercase().starts_with("DENY") {
            let reason = raw
                .strip_prefix("DENY")
                .or_else(|| raw.strip_prefix("deny"))
                .map(|s| s.trim_start_matches(':').trim().to_string())
                .unwrap_or_else(|| raw.to_string());
            return Ok(GuardDecision::Deny { reason });
        }
        tracing::warn!("Guard parse failure, defaulting to Allow: {:?}", raw);
        Ok(GuardDecision::Allow)
    }
}
