use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ProposedIntent {
    pub action: String,
    #[serde(default)]
    pub params: serde_json::Value,
    #[serde(default)]
    pub justification: String,
    #[serde(default)]
    pub reasoning: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatedIntent(ProposedIntent);

impl ValidatedIntent {
    pub fn from_proposed(inner: ProposedIntent) -> Self {
        ValidatedIntent(inner)
    }

    pub fn inner(&self) -> &ProposedIntent {
        &self.0
    }

    pub fn action(&self) -> &str {
        &self.0.action
    }

    pub fn params(&self) -> &serde_json::Value {
        &self.0.params
    }
}

impl ProposedIntent {
    pub fn params_command(&self) -> Option<&str> {
        self.params.get("command").and_then(|v| v.as_str())
    }

    pub fn params_path(&self) -> Option<&str> {
        self.params.get("path").and_then(|v| v.as_str())
    }

    pub fn params_url(&self) -> Option<&str> {
        self.params.get("url").and_then(|v| v.as_str())
    }
}
