// Ephemeral cloud credential injection for auditing AWS/GCP/Azure/Kubernetes environments.
//
// Credentials are loaded from a JSON file (path in AGENT_CLOUD_CREDS_FILE) rather than
// inline environment variables, to avoid leaking secrets via /proc/<pid>/environ or `ps`.
//
// JSON format:
// {
//   "name": "aws-audit-role",
//   "provider": "aws",
//   "env_vars": {
//     "AWS_ACCESS_KEY_ID": "...",
//     "AWS_SECRET_ACCESS_KEY": "...",
//     "AWS_SESSION_TOKEN": "..."
//   }
// }

use std::collections::HashMap;
use serde::Deserialize;

/// Recognized cloud CLI binaries that are gated behind credential presence.
pub const CLOUD_CLI_BINARIES: &[&str] = &[
    "aws",
    "gcloud",
    "az",
    "kubectl",
    "terraform",
    "eksctl",
    "helm",
];

#[derive(Clone, Debug, Deserialize)]
pub struct CloudCredentialSet {
    /// Human-readable label (e.g. "aws-audit-role"). Never contains secrets.
    pub name: String,
    /// Provider hint: "aws" | "gcp" | "azure" | "k8s" | "generic".
    pub provider: String,
    /// Environment variables injected into child processes only. Parent env is not modified.
    pub env_vars: HashMap<String, String>,
}

/// Load a `CloudCredentialSet` from the path stored in `AGENT_CLOUD_CREDS_FILE`.
/// Returns `None` if the env var is absent, the file is unreadable, or the JSON is invalid.
pub fn load_cloud_creds() -> Option<CloudCredentialSet> {
    let path = std::env::var("AGENT_CLOUD_CREDS_FILE").ok()?;
    let text = std::fs::read_to_string(&path)
        .map_err(|e| tracing::warn!("Failed to read AGENT_CLOUD_CREDS_FILE '{}': {}", path, e))
        .ok()?;
    serde_json::from_str::<CloudCredentialSet>(&text)
        .map_err(|e| tracing::warn!("Failed to parse AGENT_CLOUD_CREDS_FILE '{}': {}", path, e))
        .ok()
}

/// Returns true if `program` is a known cloud CLI binary.
pub fn is_cloud_cli(program: &str) -> bool {
    let lower = program.to_lowercase();
    CLOUD_CLI_BINARIES.iter().any(|b| *b == lower.as_str())
}
