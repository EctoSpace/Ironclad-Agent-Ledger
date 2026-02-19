// Policy-as-code: TOML audit policies validated at each step.

use crate::intent::ProposedIntent;
use serde::Deserialize;
use std::path::Path;

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct AuditPolicy {
    pub name: Option<String>,
    pub goal: Option<String>,
    pub max_steps: Option<u32>,
    pub require_findings: Option<bool>,
    pub min_severity_threshold: Option<String>,
    pub required_checks: Option<Vec<RequiredCheck>>,
    pub allowed_actions: Option<Vec<AllowedAction>>,
    pub forbidden_actions: Option<Vec<ForbiddenAction>>,
    pub findings: Option<FindingsPolicy>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct RequiredCheck {
    pub name: String,
    pub action: String,
    pub params: Option<toml::Value>,
    pub required: Option<bool>,
    pub timeout_steps: Option<u32>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct AllowedAction {
    pub action: String,
    pub path_pattern: Option<String>,
    pub allowed_commands: Option<Vec<String>>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct ForbiddenAction {
    pub action: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct FindingsPolicy {
    pub require_evidence_for_severity: Option<Vec<String>>,
    pub evidence_must_reference_observation: Option<bool>,
}

#[derive(Debug)]
pub struct PolicyViolation(pub String);

impl std::fmt::Display for PolicyViolation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "policy violation: {}", self.0)
    }
}

impl std::error::Error for PolicyViolation {}

pub struct PolicyEngine {
    policy: AuditPolicy,
}

impl PolicyEngine {
    pub fn new(policy: AuditPolicy) -> Self {
        Self { policy }
    }

    pub fn load_from_path(path: &Path) -> Result<Self, PolicyLoadError> {
        let s = std::fs::read_to_string(path).map_err(PolicyLoadError::Io)?;
        let policy: AuditPolicy = toml::from_str(&s).map_err(PolicyLoadError::Toml)?;
        Ok(Self::new(policy))
    }

    pub fn validate_intent(&self, intent: &ProposedIntent, _step: u32) -> Result<(), PolicyViolation> {
        let action = intent.action.as_str();

        if let Some(ref forbidden) = self.policy.forbidden_actions {
            for fa in forbidden {
                if fa.action == action {
                    return Err(PolicyViolation(format!(
                        "action '{}' is forbidden by policy",
                        action
                    )));
                }
            }
        }

        if let Some(ref allowed) = self.policy.allowed_actions {
            let mut matched = false;
            for aa in allowed {
                if aa.action != action {
                    continue;
                }
                if let Some(ref path_pattern) = aa.path_pattern {
                    let prefix = path_pattern.trim_end_matches("/**").trim_end_matches('*');
                    if let Some(p) = intent.params_path() {
                        if !p.starts_with(prefix) {
                            continue;
                        }
                    } else {
                        continue;
                    }
                }
                if let Some(ref commands) = aa.allowed_commands {
                    if let Some(cmd) = intent.params_command() {
                        let first_word = cmd.split_whitespace().next().unwrap_or("");
                        if !commands.iter().any(|c| first_word == c.as_str()) {
                            continue;
                        }
                    } else {
                        continue;
                    }
                }
                matched = true;
                break;
            }
            if !matched {
                return Err(PolicyViolation(format!(
                    "action '{}' with given params is not in policy allowed_actions",
                    action
                )));
            }
        }

        Ok(())
    }

    pub fn max_steps(&self) -> Option<u32> {
        self.policy.max_steps
    }

    pub fn policy(&self) -> &AuditPolicy {
        &self.policy
    }
}

#[derive(Debug)]
pub enum PolicyLoadError {
    Io(std::io::Error),
    Toml(toml::de::Error),
}

impl std::fmt::Display for PolicyLoadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PolicyLoadError::Io(e) => write!(f, "io: {}", e),
            PolicyLoadError::Toml(e) => write!(f, "toml: {}", e),
        }
    }
}

impl std::error::Error for PolicyLoadError {}

/// Hash of policy file contents for storage in genesis and session.
pub fn policy_hash_bytes(content: &[u8]) -> String {
    crate::hash::sha256_hex(content)
}
