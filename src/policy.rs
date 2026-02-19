// Policy-as-code: TOML audit policies validated at each step.
//
// TOML schema (all sections optional):
//
//   name = "my-policy"
//   max_steps = 30
//
//   [[allowed_actions]]
//   action = "read_file"
//
//   [[forbidden_actions]]
//   action = "http_get"
//
//   [[command_rules]]
//   program = "curl"
//   arg_pattern = "^https://internal\\.corp"
//   decision = "allow"
//
//   [[command_rules]]
//   program = "curl"
//   arg_pattern = ".*"
//   decision = "deny"
//   reason = "curl only permitted to approved internal domains"
//
//   [[observation_rules]]
//   pattern = "(?i)(password|secret)\\s*[:=]\\s*\\S+"
//   action = "redact"
//   label = "credential_leak"
//
//   [[approval_gates]]
//   trigger = "action == 'run_command' && command_contains('nmap')"
//   require_approval = true
//   timeout_seconds = 300
//   on_timeout = "deny"

use crate::intent::ProposedIntent;
use regex::Regex;
use serde::Deserialize;
use std::path::Path;

// ── Structs ────────────────────────────────────────────────────────────────────

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
    /// Conditional command rules evaluated when action == "run_command".
    #[serde(default)]
    pub command_rules: Vec<CommandRule>,
    /// Post-execution observation content rules.
    #[serde(default)]
    pub observation_rules: Vec<ObservationRule>,
    /// Policy-driven approval gate triggers.
    #[serde(default)]
    pub approval_gates: Vec<ApprovalGateRule>,
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

/// A conditional rule applied to `run_command` actions.
/// Rules are evaluated in order; the first matching rule wins.
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct CommandRule {
    /// Program name (first token of the command) to match.
    pub program: String,
    /// Regex applied to the full argument string (everything after the program name).
    pub arg_pattern: String,
    /// Decision when both `program` and `arg_pattern` match.
    pub decision: CommandDecision,
    /// Optional human-readable reason logged on deny.
    pub reason: Option<String>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CommandDecision {
    Allow,
    Deny,
    RequireApproval,
}

/// A rule evaluated against the text content of an observation after execution.
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct ObservationRule {
    /// Regex applied to the observation content.
    pub pattern: String,
    /// Action to take when the pattern matches.
    pub action: ObservationAction,
    /// Short label recorded in the audit thought.
    pub label: String,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ObservationAction {
    /// Replace the matched text with `[REDACTED:<label>]`.
    Redact,
    /// Log a suspicious-content thought but continue.
    Flag,
    /// Abort the session immediately.
    Abort,
}

/// A policy-level approval gate trigger.
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct ApprovalGateRule {
    /// Simple trigger expression (see `eval_trigger`).
    pub trigger: String,
    pub require_approval: bool,
    pub timeout_seconds: Option<u64>,
    pub on_timeout: Option<String>,
}

// ── Errors ─────────────────────────────────────────────────────────────────────

#[derive(Debug)]
pub struct PolicyViolation(pub String);

impl std::fmt::Display for PolicyViolation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "policy violation: {}", self.0)
    }
}

impl std::error::Error for PolicyViolation {}

/// Outcome returned by `validate_observation`.
#[derive(Debug, PartialEq)]
pub enum ObservationOutcome {
    /// Content is clean; use as-is.
    Clean,
    /// Content was modified (redactions applied).
    Redacted(String),
    /// A pattern was flagged; observation is logged but continues.
    Flagged(String),
    /// Session must be aborted.
    Abort(String),
}

// ── Engine ─────────────────────────────────────────────────────────────────────

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

    /// Validates a proposed intent against the policy.
    /// Returns `Err(PolicyViolation)` if the intent is forbidden.
    /// Also runs `command_rules` for `run_command` actions.
    pub fn validate_intent(&self, intent: &ProposedIntent, _step: u32) -> Result<(), PolicyViolation> {
        let action = intent.action.as_str();

        // 1. Forbidden actions list.
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

        // 2. Allowed actions list.
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

        // 3. Command rules (only for run_command).
        if action == "run_command" {
            if let Some(cmd_str) = intent.params_command() {
                let mut parts = cmd_str.splitn(2, char::is_whitespace);
                let program = parts.next().unwrap_or("").trim();
                let args = parts.next().unwrap_or("").trim();

                for rule in &self.policy.command_rules {
                    if rule.program != program {
                        continue;
                    }
                    let re = match Regex::new(&rule.arg_pattern) {
                        Ok(r) => r,
                        Err(e) => {
                            tracing::warn!("Invalid command rule regex '{}': {}", rule.arg_pattern, e);
                            continue;
                        }
                    };
                    if !re.is_match(args) {
                        continue;
                    }
                    // Pattern matched.
                    match rule.decision {
                        CommandDecision::Allow => return Ok(()),
                        CommandDecision::Deny => {
                            let reason = rule.reason.as_deref().unwrap_or("blocked by command_rules policy");
                            return Err(PolicyViolation(format!(
                                "command '{}' denied: {}",
                                cmd_str, reason
                            )));
                        }
                        CommandDecision::RequireApproval => {
                            // Signal via PolicyViolation with a special prefix that callers can
                            // detect. The agent loop treats this the same as an ApprovalGate trigger.
                            return Err(PolicyViolation(format!(
                                "REQUIRE_APPROVAL: command '{}' requires human approval before execution",
                                cmd_str
                            )));
                        }
                    }
                }
            }
        }

        Ok(())
    }

    /// Validates observation content after execution.
    /// Returns `ObservationOutcome` indicating how to handle the content.
    pub fn validate_observation(&self, content: &str) -> ObservationOutcome {
        let mut working = content.to_string();
        let mut flagged_labels: Vec<String> = Vec::new();

        for rule in &self.policy.observation_rules {
            let re = match Regex::new(&rule.pattern) {
                Ok(r) => r,
                Err(e) => {
                    tracing::warn!("Invalid observation rule regex '{}': {}", rule.pattern, e);
                    continue;
                }
            };
            if !re.is_match(&working) {
                continue;
            }
            match rule.action {
                ObservationAction::Abort => {
                    return ObservationOutcome::Abort(format!(
                        "observation rule '{}' triggered abort",
                        rule.label
                    ));
                }
                ObservationAction::Flag => {
                    flagged_labels.push(rule.label.clone());
                }
                ObservationAction::Redact => {
                    let label = rule.label.clone();
                    working = re
                        .replace_all(&working, format!("[REDACTED:{}]", label).as_str())
                        .into_owned();
                }
            }
        }

        if !flagged_labels.is_empty() {
            return ObservationOutcome::Flagged(flagged_labels.join(", "));
        }
        if working != content {
            return ObservationOutcome::Redacted(working);
        }
        ObservationOutcome::Clean
    }

    /// Checks whether a proposed intent triggers any approval gate rules.
    /// Returns `Some(ApprovalGateRule)` if approval is required, otherwise `None`.
    pub fn check_approval_gates<'a>(&'a self, intent: &ProposedIntent) -> Option<&'a ApprovalGateRule> {
        for gate in &self.policy.approval_gates {
            if !gate.require_approval {
                continue;
            }
            if eval_trigger(&gate.trigger, intent) {
                return Some(gate);
            }
        }
        None
    }

    pub fn max_steps(&self) -> Option<u32> {
        self.policy.max_steps
    }

    pub fn policy(&self) -> &AuditPolicy {
        &self.policy
    }
}

// ── Trigger expression evaluator ───────────────────────────────────────────────

/// Evaluates a simple trigger expression of the form:
///   `action == 'x' && command_contains('y')`
///
/// Supported predicates (joined by `&&`, evaluated left-to-right):
/// - `action == '<name>'`
/// - `command_contains('<substring>')`
fn eval_trigger(trigger: &str, intent: &ProposedIntent) -> bool {
    for clause in trigger.split("&&") {
        let clause = clause.trim();
        if !eval_clause(clause, intent) {
            return false;
        }
    }
    true
}

fn eval_clause(clause: &str, intent: &ProposedIntent) -> bool {
    if let Some(rest) = clause.strip_prefix("action == ") {
        let expected = rest.trim().trim_matches('\'').trim_matches('"');
        return intent.action == expected;
    }
    if let Some(rest) = clause.strip_prefix("command_contains(") {
        let needle = rest.trim_end_matches(')').trim().trim_matches('\'').trim_matches('"');
        if let Some(cmd) = intent.params_command() {
            return cmd.contains(needle);
        }
        return false;
    }
    // Unknown predicate: treat as false to avoid silent pass-through.
    tracing::warn!("Unknown policy trigger clause: '{}'", clause);
    false
}

// ── Load error ─────────────────────────────────────────────────────────────────

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
