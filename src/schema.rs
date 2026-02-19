use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionStatus {
    Running,
    Completed,
    Failed,
    Aborted,
}

impl SessionStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            SessionStatus::Running => "running",
            SessionStatus::Completed => "completed",
            SessionStatus::Failed => "failed",
            SessionStatus::Aborted => "aborted",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingSeverity {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuditFinding {
    pub severity: FindingSeverity,
    pub title: String,
    pub evidence: String,
    pub recommendation: String,
    /// Ledger sequence numbers that support this finding. Required for high/critical.
    #[serde(default)]
    pub evidence_sequence: Vec<i64>,
    /// Exact substrings from those observations that support the evidence.
    #[serde(default)]
    pub evidence_quotes: Vec<String>,
}

#[derive(Clone, Debug, Serialize, FromRow)]
pub struct SessionRow {
    pub id: Uuid,
    pub goal: String,
    pub goal_hash: Option<String>,
    pub status: String,
    pub llm_backend: Option<String>,
    pub llm_model: Option<String>,
    pub created_at: DateTime<Utc>,
    pub finished_at: Option<DateTime<Utc>>,
    pub policy_hash: Option<String>,
    pub session_public_key: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum EventPayload {
    Genesis { message: String },
    Thought { content: String },
    Action { name: String, params: serde_json::Value },
    Observation { content: String },
    /// Human-in-the-loop: approval requested for an action.
    ApprovalRequired {
        gate_id: String,
        action_name: String,
        action_params_summary: String,
    },
    /// Human-in-the-loop: decision recorded.
    ApprovalDecision {
        gate_id: String,
        approved: bool,
        reason: Option<String>,
    },
}

#[derive(Clone, Debug)]
pub struct LedgerEventRow {
    pub id: i64,
    pub sequence: i64,
    pub previous_hash: String,
    pub content_hash: String,
    pub payload: EventPayload,
    pub created_at: DateTime<Utc>,
}

#[derive(Clone, Debug)]
pub struct AppendedEvent {
    pub id: i64,
    pub sequence: i64,
    pub previous_hash: String,
    pub content_hash: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Clone, Debug)]
pub struct SnapshotRow {
    pub id: Uuid,
    pub sequence: i64,
    pub state_hash: String,
    pub payload: serde_json::Value,
    pub created_at: DateTime<Utc>,
}

#[derive(Clone, Debug)]
pub struct RestoredState {
    pub snapshot_sequence: i64,
    pub snapshot_payload: serde_json::Value,
    pub replayed_events: Vec<LedgerEventRow>,
}
