use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum EventPayload {
    Genesis { message: String },
    Thought { content: String },
    Action { name: String, params: serde_json::Value },
    Observation { content: String },
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
