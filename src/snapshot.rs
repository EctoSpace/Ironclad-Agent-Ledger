use crate::hash::sha256_hex;
use crate::ledger::get_events;
use crate::schema::{LedgerEventRow, SnapshotRow};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use sqlx::{FromRow, PgPool};
use uuid::Uuid;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SnapshotPayload {
    pub event_count: u64,
    pub last_sequence: i64,
    pub latest_events_summary: Vec<EventSummary>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EventSummary {
    pub sequence: i64,
    pub type_label: String,
}

fn event_type_label(payload: &crate::schema::EventPayload) -> String {
    match payload {
        crate::schema::EventPayload::Genesis { .. } => "genesis".to_string(),
        crate::schema::EventPayload::Thought { .. } => "thought".to_string(),
        crate::schema::EventPayload::Action { .. } => "action".to_string(),
        crate::schema::EventPayload::Observation { .. } => "observation".to_string(),
        crate::schema::EventPayload::ApprovalRequired { .. } => "approval_required".to_string(),
        crate::schema::EventPayload::ApprovalDecision { .. } => "approval_decision".to_string(),
        crate::schema::EventPayload::CrossLedgerSeal { .. } => "cross_ledger_seal".to_string(),
        crate::schema::EventPayload::Anchor { .. } => "anchor".to_string(),
    }
}

pub fn build_snapshot_payload(events: &[LedgerEventRow], last_sequence: i64) -> SnapshotPayload {
    let event_count = events.len() as u64;
    let latest_events_summary: Vec<EventSummary> = events
        .iter()
        .rev()
        .take(100)
        .rev()
        .map(|e| EventSummary {
            sequence: e.sequence,
            type_label: event_type_label(&e.payload),
        })
        .collect();
    SnapshotPayload {
        event_count,
        last_sequence,
        latest_events_summary,
    }
}

pub fn compute_state_hash(payload: &SnapshotPayload) -> Result<String, serde_json::Error> {
    let json = serde_json::to_string(payload)?;
    Ok(sha256_hex(json.as_bytes()))
}

#[derive(FromRow)]
struct AgentSnapshotDbRow {
    id: Uuid,
    sequence: i64,
    state_hash: String,
    payload: sqlx::types::Json<serde_json::Value>,
    created_at: chrono::DateTime<Utc>,
}

pub async fn get_latest_snapshot(pool: &PgPool) -> Result<Option<SnapshotRow>, sqlx::Error> {
    let row = sqlx::query_as::<_, AgentSnapshotDbRow>(
        "SELECT id, sequence, state_hash, payload, created_at
         FROM agent_snapshots
         ORDER BY sequence DESC
         LIMIT 1",
    )
    .fetch_optional(pool)
    .await?;
    Ok(row.map(|r| SnapshotRow {
        id: r.id,
        sequence: r.sequence,
        state_hash: r.state_hash,
        payload: r.payload.0,
        created_at: r.created_at,
    }))
}

pub async fn save_snapshot(
    pool: &PgPool,
    sequence: i64,
    state_hash: &str,
    payload: &SnapshotPayload,
) -> Result<SnapshotRow, sqlx::Error> {
    let payload_value = serde_json::to_value(payload).map_err(|e| {
        sqlx::Error::Decode(Box::new(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            e.to_string(),
        )))
    })?;
    let now = Utc::now();
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO agent_snapshots (id, sequence, state_hash, payload, created_at)
         VALUES ($1, $2, $3, $4, $5)",
    )
    .bind(id)
    .bind(sequence)
    .bind(state_hash)
    .bind(sqlx::types::Json(&payload_value))
    .bind(now)
    .execute(pool)
    .await?;

    Ok(SnapshotRow {
        id,
        sequence,
        state_hash: state_hash.to_string(),
        payload: payload_value,
        created_at: now,
    })
}

pub async fn snapshot_at_sequence(
    pool: &PgPool,
    sequence: i64,
) -> Result<SnapshotRow, SnapshotError> {
    let events = get_events(pool, 0, sequence).await.map_err(SnapshotError::Db)?;
    let payload = build_snapshot_payload(&events, sequence);
    let state_hash = compute_state_hash(&payload).map_err(SnapshotError::Serialize)?;
    save_snapshot(pool, sequence, &state_hash, &payload)
        .await
        .map_err(SnapshotError::Db)
}

#[derive(Debug)]
pub enum SnapshotError {
    Db(sqlx::Error),
    Serialize(serde_json::Error),
}

impl std::fmt::Display for SnapshotError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SnapshotError::Db(e) => write!(f, "db: {}", e),
            SnapshotError::Serialize(e) => write!(f, "serialize: {}", e),
        }
    }
}

impl std::error::Error for SnapshotError {}
