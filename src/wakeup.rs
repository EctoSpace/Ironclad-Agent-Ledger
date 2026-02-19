use crate::ledger::get_events;
use crate::schema::{RestoredState, SnapshotRow};
use crate::snapshot::{get_latest_snapshot, compute_state_hash, SnapshotPayload};
use serde_json::Value;
use sqlx::PgPool;

pub async fn replay_after_snapshot(
    pool: &PgPool,
    from_sequence: i64,
) -> Result<Vec<crate::schema::LedgerEventRow>, sqlx::Error> {
    let latest = get_latest(pool).await?;
    let to_sequence = match latest {
        None => return Ok(Vec::new()),
        Some((seq, _)) => seq,
    };
    if to_sequence <= from_sequence {
        return Ok(Vec::new());
    }
    get_events(pool, from_sequence + 1, to_sequence).await
}

async fn get_latest(pool: &PgPool) -> Result<Option<(i64, String)>, sqlx::Error> {
    crate::ledger::get_latest(pool).await
}

pub fn verify_snapshot_hash(snapshot: &SnapshotRow) -> Result<bool, serde_json::Error> {
    let payload: SnapshotPayload = serde_json::from_value(snapshot.payload.clone())?;
    let expected = compute_state_hash(&payload)?;
    Ok(snapshot.state_hash == expected)
}

pub async fn restore_state(
    pool: &PgPool,
    verify_snapshot: bool,
) -> Result<RestoredState, WakeUpError> {
    let snapshot = get_latest_snapshot(pool)
        .await
        .map_err(WakeUpError::Db)?
        .ok_or(WakeUpError::NoSnapshot)?;

    if verify_snapshot {
        let valid = verify_snapshot_hash(&snapshot).map_err(WakeUpError::Serialize)?;
        if !valid {
            return Err(WakeUpError::SnapshotHashMismatch);
        }
    }

    let replayed = replay_after_snapshot(pool, snapshot.sequence)
        .await
        .map_err(WakeUpError::Db)?;

    Ok(RestoredState {
        snapshot_sequence: snapshot.sequence,
        snapshot_payload: snapshot.payload,
        replayed_events: replayed,
    })
}

pub async fn restore_state_from_genesis(pool: &PgPool) -> Result<RestoredState, sqlx::Error> {
    let latest = get_latest(pool).await?;
    let (to_sequence, replayed) = match latest {
        None => {
            return Ok(RestoredState {
                snapshot_sequence: -1,
                snapshot_payload: Value::Object(serde_json::Map::new()),
                replayed_events: Vec::new(),
            });
        }
        Some((seq, _)) => {
            let events = get_events(pool, 0, seq).await?;
            (seq, events)
        }
    };
    let snapshot_payload = serde_json::json!({
        "event_count": replayed.len(),
        "last_sequence": to_sequence,
        "latest_events_summary": []
    });
    Ok(RestoredState {
        snapshot_sequence: to_sequence,
        snapshot_payload,
        replayed_events: replayed,
    })
}

#[derive(Debug)]
pub enum WakeUpError {
    Db(sqlx::Error),
    Serialize(serde_json::Error),
    NoSnapshot,
    SnapshotHashMismatch,
}

impl std::fmt::Display for WakeUpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WakeUpError::Db(e) => write!(f, "db: {}", e),
            WakeUpError::Serialize(e) => write!(f, "serialize: {}", e),
            WakeUpError::NoSnapshot => write!(f, "no snapshot found"),
            WakeUpError::SnapshotHashMismatch => write!(f, "snapshot state_hash mismatch"),
        }
    }
}

impl std::error::Error for WakeUpError {}
