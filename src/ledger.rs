use crate::hash::{compute_content_hash, GENESIS_PREVIOUS_HASH};
use crate::schema::{AppendedEvent, EventPayload, LedgerEventRow};
use chrono::Utc;
use sqlx::{FromRow, PgPool};

#[derive(FromRow)]
struct AgentEventDbRow {
    id: i64,
    sequence: i64,
    previous_hash: String,
    content_hash: String,
    payload: sqlx::types::Json<EventPayload>,
    created_at: chrono::DateTime<Utc>,
}

fn db_row_to_ledger_event(row: AgentEventDbRow) -> LedgerEventRow {
    LedgerEventRow {
        id: row.id,
        sequence: row.sequence,
        previous_hash: row.previous_hash,
        content_hash: row.content_hash,
        payload: row.payload.0,
        created_at: row.created_at,
    }
}

pub async fn get_latest(pool: &PgPool) -> Result<Option<(i64, String)>, sqlx::Error> {
    let row = sqlx::query_as::<_, (i64, String)>(
        "SELECT sequence, content_hash FROM agent_events ORDER BY sequence DESC LIMIT 1",
    )
    .fetch_optional(pool)
    .await?;
    Ok(row)
}

pub async fn verify_chain(
    pool: &PgPool,
    from_sequence: i64,
    to_sequence: i64,
) -> Result<bool, sqlx::Error> {
    let rows = sqlx::query_as::<_, AgentEventDbRow>(
        "SELECT id, sequence, previous_hash, content_hash, payload, created_at
         FROM agent_events
         WHERE sequence >= $1 AND sequence <= $2
         ORDER BY sequence ASC",
    )
    .bind(from_sequence)
    .bind(to_sequence)
    .fetch_all(pool)
    .await?;

    if rows.is_empty() {
        return Ok(true);
    }

    let mut prev_content_hash: Option<String> = None;
    for row in rows {
        let expected_prev = prev_content_hash.as_deref().unwrap_or(GENESIS_PREVIOUS_HASH);
        if row.previous_hash != expected_prev {
            return Ok(false);
        }
        let payload_json = serde_json::to_string(&row.payload.0).map_err(|_| {
            sqlx::Error::Decode(Box::new(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "payload serialize",
            )))
        })?;
        let expected_content = compute_content_hash(&row.previous_hash, row.sequence, &payload_json);
        if row.content_hash != expected_content {
            return Ok(false);
        }
        prev_content_hash = Some(row.content_hash);
    }
    Ok(true)
}

pub async fn append_event(
    pool: &PgPool,
    payload: EventPayload,
) -> Result<AppendedEvent, AppendError> {
    let payload_json = serde_json::to_string(&payload).map_err(AppendError::Serialize)?;

    let (sequence, previous_hash) = match get_latest(pool).await.map_err(AppendError::Db)? {
        None => (0_i64, GENESIS_PREVIOUS_HASH.to_string()),
        Some((seq, content_hash)) => (seq + 1, content_hash),
    };

    let content_hash = compute_content_hash(&previous_hash, sequence, &payload_json);
    let now = Utc::now();

    let row = sqlx::query_as::<_, (i64, i64, String, String, chrono::DateTime<Utc>)>(
        "INSERT INTO agent_events (sequence, previous_hash, content_hash, payload, created_at)
         VALUES ($1, $2, $3, $4, $5)
         RETURNING id, sequence, previous_hash, content_hash, created_at",
    )
    .bind(sequence)
    .bind(&previous_hash)
    .bind(&content_hash)
    .bind(sqlx::types::Json(&payload))
    .bind(now)
    .fetch_one(pool)
    .await
    .map_err(AppendError::Db)?;

    Ok(AppendedEvent {
        id: row.0,
        sequence: row.1,
        previous_hash: row.2,
        content_hash: row.3,
        created_at: row.4,
    })
}

pub async fn ensure_genesis(pool: &PgPool) -> Result<AppendedEvent, AppendError> {
    let latest = get_latest(pool).await.map_err(AppendError::Db)?;
    if let Some((seq, _)) = latest {
        let row = sqlx::query_as::<_, (i64, i64, String, String, chrono::DateTime<Utc>)>(
            "SELECT id, sequence, previous_hash, content_hash, created_at FROM agent_events WHERE sequence = $1",
        )
        .bind(seq)
        .fetch_one(pool)
        .await
        .map_err(AppendError::Db)?;
        return Ok(AppendedEvent {
            id: row.0,
            sequence: row.1,
            previous_hash: row.2,
            content_hash: row.3,
            created_at: row.4,
        });
    }

    let payload = EventPayload::Genesis {
        message: "Ironclad Agent Ledger initialized".to_string(),
    };
    append_event(pool, payload).await
}

pub async fn get_events(
    pool: &PgPool,
    from_sequence: i64,
    to_sequence: i64,
) -> Result<Vec<LedgerEventRow>, sqlx::Error> {
    let rows = sqlx::query_as::<_, AgentEventDbRow>(
        "SELECT id, sequence, previous_hash, content_hash, payload, created_at
         FROM agent_events
         WHERE sequence >= $1 AND sequence <= $2
         ORDER BY sequence ASC",
    )
    .bind(from_sequence)
    .bind(to_sequence)
    .fetch_all(pool)
    .await?;
    Ok(rows.into_iter().map(db_row_to_ledger_event).collect())
}

#[derive(Debug)]
pub enum AppendError {
    Db(sqlx::Error),
    Serialize(serde_json::Error),
}

impl std::fmt::Display for AppendError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AppendError::Db(e) => write!(f, "db: {}", e),
            AppendError::Serialize(e) => write!(f, "serialize: {}", e),
        }
    }
}

impl std::error::Error for AppendError {}
