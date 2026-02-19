use crate::hash::{compute_content_hash, GENESIS_PREVIOUS_HASH};
use crate::schema::{AppendedEvent, EventPayload, LedgerEventRow, SessionRow};
use chrono::Utc;
use sqlx::{FromRow, PgPool};
use uuid::Uuid;

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

pub async fn create_session(
    pool: &PgPool,
    goal: &str,
    llm_backend: &str,
    llm_model: &str,
) -> Result<SessionRow, sqlx::Error> {
    let id = Uuid::new_v4();
    let now = Utc::now();
    sqlx::query(
        "INSERT INTO agent_sessions (id, goal, status, llm_backend, llm_model, created_at)
         VALUES ($1, $2, 'running', $3, $4, $5)",
    )
    .bind(id)
    .bind(goal)
    .bind(llm_backend)
    .bind(llm_model)
    .bind(now)
    .execute(pool)
    .await?;
    Ok(SessionRow {
        id,
        goal: goal.to_string(),
        goal_hash: None,
        status: "running".to_string(),
        llm_backend: Some(llm_backend.to_string()),
        llm_model: Some(llm_model.to_string()),
        created_at: now,
        finished_at: None,
    })
}

pub async fn finish_session(
    pool: &PgPool,
    session_id: Uuid,
    status: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "UPDATE agent_sessions SET status = $1, finished_at = now() WHERE id = $2",
    )
    .bind(status)
    .bind(session_id)
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn list_sessions(pool: &PgPool) -> Result<Vec<SessionRow>, sqlx::Error> {
    let rows = sqlx::query_as::<_, SessionRow>(
        "SELECT id, goal, goal_hash, status, llm_backend, llm_model, created_at, finished_at
         FROM agent_sessions ORDER BY created_at DESC",
    )
    .fetch_all(pool)
    .await?;
    Ok(rows)
}

pub async fn append_event(
    pool: &PgPool,
    payload: EventPayload,
    session_id: Option<Uuid>,
) -> Result<AppendedEvent, AppendError> {
    let payload_json = serde_json::to_string(&payload).map_err(AppendError::Serialize)?;

    let mut tx = pool.begin().await.map_err(AppendError::Db)?;

    let latest = sqlx::query_as::<_, (i64, String)>(
        "SELECT sequence, content_hash FROM agent_events ORDER BY sequence DESC LIMIT 1 FOR UPDATE",
    )
    .fetch_optional(&mut *tx)
    .await
    .map_err(AppendError::Db)?;

    let (sequence, previous_hash) = match latest {
        None => (0_i64, GENESIS_PREVIOUS_HASH.to_string()),
        Some((seq, content_hash)) => (seq + 1, content_hash),
    };

    let content_hash = compute_content_hash(&previous_hash, sequence, &payload_json);
    let now = Utc::now();

    let row = sqlx::query_as::<_, (i64, i64, String, String, chrono::DateTime<Utc>)>(
        "INSERT INTO agent_events (sequence, previous_hash, content_hash, payload, created_at, session_id)
         VALUES ($1, $2, $3, $4, $5, $6)
         RETURNING id, sequence, previous_hash, content_hash, created_at",
    )
    .bind(sequence)
    .bind(&previous_hash)
    .bind(&content_hash)
    .bind(sqlx::types::Json(&payload))
    .bind(now)
    .bind(session_id)
    .fetch_one(&mut *tx)
    .await
    .map_err(AppendError::Db)?;

    tx.commit().await.map_err(AppendError::Db)?;

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
    append_event(pool, payload, None).await
}

pub async fn get_event_by_id(
    pool: &PgPool,
    event_id: i64,
) -> Result<Option<LedgerEventRow>, sqlx::Error> {
    let row = sqlx::query_as::<_, AgentEventDbRow>(
        "SELECT id, sequence, previous_hash, content_hash, payload, created_at
         FROM agent_events WHERE id = $1",
    )
    .bind(event_id)
    .fetch_optional(pool)
    .await?;
    Ok(row.map(db_row_to_ledger_event))
}

pub async fn mark_action_executing(
    pool: &PgPool,
    event_id: i64,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO agent_action_log (event_id, status) VALUES ($1, 'executing')",
    )
    .bind(event_id)
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn mark_action_completed(
    pool: &PgPool,
    event_id: i64,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "UPDATE agent_action_log SET status = 'completed', finished_at = now() WHERE event_id = $1",
    )
    .bind(event_id)
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn mark_action_failed(
    pool: &PgPool,
    event_id: i64,
    error_msg: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "UPDATE agent_action_log SET status = 'failed', finished_at = now(), error_msg = $2 WHERE event_id = $1",
    )
    .bind(event_id)
    .bind(error_msg)
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn get_dangling_actions(pool: &PgPool) -> Result<Vec<i64>, sqlx::Error> {
    let rows = sqlx::query_scalar::<_, i64>(
        "SELECT event_id FROM agent_action_log WHERE status IN ('pending', 'executing') ORDER BY started_at ASC",
    )
    .fetch_all(pool)
    .await?;
    Ok(rows)
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

/// Returns the observation content for the most recent completed `http_get`
/// action whose URL matches `url`, or `None` if no such cached result exists.
pub async fn find_cached_http_get(
    pool: &PgPool,
    url: &str,
) -> Result<Option<String>, sqlx::Error> {
    let row = sqlx::query_scalar::<_, sqlx::types::Json<crate::schema::EventPayload>>(
        r#"SELECT ae_obs.payload
           FROM agent_events ae_act
           JOIN agent_action_log aal
             ON aal.event_id = ae_act.id AND aal.status = 'completed'
           JOIN agent_events ae_obs
             ON ae_obs.sequence = ae_act.sequence + 1
          WHERE ae_act.payload->>'type' = 'action'
            AND ae_act.payload->>'name' = 'http_get'
            AND ae_act.payload->'params'->>'url' = $1
          ORDER BY ae_act.sequence DESC
          LIMIT 1"#,
    )
    .bind(url)
    .fetch_optional(pool)
    .await?;

    if let Some(payload) = row {
        if let crate::schema::EventPayload::Observation { content } = payload.0 {
            return Ok(Some(content));
        }
    }
    Ok(None)
}

pub async fn get_events_by_session(
    pool: &PgPool,
    session_id: Uuid,
) -> Result<Vec<LedgerEventRow>, sqlx::Error> {
    let rows = sqlx::query_as::<_, AgentEventDbRow>(
        "SELECT id, sequence, previous_hash, content_hash, payload, created_at
         FROM agent_events
         WHERE session_id = $1
         ORDER BY sequence ASC",
    )
    .bind(session_id)
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
