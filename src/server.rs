use axum::extract::{Query, State};
use axum::response::sse::{Event, Sse};
use axum::routing::get;
use axum::Router;
use serde::Serialize;
use sqlx::PgPool;
use std::convert::Infallible;
use std::sync::Arc;
use std::time::Duration;
use tokio_stream::StreamExt;

const INDEX_HTML: &str = include_str!("index.html");

#[derive(Clone)]
pub struct AppState {
    pub pool: PgPool,
}

#[derive(Debug, Serialize)]
struct StreamEvent {
    id: i64,
    sequence: i64,
    previous_hash: String,
    content_hash: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    payload: Option<serde_json::Value>,
    created_at: String,
}

async fn index() -> &'static str {
    INDEX_HTML
}

#[derive(Debug, serde::Deserialize)]
struct StreamQuery {
    after: Option<i64>,
}

async fn stream_events(
    State(state): State<Arc<AppState>>,
    Query(q): Query<StreamQuery>,
) -> Sse<impl futures_util::Stream<Item = Result<Event, Infallible>>> {
    let pool = state.pool.clone();
    let mut last_id = q.after.unwrap_or(0);

    let stream = async_stream::stream! {
        loop {
            let rows: Vec<(i64, i64, String, String, serde_json::Value, chrono::DateTime<chrono::Utc>)> = sqlx::query_as(
                "SELECT id, sequence, previous_hash, content_hash, payload, created_at FROM agent_events WHERE id > $1 ORDER BY id ASC",
            )
            .bind(last_id)
            .fetch_all(&pool)
            .await
            .unwrap_or_default();

            for row in rows {
                last_id = row.0;
                let ev = StreamEvent {
                    id: row.0,
                    sequence: row.1,
                    previous_hash: row.2,
                    content_hash: row.3,
                    payload: Some(row.4),
                    created_at: row.5.to_rfc3339(),
                };
                if let Ok(data) = serde_json::to_string(&ev) {
                    yield Ok(Event::default().event("event").id(row.0.to_string()).data(data));
                }
            }

            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    };

    let stream = stream.map(|r| r.map_err(|_: Infallible| unreachable!()));
    Sse::new(stream).keep_alive(
        axum::response::sse::KeepAlive::new()
            .interval(Duration::from_secs(15))
            .text("keep-alive"),
    )
}

pub fn router(pool: PgPool) -> Router {
    let state = Arc::new(AppState { pool });
    Router::new()
        .route("/", get(index))
        .route("/api/stream", get(stream_events))
        .with_state(state)
}
