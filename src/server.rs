use axum::extract::{ConnectInfo, Query, Request, State};
use axum::http::StatusCode;
use axum::middleware::Next;
use axum::response::sse::{Event, Sse};
use axum::response::Html;
use axum::routing::get;
use axum::Router;
use crate::config;
use crate::ledger;
use serde::Serialize;
use sqlx::PgPool;
use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio_stream::StreamExt;
use tower_governor::{governor::GovernorConfigBuilder, key_extractor::SmartIpKeyExtractor, GovernorLayer};
use uuid::Uuid;

use crate::metrics::Metrics;

const INDEX_HTML: &str = include_str!("index.html");

#[derive(Clone)]
pub struct AppState {
    pub pool: PgPool,
    pub metrics: Arc<Metrics>,
    pub observer_token: Option<String>,
}

async fn require_auth(
    State(state): State<Arc<AppState>>,
    request: Request,
    next: Next,
) -> Result<axum::response::Response, StatusCode> {
    let Some(expected) = &state.observer_token else {
        return Ok(next.run(request).await);
    };
    let (parts, body) = request.into_parts();
    let bearer = parts
        .headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "));
    let query_token = parts.uri.query().and_then(|q| {
        q.split('&')
            .find_map(|pair| {
                let (k, v) = pair.split_once('=')?;
                if k == "token" { Some(v.to_string()) } else { None }
            })
    });
    let provided = bearer.or(query_token.as_deref());
    if provided.map(|t| t == expected.as_str()) == Some(true) {
        return Ok(next.run(Request::from_parts(parts, body)).await);
    }
    Err(StatusCode::UNAUTHORIZED)
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

async fn index() -> Html<&'static str> {
    Html(INDEX_HTML)
}

#[derive(Debug, serde::Deserialize)]
struct StreamQuery {
    after: Option<i64>,
    session_id: Option<Uuid>,
}

async fn stream_events(
    State(state): State<Arc<AppState>>,
    Query(q): Query<StreamQuery>,
    ConnectInfo(_addr): ConnectInfo<SocketAddr>,
) -> Sse<impl futures_util::Stream<Item = Result<Event, Infallible>>> {
    let pool = state.pool.clone();
    let mut last_id = q.after.unwrap_or(0);
    let session_id = q.session_id;

    let stream = async_stream::stream! {
        loop {
            let rows: Vec<(i64, i64, String, String, serde_json::Value, chrono::DateTime<chrono::Utc>)> = if let Some(sid) = session_id {
                sqlx::query_as(
                    "SELECT id, sequence, previous_hash, content_hash, payload, created_at FROM agent_events WHERE id > $1 AND session_id = $2 ORDER BY id ASC",
                )
                .bind(last_id)
                .bind(sid)
                .fetch_all(&pool)
                .await
                .unwrap_or_default()
            } else {
                sqlx::query_as(
                    "SELECT id, sequence, previous_hash, content_hash, payload, created_at FROM agent_events WHERE id > $1 ORDER BY id ASC",
                )
                .bind(last_id)
                .fetch_all(&pool)
                .await
                .unwrap_or_default()
            };

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

async fn list_sessions(
    State(state): State<Arc<AppState>>,
) -> axum::Json<Vec<crate::schema::SessionRow>> {
    let sessions = ledger::list_sessions(&state.pool).await.unwrap_or_default();
    axum::Json(sessions)
}

async fn metrics_handler(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
) -> ([(axum::http::header::HeaderName, &'static str); 1], String) {
    let body = state.metrics.prometheus_text();

    let wants_html = headers
        .get(axum::http::header::ACCEPT)
        .and_then(|v| v.to_str().ok())
        .map(|a| a.contains("text/html"))
        .unwrap_or(false);

    if wants_html {
        let html = format!(
            r#"<!DOCTYPE html><html lang="en"><head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Ironclad — Metrics</title>
<style>
  body{{margin:0;background:#0d1117;color:#c9d1d9;font-family:"SF Mono","Fira Code",Consolas,monospace;font-size:13px;padding:16px;}}
  h2{{color:#58a6ff;font-size:14px;margin-bottom:12px;}}
  pre{{white-space:pre-wrap;word-break:break-all;background:#161b22;padding:16px;border-radius:4px;border:1px solid #21262d;}}
  a{{color:#58a6ff;font-size:12px;}}
</style>
</head><body>
<h2>Ironclad Agent Ledger — Prometheus Metrics</h2>
<pre>{}</pre>
<a href="/">&larr; Observer dashboard</a>
</body></html>"#,
            body
        );
        (
            [(axum::http::header::CONTENT_TYPE, "text/html; charset=utf-8")],
            html,
        )
    } else {
        (
            [(axum::http::header::CONTENT_TYPE, "text/plain; charset=utf-8")],
            body,
        )
    }
}

pub fn router(pool: PgPool, metrics: Arc<crate::metrics::Metrics>) -> Router {
    let observer_token = config::observer_token();
    if observer_token.is_none() {
        tracing::warn!("OBSERVER_TOKEN is unset; dashboard is unauthenticated");
    }
    let state = Arc::new(AppState {
        pool,
        metrics,
        observer_token,
    });

    let governor_conf = Arc::new(
        GovernorConfigBuilder::default()
            .key_extractor(SmartIpKeyExtractor)
            .per_second(10)
            .burst_size(30)
            .finish()
            .expect("governor config"),
    );

    let stream_router = Router::new()
        .route("/api/stream", get(stream_events))
        .route_layer(GovernorLayer {
            config: governor_conf,
        });

    Router::new()
        .route("/", get(index))
        .route("/api/sessions", get(list_sessions))
        .route("/metrics", get(metrics_handler))
        .merge(stream_router)
        .route_layer(axum::middleware::from_fn_with_state(
            state.clone(),
            require_auth,
        ))
        .with_state(state)
}
