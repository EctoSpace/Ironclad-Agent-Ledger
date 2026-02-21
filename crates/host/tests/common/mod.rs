// Helpers for integration tests (used when tests are run with --ignored).
#![allow(dead_code)]

use ironclad_agent_ledger::ledger;
use ironclad_agent_ledger::llm::{LlmBackend, LlmError};
use ironclad_agent_ledger::intent::ProposedIntent;
use ironclad_agent_ledger::db_setup;
use ironclad_agent_ledger::config;
use async_trait::async_trait;
use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;
use std::collections::VecDeque;
use std::sync::Mutex;

pub async fn spawn_test_pool() -> (PgPool, ironclad_agent_ledger::db_setup::EmbeddedDb) {
    let url = config::database_url().expect("DATABASE_URL");
    let (database_url, embedded) = db_setup::ensure_postgres_ready(&url).await.expect("postgres ready");
    let pool = PgPoolOptions::new()
        .max_connections(2)
        .connect(&database_url)
        .await
        .expect("connect");
    sqlx::migrate!("./migrations").run(&pool).await.expect("migrate");
    (pool, embedded)
}

pub async fn reset_ledger(pool: &PgPool) {
    sqlx::query("TRUNCATE agent_events, agent_action_log, agent_snapshots, agent_sessions RESTART IDENTITY CASCADE")
        .execute(pool)
        .await
        .expect("truncate");
}

pub async fn assert_chain_valid(pool: &PgPool, from: i64, to: i64) {
    let valid = ledger::verify_chain(pool, from, to).await.expect("verify_chain");
    assert!(valid, "chain verification failed for sequence {}..{}", from, to);
}

pub struct MockLlmBackend {
    responses: Mutex<VecDeque<ProposedIntent>>,
}

impl MockLlmBackend {
    pub fn new(responses: Vec<ProposedIntent>) -> Self {
        Self {
            responses: Mutex::new(responses.into_iter().collect()),
        }
    }
}

#[async_trait]
impl LlmBackend for MockLlmBackend {
    async fn propose(&self, _system: &str, _user: &str) -> Result<ProposedIntent, LlmError> {
        let mut r = self.responses.lock().expect("lock");
        r.pop_front().ok_or(LlmError::EmptyResponse)
    }

    async fn raw_call(&self, _system: &str, _user: &str) -> Result<String, LlmError> {
        Err(LlmError::EmptyResponse)
    }

    fn backend_name(&self) -> &str {
        "mock"
    }

    fn model_name(&self) -> &str {
        "mock"
    }
}
