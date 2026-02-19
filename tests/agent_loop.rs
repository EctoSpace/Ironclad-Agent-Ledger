mod common;

use common::{assert_chain_valid, reset_ledger, spawn_test_pool, MockLlmBackend};
use ironclad_agent_ledger::agent::{self, AgentLoopConfig};
use ironclad_agent_ledger::ledger;
use ironclad_agent_ledger::schema::EventPayload;
use ironclad_agent_ledger::tripwire::{self, Tripwire};
use ironclad_agent_ledger::intent::ProposedIntent;
use std::path::PathBuf;

#[tokio::test]
#[ignore] // requires Postgres (run with: cargo test --ignored)
async fn mock_llm_read_file_then_complete() {
    let (pool, _db) = spawn_test_pool().await;
    reset_ledger(&pool).await;
    ledger::ensure_genesis(&pool).await.expect("genesis");
    ledger::append_event(
        &pool,
        EventPayload::Thought {
            content: "Audit goal: read test".to_string(),
        },
        None,
    )
    .await
    .expect("append");

    let mock = MockLlmBackend::new(vec![
        ProposedIntent {
            action: "read_file".to_string(),
            params: serde_json::json!({"path": "Cargo.toml"}),
            justification: "Read Cargo.toml to inspect project dependencies.".to_string(),
            reasoning: "First step of audit: enumerate project structure.".to_string(),
        },
        ProposedIntent {
            action: "complete".to_string(),
            params: serde_json::json!({"findings": []}),
            justification: "Audit complete; all planned checks finished.".to_string(),
            reasoning: "No findings from dependency review.".to_string(),
        },
    ]);
    let workspace = PathBuf::from(".").canonicalize().unwrap_or_else(|_| PathBuf::from("."));
    let tripwire = Tripwire::new(
        vec![workspace],
        vec![],
        tripwire::default_banned_command_patterns(),
    );
    let config = AgentLoopConfig {
        llm: Box::new(mock),
        tripwire: &tripwire,
        max_steps: Some(10),
        session_id: None,
        session_goal: "read test".to_string(),
        guard: None,
        metrics: None,
    };
    let client = reqwest::Client::new();
    agent::run_cognitive_loop(&pool, &client, config).await.expect("loop");

    let latest = ledger::get_latest(&pool).await.expect("get_latest");
    let (seq, _) = latest.expect("has events");
    assert!(seq >= 2, "expected at least 2 events (action + observation + complete)");
    assert_chain_valid(&pool, 0, seq).await;
}
