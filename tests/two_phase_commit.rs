mod common;

use common::{reset_ledger, spawn_test_pool};
use ironclad_agent_ledger::ledger;
use ironclad_agent_ledger::schema::EventPayload;
use ironclad_agent_ledger::wakeup;

#[tokio::test]
#[ignore] // requires Postgres (run with: cargo test --ignored)
async fn recover_incomplete_actions_appends_failure_observation() {
    let (pool, _db) = spawn_test_pool().await;
    reset_ledger(&pool).await;
    ledger::ensure_genesis(&pool).await.expect("genesis");
    let appended = ledger::append_event(
        &pool,
        EventPayload::Action {
            name: "read_file".to_string(),
            params: serde_json::json!({"path": "Cargo.toml"}),
        },
        None,
        None,
        None,
    )
    .await
    .expect("append");
    ledger::mark_action_executing(&pool, appended.id).await.expect("mark_executing");

    wakeup::recover_incomplete_actions(&pool).await.expect("recover");

    let events = ledger::get_events(&pool, 0, 10).await.expect("get_events");
    let has_recovered_observation = events.iter().any(|e| {
        if let EventPayload::Observation { content } = &e.payload {
            content.contains("recovered from previous run")
        } else {
            false
        }
    });
    assert!(has_recovered_observation, "expected a recovery observation to be appended");
}
