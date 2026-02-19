mod common;

use common::{assert_chain_valid, reset_ledger, spawn_test_pool};
use ironclad_agent_ledger::ledger;
use ironclad_agent_ledger::schema::EventPayload;

#[tokio::test]
#[ignore] // requires Postgres (run with: cargo test --ignored)
async fn genesis_valid() {
    let (pool, _db) = spawn_test_pool().await;
    reset_ledger(&pool).await;
    let appended = ledger::ensure_genesis(&pool).await.expect("ensure_genesis");
    assert_eq!(appended.sequence, 0);
    assert_chain_valid(&pool, 0, 0).await;
}

#[tokio::test]
#[ignore] // requires Postgres (run with: cargo test --ignored)
async fn chain_of_10_valid() {
    let (pool, _db) = spawn_test_pool().await;
    reset_ledger(&pool).await;
    ledger::ensure_genesis(&pool).await.expect("ensure_genesis");
    for i in 1..=10 {
        ledger::append_event(
            &pool,
            EventPayload::Thought {
                content: format!("step {}", i),
            },
            None,
        )
        .await
        .expect("append");
    }
    assert_chain_valid(&pool, 0, 10).await;
}

#[tokio::test]
#[ignore] // requires Postgres (run with: cargo test --ignored)
async fn tampered_hash_detected() {
    let (pool, _db) = spawn_test_pool().await;
    reset_ledger(&pool).await;
    ledger::ensure_genesis(&pool).await.expect("ensure_genesis");
    ledger::append_event(
        &pool,
        EventPayload::Thought {
            content: "one".to_string(),
        },
        None,
    )
    .await
    .expect("append");
    // Tamper: change content_hash of the last event
    sqlx::query("UPDATE agent_events SET content_hash = 'tampered' WHERE sequence = 1")
        .execute(&pool)
        .await
        .expect("update");
    let valid = ledger::verify_chain(&pool, 0, 1).await.expect("verify");
    assert!(!valid);
}
