mod common;

use common::{assert_chain_valid, reset_ledger, spawn_test_pool};
use ironclad_agent_ledger::ledger;
use ironclad_agent_ledger::schema::EventPayload;
use ironclad_agent_ledger::snapshot;
use ironclad_agent_ledger::wakeup;

#[tokio::test]
#[ignore] // requires Postgres (run with: cargo test --ignored)
async fn append_100_snapshot_then_restore() {
    let (pool, _db) = spawn_test_pool().await;
    reset_ledger(&pool).await;
    ledger::ensure_genesis(&pool).await.expect("genesis");
    for i in 1..=100 {
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
    let (latest_seq, _) = ledger::get_latest(&pool).await.expect("get_latest").expect("events");
    assert_chain_valid(&pool, 0, latest_seq).await;

    let row = snapshot::snapshot_at_sequence(&pool, latest_seq).await.expect("snapshot_at_sequence");
    assert_eq!(row.sequence, latest_seq);

    let state = wakeup::restore_state(&pool, true).await.expect("restore_state");
    assert_eq!(state.snapshot_sequence, latest_seq);
    assert!(state.replayed_events.is_empty(), "restore from snapshot should have no replayed events when at tip");
}
