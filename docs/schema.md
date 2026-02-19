# Ironclad Agent Ledger — Schema

## Design

- **Agent state** lives in PostgreSQL. The Rust process is a transient worker.
- **Event log** is append-only and hash-chained to prevent tampering and support verification.
- **Snapshots** are derived from the log for fast state recovery (wake-up).

## Tables

### `agent_events` (immutable)

| Column         | Type         | Description |
|----------------|--------------|-------------|
| `id`           | BIGSERIAL    | Primary key. |
| `sequence`     | BIGINT       | Strict ordering; unique. Genesis block uses `sequence = 0`. |
| `previous_hash`| VARCHAR(64)  | SHA-256 hex of the **previous** row’s `content_hash`. For genesis, a fixed constant (e.g. 64 zero hex chars). |
| `content_hash` | VARCHAR(64)  | SHA-256 hex of this event: `previous_hash || sequence || payload_json` (deterministic). |
| `payload`      | JSONB        | Event body (e.g. thought, action, observation, genesis). |
| `created_at`   | TIMESTAMPTZ  | Insert time. |

**Invariants:** No `UPDATE` or `DELETE` in application code. Each row’s `previous_hash` must equal the previous row’s `content_hash`.

### `agent_snapshots` (mutable)

| Column       | Type        | Description |
|--------------|-------------|-------------|
| `id`         | UUID        | Primary key. |
| `sequence`   | BIGINT      | Last replayed event `sequence` for this snapshot. |
| `state_hash`| VARCHAR(64) | SHA-256 hex of canonical snapshot payload (for verification). |
| `payload`   | JSONB       | Aggregated state / performance summary. |
| `created_at`| TIMESTAMPTZ | Insert time. |

Used by the **wake-up protocol**: load latest snapshot by `sequence`, then replay events where `sequence > snapshot.sequence`.

## Genesis rule

- The first event has `sequence = 0` and `previous_hash = GENESIS_PREVIOUS_HASH` (e.g. 64 zero hex characters).
- `content_hash` is computed the same way as for any other event.
