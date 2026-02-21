// Binary schemas used in the SP1 zkVM guest/host protocol.
//
// These types are serialized with `bincode` for high-throughput guest I/O.
// All three derive `serde::{Serialize, Deserialize}` so they work with both
// `bincode` (inside the zkVM) and `serde_json` (for diagnostics on the host).

/// A single link in the tamper-evident event hash chain passed to the guest.
///
/// The guest re-derives `content_hash = sha256(previous_hash || sequence || payload_json)` for
/// every event and verifies that each link's `previous_hash` equals the prior computed hash.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct ChainEvent {
    /// Monotonically increasing position in the ledger (0-based genesis event = 0).
    pub sequence: i64,
    /// SHA-256 content hash of the *previous* event (all-zeros hex for genesis).
    pub previous_hash: String,
    /// Raw JSON payload string used verbatim during hash chain computation.
    pub payload_json: String,
}

/// Everything the SP1 guest program needs to produce a validity proof.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct GuestInput {
    /// Expected SHA-256 content hash of the genesis event (event 0).
    pub genesis_hash: String,
    /// Expected SHA-256 content hash of the final event (ledger tip).
    pub tip_hash: String,
    /// Expected Merkle root of all event content hashes (in sequence order).
    pub merkle_root: String,
    /// Full ordered event chain. Length must be ≥ 1 (genesis event always present).
    pub events: Vec<ChainEvent>,
    /// Flat list of `regex-lite`-compatible patterns the guest compiles once.
    /// Each event's `payload_json` is checked against all patterns; a match is a violation.
    pub policy_patterns: Vec<String>,
}

/// The guest's verdict, committed to the SP1 proof public values.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct GuestOutput {
    /// `true` when every check passed; `false` is never committed (the guest panics instead).
    pub verified: bool,
    /// Number of events that were checked.
    pub event_count: u64,
    /// Human-readable description of each policy violation found (empty on success).
    pub violations: Vec<String>,
}
