// IronClad Audit Certificate (.iac)
//
// Produces a self-contained, cryptographically verifiable audit record from a completed session.
// The certificate bundles:
//   - The full event hash-chain (sequence + content_hash pairs)
//   - A binary Merkle tree over all event content_hashes
//   - Per-finding Merkle inclusion proofs
//   - An (optional) OpenTimestamps stamp over the ledger tip hash
//   - An Ed25519 signature over the canonical JSON of all other fields
//
// The canonical JSON is produced with keys sorted alphabetically via `serde_json::to_string`
// on a `BTreeMap`, so the signature can be re-verified deterministically on any platform.

use crate::hash::sha256_hex;
use crate::ledger;
use crate::merkle::{self, MerkleProof};
use crate::ots::{self, OtsError};
use crate::schema::{AuditFinding, LedgerEventRow, SessionRow};
use crate::signing;
use ed25519_dalek::SigningKey;
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use std::collections::BTreeMap;
use uuid::Uuid;

/// One entry in the event chain embedded in the certificate.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CertEventEntry {
    pub sequence: i64,
    pub content_hash: String,
}

/// A finding as captured in the certificate, enriched with its Merkle proof.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CertFinding {
    pub title: String,
    pub severity: String,
    /// Ledger sequence numbers that support this finding.
    pub evidence_sequence: Vec<i64>,
    /// Exact quotes from those observations.
    pub evidence_quotes: Vec<String>,
    /// Merkle inclusion proofs for each evidence event (one proof per sequence entry).
    pub merkle_proofs: Vec<MerkleProof>,
}

/// The complete IronClad Audit Certificate.
/// Serialized with keys sorted alphabetically for deterministic signatures.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IronCladCertificate {
    pub version: u32,
    pub session_id: Uuid,
    pub goal: String,
    pub goal_hash: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_public_key: Option<String>,
    /// SHA-256 content_hash of the last event in the session.
    pub ledger_tip_hash: String,
    /// Merkle root of all event content_hashes in sequence order.
    pub merkle_root: String,
    pub event_count: u64,
    pub started_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub completed_at: Option<String>,
    /// Full chain for reconstruction (sequence + content_hash pairs).
    pub events: Vec<CertEventEntry>,
    /// Audit findings with Merkle proof paths.
    pub findings: Vec<CertFinding>,
    /// OpenTimestamps stamp over the ledger tip hash (hex-encoded binary blob).
    /// `null` if OTS submission was skipped or failed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ots_proof_hex: Option<String>,
    /// Ed25519 signature over the canonical JSON of all other fields (hex).
    /// To verify: remove this field, re-serialize as canonical JSON, verify against `session_public_key`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
}

/// Error type for certificate operations.
#[derive(Debug)]
pub enum CertificateError {
    Db(sqlx::Error),
    SessionNotFound,
    NoEvents,
    Serialize(serde_json::Error),
    Ots(OtsError),
    Io(std::io::Error),
}

impl std::fmt::Display for CertificateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CertificateError::Db(e) => write!(f, "database: {}", e),
            CertificateError::SessionNotFound => write!(f, "session not found"),
            CertificateError::NoEvents => write!(f, "session has no events"),
            CertificateError::Serialize(e) => write!(f, "serialize: {}", e),
            CertificateError::Ots(e) => write!(f, "ots: {}", e),
            CertificateError::Io(e) => write!(f, "io: {}", e),
        }
    }
}

impl std::error::Error for CertificateError {}

// ── Canonical JSON serialization ───────────────────────────────────────────────

/// Serializes a certificate to canonical JSON (BTreeMap key order) suitable for signing.
/// The `signature` field is excluded from the signed payload.
pub fn canonical_json_for_signing(cert: &IronCladCertificate) -> Result<String, serde_json::Error> {
    // Convert to serde_json::Value, remove the signature field, then
    // re-serialize via a BTreeMap to guarantee alphabetically sorted keys.
    let mut val = serde_json::to_value(cert)?;
    if let Some(obj) = val.as_object_mut() {
        obj.remove("signature");
    }
    // Re-serialize through a sorted BTreeMap at the top level.
    let sorted: BTreeMap<String, serde_json::Value> = match val {
        serde_json::Value::Object(m) => m.into_iter().collect(),
        _ => BTreeMap::new(),
    };
    serde_json::to_string(&sorted)
}

// ── Main builder ───────────────────────────────────────────────────────────────

/// Build a complete `IronCladCertificate` for the given session.
///
/// Steps:
/// 1. Load the session and all its events from the DB.
/// 2. Build a binary Merkle tree over event content_hashes (in sequence order).
/// 3. Extract any findings from the final `Action{complete}` event and compute per-finding proofs.
/// 4. Optionally submit the ledger tip to OTS (can be disabled via `submit_ots: false`).
/// 5. Sign the canonical JSON with the provided `signing_key`.
pub async fn build_certificate(
    pool: &PgPool,
    session_id: Uuid,
    signing_key: Option<&SigningKey>,
    submit_ots: bool,
) -> Result<IronCladCertificate, CertificateError> {
    // 1. Load session metadata.
    let sessions = ledger::list_sessions(pool)
        .await
        .map_err(CertificateError::Db)?;
    let session: SessionRow = sessions
        .into_iter()
        .find(|s| s.id == session_id)
        .ok_or(CertificateError::SessionNotFound)?;

    // 2. Load all events for this session.
    let events: Vec<LedgerEventRow> = ledger::get_events_by_session(pool, session_id)
        .await
        .map_err(CertificateError::Db)?;

    if events.is_empty() {
        return Err(CertificateError::NoEvents);
    }

    let ledger_tip_hash = events.last().unwrap().content_hash.clone();

    // 3. Build Merkle tree over content_hashes in sequence order.
    let content_hashes: Vec<&str> = events.iter().map(|e| e.content_hash.as_str()).collect();
    let tree = merkle::build_merkle_tree(&content_hashes);
    let merkle_root = merkle::root(&tree);

    // Build a lookup from content_hash → leaf_index for proof generation.
    let hash_to_leaf: std::collections::HashMap<&str, usize> = content_hashes
        .iter()
        .enumerate()
        .map(|(i, h)| (*h, i))
        .collect();

    // 4. Extract findings from the last `complete` action (if any).
    let findings = extract_findings_with_proofs(&events, &tree, &hash_to_leaf);

    // 5. OTS stamp.
    let ots_proof_hex = if submit_ots {
        match ots::submit_ots_stamp(&ledger_tip_hash).await {
            Ok(bytes) => Some(hex::encode(bytes)),
            Err(e) => {
                tracing::warn!("OTS submission failed (certificate will have null ots_proof_hex): {}", e);
                None
            }
        }
    } else {
        None
    };

    // Assemble certificate without signature first.
    let goal_hash = session
        .goal_hash
        .clone()
        .unwrap_or_else(|| sha256_hex(session.goal.as_bytes()));

    let cert_events: Vec<CertEventEntry> = events
        .iter()
        .map(|e| CertEventEntry {
            sequence: e.sequence,
            content_hash: e.content_hash.clone(),
        })
        .collect();

    let mut cert = IronCladCertificate {
        version: 1,
        session_id,
        goal: session.goal.clone(),
        goal_hash,
        policy_hash: session.policy_hash.clone(),
        session_public_key: session.session_public_key.clone(),
        ledger_tip_hash,
        merkle_root,
        event_count: events.len() as u64,
        started_at: session.created_at.to_rfc3339(),
        completed_at: session.finished_at.map(|t| t.to_rfc3339()),
        events: cert_events,
        findings,
        ots_proof_hex,
        signature: None,
    };

    // 6. Sign canonical JSON.
    if let Some(sk) = signing_key {
        let payload = canonical_json_for_signing(&cert).map_err(CertificateError::Serialize)?;
        let sig = signing::sign_content_hash(sk, &payload);
        cert.signature = Some(sig);
    }

    Ok(cert)
}

/// Extract `AuditFinding` entries from the last `complete` action event and enrich with Merkle proofs.
fn extract_findings_with_proofs(
    events: &[LedgerEventRow],
    tree: &merkle::MerkleTree,
    hash_to_leaf: &std::collections::HashMap<&str, usize>,
) -> Vec<CertFinding> {
    // Build a sequence → content_hash lookup to find evidence proofs.
    let seq_to_hash: std::collections::HashMap<i64, &str> = events
        .iter()
        .map(|e| (e.sequence, e.content_hash.as_str()))
        .collect();

    let raw_findings: Vec<AuditFinding> = events
        .iter()
        .rev()
        .find_map(|e| {
            if let crate::schema::EventPayload::Action { name, params } = &e.payload {
                if name == "complete" {
                    if let Some(f) = params.get("findings") {
                        return serde_json::from_value::<Vec<AuditFinding>>(f.clone()).ok();
                    }
                }
            }
            None
        })
        .unwrap_or_default();

    raw_findings
        .into_iter()
        .map(|f| {
            let merkle_proofs = f
                .evidence_sequence
                .iter()
                .filter_map(|seq| {
                    let hash = seq_to_hash.get(seq)?;
                    let leaf_idx = *hash_to_leaf.get(hash)?;
                    Some(merkle::proof(tree, leaf_idx))
                })
                .collect();

            CertFinding {
                title: f.title,
                severity: format!("{:?}", f.severity).to_lowercase(),
                evidence_sequence: f.evidence_sequence,
                evidence_quotes: f.evidence_quotes,
                merkle_proofs,
            }
        })
        .collect()
}

/// Serialize a certificate to pretty-printed JSON and write it to a file.
pub fn write_certificate_file(
    cert: &IronCladCertificate,
    path: &std::path::Path,
) -> Result<(), CertificateError> {
    let json = serde_json::to_string_pretty(cert).map_err(CertificateError::Serialize)?;
    std::fs::write(path, json.as_bytes()).map_err(CertificateError::Io)
}

/// Read a certificate from a `.iac` file.
pub fn read_certificate_file(
    path: &std::path::Path,
) -> Result<IronCladCertificate, CertificateError> {
    let bytes = std::fs::read(path).map_err(CertificateError::Io)?;
    serde_json::from_slice(&bytes).map_err(CertificateError::Serialize)
}
