// OpenTimestamps integration — shared between `certificate.rs` and the `anchor-session` CLI command.
//
// Submits a SHA-256 digest (hex) to the public OTS aggregator pool and returns
// the raw (incomplete) binary stamp. The stamp is stored hex-encoded in certificates
// and Anchor ledger events. Confirmation against a Bitcoin block happens later
// when the aggregator finalises the calendar commitment.

use reqwest::Client;

/// Errors that can arise from OTS operations.
#[derive(Debug)]
pub enum OtsError {
    Http(reqwest::Error),
    InvalidHex(hex::FromHexError),
    Unexpected(String),
}

impl std::fmt::Display for OtsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OtsError::Http(e) => write!(f, "http: {}", e),
            OtsError::InvalidHex(e) => write!(f, "hex decode: {}", e),
            OtsError::Unexpected(s) => write!(f, "{}", s),
        }
    }
}

impl std::error::Error for OtsError {}

/// Submits a SHA-256 digest (hex-encoded) to the OTS aggregator pool.
/// Returns the raw (incomplete) OTS stamp bytes, hex-encoded.
///
/// The returned stamp can be upgraded to a complete Bitcoin timestamp by
/// calling `ots upgrade <stamp-file>` once the aggregator has committed.
pub async fn submit_ots_stamp(ledger_tip_hash: &str) -> Result<Vec<u8>, OtsError> {
    let digest = hex::decode(ledger_tip_hash).map_err(OtsError::InvalidHex)?;
    let client = Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .map_err(OtsError::Http)?;
    let resp = client
        .post("https://a.pool.opentimestamps.org/digest")
        .header("Content-Type", "application/octet-stream")
        .body(digest)
        .send()
        .await
        .map_err(OtsError::Http)?;
    if !resp.status().is_success() {
        return Err(OtsError::Unexpected(format!(
            "OTS server returned {}",
            resp.status()
        )));
    }
    let bytes = resp.bytes().await.map_err(OtsError::Http)?;
    Ok(bytes.to_vec())
}
