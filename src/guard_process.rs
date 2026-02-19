// Process-isolated guard: spawns the guard-worker binary and communicates
// over stdin/stdout with a HMAC-SHA256 authenticated JSON protocol.
// Each request line is `<json>\t<hmac_hex>` where the HMAC covers the
// serialized nonce + goal + intent. Responses are likewise HMAC-authenticated.
// This prevents injected payload lines from spoofing approval messages.

use crate::guard::{GuardDecision, GuardExecutor};
use crate::intent::ProposedIntent;
use async_trait::async_trait;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::path::PathBuf;
use std::process::Stdio;
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::Command;

type HmacSha256 = Hmac<Sha256>;

const HMAC_KEY_ENV: &str = "GUARD_HMAC_KEY";

#[derive(serde::Serialize)]
struct GuardRequest {
    goal: String,
    intent: ProposedIntent,
    nonce: u64,
}

/// Compute HMAC-SHA256 over `nonce:json_body` using the session key.
fn compute_hmac(key: &[u8], nonce: u64, body: &str) -> String {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key size");
    mac.update(nonce.to_string().as_bytes());
    mac.update(b":");
    mac.update(body.as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

fn verify_hmac(key: &[u8], nonce: u64, body: &str, expected_hex: &str) -> bool {
    let got = compute_hmac(key, nonce, body);
    // Constant-time comparison using HMAC verify machinery.
    let Ok(expected_bytes) = hex::decode(expected_hex) else { return false; };
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key size");
    mac.update(nonce.to_string().as_bytes());
    mac.update(b":");
    mac.update(body.as_bytes());
    mac.verify_slice(&expected_bytes).is_ok() && !got.is_empty()
}

/// Resolves the path to the guard-worker binary (same directory as current executable).
fn guard_worker_path() -> Result<PathBuf, GuardProcessError> {
    let current_exe = std::env::current_exe().map_err(GuardProcessError::CurrentExe)?;
    let dir = current_exe.parent().ok_or(GuardProcessError::NoParent)?;
    let name = format!("guard-worker{}", std::env::consts::EXE_SUFFIX);
    Ok(dir.join(name))
}

pub struct GuardProcess {
    #[allow(dead_code)]
    child: tokio::process::Child,
    stdin: tokio::process::ChildStdin,
    reader: BufReader<tokio::process::ChildStdout>,
    hmac_key: Vec<u8>,
    nonce: AtomicU64,
}

#[derive(Debug)]
pub enum GuardProcessError {
    Spawn(String),
    CurrentExe(std::io::Error),
    NoParent,
    Io(std::io::Error),
    Json(serde_json::Error),
    UnexpectedEof,
    WorkerError(String),
    HmacMismatch,
}

impl std::fmt::Display for GuardProcessError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GuardProcessError::Spawn(s) => write!(f, "guard-worker spawn: {}", s),
            GuardProcessError::CurrentExe(e) => write!(f, "current exe: {}", e),
            GuardProcessError::NoParent => write!(f, "no parent directory for executable"),
            GuardProcessError::Io(e) => write!(f, "io: {}", e),
            GuardProcessError::Json(e) => write!(f, "json: {}", e),
            GuardProcessError::UnexpectedEof => write!(f, "guard-worker closed stdout unexpectedly"),
            GuardProcessError::WorkerError(s) => write!(f, "worker: {}", s),
            GuardProcessError::HmacMismatch => write!(f, "guard-worker response HMAC mismatch — possible spoofing attempt"),
        }
    }
}

impl std::error::Error for GuardProcessError {}

impl GuardProcess {
    /// Spawn the guard-worker binary. Generates a random session-scoped HMAC key
    /// and passes it to the child via `GUARD_HMAC_KEY` so the worker can
    /// authenticate requests and sign responses.
    pub fn spawn() -> Result<Self, GuardProcessError> {
        let path = guard_worker_path()?;
        if !path.exists() {
            return Err(GuardProcessError::Spawn(format!(
                "guard-worker binary not found at {} (build with `cargo build` to produce both binaries)",
                path.display()
            )));
        }

        // Generate a 32-byte random HMAC key for this session.
        let hmac_key: [u8; 32] = rand::random();
        let hmac_key_hex = hex::encode(hmac_key);

        let mut child = Command::new(&path)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .env(HMAC_KEY_ENV, &hmac_key_hex)
            .spawn()
            .map_err(|e| GuardProcessError::Spawn(e.to_string()))?;
        let stdin = child
            .stdin
            .take()
            .ok_or_else(|| GuardProcessError::Spawn("stdin not captured".to_string()))?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| GuardProcessError::Spawn("stdout not captured".to_string()))?;
        let reader = BufReader::new(stdout);
        Ok(GuardProcess {
            child,
            stdin,
            reader,
            hmac_key: hmac_key.to_vec(),
            nonce: AtomicU64::new(0),
        })
    }

    pub async fn evaluate(
        &mut self,
        goal: &str,
        proposed: &ProposedIntent,
    ) -> Result<GuardDecision, GuardProcessError> {
        let nonce = self.nonce.fetch_add(1, Ordering::Relaxed);

        let req = GuardRequest {
            goal: goal.to_string(),
            intent: proposed.clone(),
            nonce,
        };
        let json = serde_json::to_string(&req).map_err(GuardProcessError::Json)?;
        let mac = compute_hmac(&self.hmac_key, nonce, &json);

        // Format: `<json>\t<hmac_hex>\n`
        let line = format!("{}\t{}\n", json, mac);
        self.stdin
            .write_all(line.as_bytes())
            .await
            .map_err(GuardProcessError::Io)?;
        self.stdin.flush().await.map_err(GuardProcessError::Io)?;

        let mut response = String::new();
        let n = self
            .reader
            .read_line(&mut response)
            .await
            .map_err(GuardProcessError::Io)?;
        if n == 0 {
            return Err(GuardProcessError::UnexpectedEof);
        }

        // Parse response: `ALLOW\t<hmac_hex>` or `DENY: reason\t<hmac_hex>`
        let raw = response.trim();
        let (verdict, resp_mac) = match raw.rsplit_once('\t') {
            Some(parts) => parts,
            None => {
                // No HMAC tab separator — treat as unauthenticated/spoofed.
                tracing::error!("Guard response missing HMAC tab; treating as deny");
                return Ok(GuardDecision::Deny {
                    reason: "unauthenticated guard response".to_string(),
                });
            }
        };

        if !verify_hmac(&self.hmac_key, nonce, verdict, resp_mac) {
            tracing::error!("Guard response HMAC mismatch — possible spoofing attempt");
            return Err(GuardProcessError::HmacMismatch);
        }

        if verdict.to_uppercase().starts_with("ALLOW") {
            return Ok(GuardDecision::Allow);
        }
        if verdict.to_uppercase().starts_with("DENY") {
            let reason = verdict
                .strip_prefix("DENY")
                .or_else(|| verdict.strip_prefix("deny"))
                .map(|s| s.trim_start_matches(':').trim().to_string())
                .unwrap_or_else(|| verdict.to_string());
            return Ok(GuardDecision::Deny { reason });
        }
        // Unknown verdict — fail closed.
        Ok(GuardDecision::Deny {
            reason: format!("unrecognised guard verdict: {}", verdict),
        })
    }
}

#[async_trait]
impl GuardExecutor for GuardProcess {
    async fn evaluate(
        &mut self,
        goal: &str,
        proposed: &ProposedIntent,
    ) -> Result<GuardDecision, Box<dyn std::error::Error + Send + Sync>> {
        GuardProcess::evaluate(self, goal, proposed)
            .await
            .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)
    }
}
