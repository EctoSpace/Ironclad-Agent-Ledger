// Process-isolated guard: spawns the guard-worker binary and communicates
// over stdin/stdout with a minimal JSON protocol for real isolation
// (separate OS process, separate credentials, different model class).

use crate::guard::{GuardDecision, GuardExecutor};
use crate::intent::ProposedIntent;
use async_trait::async_trait;
use std::path::PathBuf;
use std::process::Stdio;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::Command;

#[derive(serde::Serialize)]
struct GuardRequest {
    goal: String,
    intent: ProposedIntent,
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
        }
    }
}

impl std::error::Error for GuardProcessError {}

impl GuardProcess {
    /// Spawn the guard-worker binary. Fails if the binary is not found or cannot be started.
    pub fn spawn() -> Result<Self, GuardProcessError> {
        let path = guard_worker_path()?;
        if !path.exists() {
            return Err(GuardProcessError::Spawn(format!(
                "guard-worker binary not found at {} (build with `cargo build` to produce both binaries)",
                path.display()
            )));
        }
        let mut child = Command::new(&path)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
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
        })
    }

    pub async fn evaluate(
        &mut self,
        goal: &str,
        proposed: &ProposedIntent,
    ) -> Result<GuardDecision, GuardProcessError> {
        let req = GuardRequest {
            goal: goal.to_string(),
            intent: proposed.clone(),
        };
        let line = serde_json::to_string(&req).map_err(GuardProcessError::Json)?;
        self.stdin
            .write_all(line.as_bytes())
            .await
            .map_err(GuardProcessError::Io)?;
        self.stdin
            .write_all(b"\n")
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
        let raw = response.trim();
        if raw.to_uppercase().starts_with("ALLOW") {
            return Ok(GuardDecision::Allow);
        }
        if raw.to_uppercase().starts_with("DENY") {
            let reason = raw
                .strip_prefix("DENY")
                .or_else(|| raw.strip_prefix("deny"))
                .map(|s| s.trim_start_matches(':').trim().to_string())
                .unwrap_or_else(|| raw.to_string());
            return Ok(GuardDecision::Deny { reason });
        }
        Ok(GuardDecision::Allow)
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
