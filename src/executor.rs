use crate::intent::ValidatedIntent;
use std::time::Duration;
use tokio::process::Command;
#[cfg(target_os = "linux")]
use std::os::unix::process::CommandExt as _;

const CMD_TIMEOUT_SECS: u64 = 30;
const CMD_MAX_OUTPUT_BYTES: usize = 32 * 1024;
const FILE_MAX_BYTES: usize = 256 * 1024;
const HTTP_TIMEOUT_SECS: u64 = 10;
const HTTP_MAX_BODY_BYTES: usize = 64 * 1024;

const ALLOWED_PROGRAMS: &[&str] = &[
    "ls",
    "cat",
    "find",
    "grep",
    "head",
    "tail",
    "wc",
    "stat",
    "file",
    "diff",
    "md5sum",
    "sha256sum",
    "sha1sum",
    "ps",
    "env",
    "echo",
    "date",
    "id",
    "hostname",
    "uname",
    "df",
    "du",
    "pwd",
    "which",
    "whoami",
    "netstat",
    "ss",
    "lsof",
    // "nmap" and "openssl" removed: network pivoting risk. Add via AGENT_ALLOWED_PROGRAMS if needed.
    // "wget" removed: curl covers the same use case and is already in the tripwire ban list.
    //   wget supports recursive download (-r) and mirror (-m) which increase exfiltration surface.
    //   To re-enable, add "wget" to the AGENT_ALLOWED_PROGRAMS env var (comma-separated).
    "curl",
];

fn allowed_programs() -> Vec<String> {
    let mut list: Vec<String> = ALLOWED_PROGRAMS.iter().map(|s| (*s).to_string()).collect();
    if let Ok(extra) = std::env::var("AGENT_ALLOWED_PROGRAMS") {
        for s in extra.split(',') {
            let t = s.trim().to_string();
            if !t.is_empty() && !list.contains(&t) {
                list.push(t);
            }
        }
    }
    list
}

fn parse_command(cmd: &str) -> Result<(String, Vec<String>), ExecuteError> {
    let parts = shlex::split(cmd).ok_or_else(|| ExecuteError::InvalidCommand(cmd.to_string()))?;
    if parts.is_empty() {
        return Err(ExecuteError::InvalidCommand("empty command".to_string()));
    }
    Ok((parts[0].clone(), parts[1..].to_vec()))
}

pub async fn execute(validated: ValidatedIntent) -> Result<String, ExecuteError> {
    let action = validated.action();
    match action {
        "run_command" => run_command(validated).await,
        "read_file" => read_file(validated).await,
        "http_get" => http_get(validated).await,
        "complete" => complete_audit(validated),
        _ => Err(ExecuteError::UnknownAction(action.to_string())),
    }
}

fn complete_audit(validated: ValidatedIntent) -> Result<String, ExecuteError> {
    let params = validated.params();
    if let Some(findings_val) = params.get("findings") {
        match serde_json::from_value::<Vec<crate::schema::AuditFinding>>(findings_val.clone()) {
            Ok(findings) => {
                let summary = findings
                    .iter()
                    .map(|f| format!("[{:?}] {}", f.severity, f.title))
                    .collect::<Vec<_>>()
                    .join(", ");
                return Ok(format!(
                    "Audit complete. {} finding(s): {}",
                    findings.len(),
                    if summary.is_empty() { "none".to_string() } else { summary }
                ));
            }
            Err(e) => {
                tracing::warn!("complete action findings did not conform to AuditFinding schema: {}", e);
            }
        }
    }
    Ok("Audit complete.".to_string())
}

async fn run_command(validated: ValidatedIntent) -> Result<String, ExecuteError> {
    let cmd = validated
        .params()
        .get("command")
        .and_then(|v| v.as_str())
        .ok_or(ExecuteError::MissingParam("command"))?;

    let (program, args) = parse_command(cmd)?;

    let allowed = allowed_programs();
    let program_lower = program.to_lowercase();
    let is_allowed = allowed
        .iter()
        .any(|a| a.to_lowercase() == program_lower);
    if !is_allowed {
        return Err(ExecuteError::ProgramNotAllowed(program));
    }

    let mut cmd = Command::new(&program);
    cmd.args(&args);

    #[cfg(all(target_os = "linux", feature = "sandbox"))]
    {
        let workspace = std::env::current_dir().unwrap_or_else(|_| std::path::PathBuf::from("."));
        unsafe {
            cmd.pre_exec(move || {
                crate::sandbox::apply_child_sandbox(&workspace)
                    .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))
            });
        }
    }

    let output = tokio::time::timeout(
        Duration::from_secs(CMD_TIMEOUT_SECS),
        cmd.output(),
    )
    .await
    .map_err(|_| ExecuteError::Timeout)?
    .map_err(ExecuteError::Io)?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let out_str = stdout.to_string();
    let err_str = stderr.to_string();
    let out_trim = trim_to_max(&out_str, CMD_MAX_OUTPUT_BYTES);
    let err_trim = trim_to_max(&err_str, CMD_MAX_OUTPUT_BYTES);
    let status = output.status;
    Ok(format!(
        "exit_code: {:?}; stdout: {}; stderr: {}",
        status.code(),
        out_trim,
        err_trim
    ))
}

async fn read_file(validated: ValidatedIntent) -> Result<String, ExecuteError> {
    let path = validated
        .params()
        .get("path")
        .and_then(|v| v.as_str())
        .ok_or(ExecuteError::MissingParam("path"))?;
    let content = tokio::fs::read_to_string(path)
        .await
        .map_err(ExecuteError::Io)?;
    if content.len() > FILE_MAX_BYTES {
        return Ok(format!(
            "file too large ({} bytes); showing first {} bytes: {}",
            content.len(),
            FILE_MAX_BYTES,
            trim_to_max(&content, FILE_MAX_BYTES)
        ));
    }
    Ok(content)
}

async fn http_get(validated: ValidatedIntent) -> Result<String, ExecuteError> {
    let url = validated
        .params()
        .get("url")
        .and_then(|v| v.as_str())
        .ok_or(ExecuteError::MissingParam("url"))?;
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(HTTP_TIMEOUT_SECS))
        .build()
        .map_err(ExecuteError::Http)?;
    let response = client.get(url).send().await.map_err(ExecuteError::Http)?;
    let status = response.status();
    let body = response.bytes().await.map_err(ExecuteError::Http)?;
    if body.len() > HTTP_MAX_BODY_BYTES {
        return Ok(format!(
            "status: {}; body too large ({} bytes); first {} bytes: {}",
            status,
            body.len(),
            HTTP_MAX_BODY_BYTES,
            String::from_utf8_lossy(&body[..HTTP_MAX_BODY_BYTES.min(body.len())])
        ));
    }
    let text = String::from_utf8_lossy(&body).to_string();
    Ok(format!("status: {}; body: {}", status, text))
}

fn trim_to_max(s: &str, max_bytes: usize) -> String {
    if s.len() <= max_bytes {
        return s.to_string();
    }
    let mut boundary = max_bytes;
    while boundary > 0 && !s.is_char_boundary(boundary) {
        boundary -= 1;
    }
    format!("{}...", &s[..boundary])
}

#[derive(Debug)]
pub enum ExecuteError {
    UnknownAction(String),
    MissingParam(&'static str),
    InvalidCommand(String),
    ProgramNotAllowed(String),
    Timeout,
    Io(std::io::Error),
    Http(reqwest::Error),
}

impl std::fmt::Display for ExecuteError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ExecuteError::UnknownAction(a) => write!(f, "unknown action: {}", a),
            ExecuteError::MissingParam(p) => write!(f, "missing param: {}", p),
            ExecuteError::InvalidCommand(c) => write!(f, "invalid command: {}", c),
            ExecuteError::ProgramNotAllowed(p) => write!(f, "program not allowed: {}", p),
            ExecuteError::Timeout => write!(f, "timeout"),
            ExecuteError::Io(e) => write!(f, "io: {}", e),
            ExecuteError::Http(e) => write!(f, "http: {}", e),
        }
    }
}

impl std::error::Error for ExecuteError {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::intent::{ProposedIntent, ValidatedIntent};

    #[test]
    fn parse_command_simple() {
        let (prog, args) = parse_command("ls -la").unwrap();
        assert_eq!(prog, "ls");
        assert_eq!(args, ["-la"]);
    }

    #[test]
    fn parse_command_empty_fails() {
        assert!(parse_command("").is_err());
    }

    #[test]
    fn allowed_programs_includes_ls() {
        let list = allowed_programs();
        assert!(list.iter().any(|s| s == "ls"));
    }

    #[test]
    fn program_not_in_allowlist_rejected_at_runtime() {
        let intent = ValidatedIntent::from_proposed(ProposedIntent {
            action: "run_command".to_string(),
            params: serde_json::json!({ "command": "sudo ls" }),
            justification: "check elevated privileges".to_string(),
            reasoning: String::new(),
        });
        let result = tokio::runtime::Runtime::new().unwrap().block_on(run_command(intent));
        assert!(matches!(result, Err(ExecuteError::ProgramNotAllowed(p)) if p == "sudo"));
    }

    #[test]
    fn tripwire_accepts_safe_command_executor_allows() {
        let intent = ValidatedIntent::from_proposed(ProposedIntent {
            action: "run_command".to_string(),
            params: serde_json::json!({ "command": "ls -la" }),
            justification: "listing directory contents".to_string(),
            reasoning: String::new(),
        });
        let result = tokio::runtime::Runtime::new().unwrap().block_on(run_command(intent));
        assert!(result.is_ok());
    }
}
