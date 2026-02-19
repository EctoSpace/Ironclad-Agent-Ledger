use crate::intent::ValidatedIntent;
use std::time::Duration;
use tokio::process::Command;

const CMD_TIMEOUT_SECS: u64 = 30;
const CMD_MAX_OUTPUT_BYTES: usize = 32 * 1024;
const FILE_MAX_BYTES: usize = 256 * 1024;
const HTTP_TIMEOUT_SECS: u64 = 10;
const HTTP_MAX_BODY_BYTES: usize = 64 * 1024;

pub async fn execute(validated: ValidatedIntent) -> Result<String, ExecuteError> {
    let action = validated.action();
    match action {
        "run_command" => run_command(validated).await,
        "read_file" => read_file(validated).await,
        "http_get" => http_get(validated).await,
        "complete" => Ok("Audit complete.".to_string()),
        _ => Err(ExecuteError::UnknownAction(action.to_string())),
    }
}

async fn run_command(validated: ValidatedIntent) -> Result<String, ExecuteError> {
    let cmd = validated
        .params()
        .get("command")
        .and_then(|v| v.as_str())
        .ok_or(ExecuteError::MissingParam("command"))?;
    let output = tokio::time::timeout(
        Duration::from_secs(CMD_TIMEOUT_SECS),
        Command::new("sh").arg("-c").arg(cmd).output(),
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
    Timeout,
    Io(std::io::Error),
    Http(reqwest::Error),
}

impl std::fmt::Display for ExecuteError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ExecuteError::UnknownAction(a) => write!(f, "unknown action: {}", a),
            ExecuteError::MissingParam(p) => write!(f, "missing param: {}", p),
            ExecuteError::Timeout => write!(f, "timeout"),
            ExecuteError::Io(e) => write!(f, "io: {}", e),
            ExecuteError::Http(e) => write!(f, "http: {}", e),
        }
    }
}

impl std::error::Error for ExecuteError {}
