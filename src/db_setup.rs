use std::process::Command;
use std::time::Duration;

const CONTAINER_NAME: &str = "ironclad-postgres";
const POLL_MAX_ATTEMPTS: u32 = 60;

pub async fn ensure_postgres_ready(database_url: &str) -> Result<(), DbSetupError> {
    let use_docker = database_url.contains("localhost") || database_url.contains("127.0.0.1");
    if use_docker {
        ensure_container_running()?;
    }
    poll_until_connected(database_url).await
}

fn ensure_container_running() -> Result<(), DbSetupError> {
    let running = Command::new("docker")
        .args(["ps", "-a", "--filter", &format!("name={}", CONTAINER_NAME), "--format", "{{.Names}}\t{{.Status}}"])
        .output()
        .map_err(|e| DbSetupError::DockerUnavailable(e.to_string()))?;

    if !running.status.success() {
        return Err(DbSetupError::DockerUnavailable(
            "docker ps failed".to_string(),
        ));
    }

    let out = String::from_utf8_lossy(&running.stdout);
    let running_line = out.lines().find(|l| l.starts_with(CONTAINER_NAME));
    let is_running = running_line.map(|l| l.contains("Up")).unwrap_or(false);
    let exists = running_line.is_some();

    if is_running {
        return Ok(());
    }

    if exists {
        let status = Command::new("docker")
            .args(["start", CONTAINER_NAME])
            .status()
            .map_err(|e| DbSetupError::StartFailed(e.to_string()))?;
        if !status.success() {
            return Err(DbSetupError::StartFailed(
                "docker start ironclad-postgres failed".to_string(),
            ));
        }
        return Ok(());
    }

    let status = Command::new("docker")
        .args([
            "run",
            "--name",
            CONTAINER_NAME,
            "-e",
            "POSTGRES_USER=ironclad",
            "-e",
            "POSTGRES_PASSWORD=ironclad",
            "-e",
            "POSTGRES_DB=ironclad",
            "-p",
            "5432:5432",
            "-d",
            "postgres:alpine",
        ])
        .status()
        .map_err(|e| DbSetupError::DockerRunFailed(e.to_string()))?;

    if !status.success() {
        return Err(DbSetupError::DockerRunFailed(
            "docker run ironclad-postgres failed".to_string(),
        ));
    }

    Ok(())
}

async fn poll_until_connected(database_url: &str) -> Result<(), DbSetupError> {
    for attempt in 1..=POLL_MAX_ATTEMPTS {
        match sqlx::postgres::PgPoolOptions::new()
            .max_connections(1)
            .connect(database_url)
            .await
        {
            Ok(pool) => {
                let _ = pool.close().await;
                return Ok(());
            }
            Err(_) => {
                if attempt < POLL_MAX_ATTEMPTS {
                    tokio::time::sleep(Duration::from_secs(1)).await;
                } else {
                    return Err(DbSetupError::Timeout);
                }
            }
        }
    }
    Err(DbSetupError::Timeout)
}

#[derive(Debug)]
pub enum DbSetupError {
    DockerUnavailable(String),
    StartFailed(String),
    DockerRunFailed(String),
    Timeout,
}

impl std::fmt::Display for DbSetupError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DbSetupError::DockerUnavailable(msg) => write!(f, "Docker unavailable: {}", msg),
            DbSetupError::StartFailed(msg) => write!(f, "start failed: {}", msg),
            DbSetupError::DockerRunFailed(msg) => write!(f, "docker run failed: {}", msg),
            DbSetupError::Timeout => write!(
                f,
                "PostgreSQL did not accept connections within {} seconds",
                POLL_MAX_ATTEMPTS
            ),
        }
    }
}

impl std::error::Error for DbSetupError {}
