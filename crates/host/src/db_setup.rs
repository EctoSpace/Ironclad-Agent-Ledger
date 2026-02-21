use pg_embed::pg_enums::PgAuthMethod;
use pg_embed::pg_fetch::{PgFetchSettings, PG_V15};
use pg_embed::postgres::{PgEmbed, PgSettings};
use std::path::PathBuf;
use std::time::Duration;

const POLL_MAX_ATTEMPTS: u32 = 60;

pub struct EmbeddedDb(#[allow(dead_code)] Option<PgEmbed>);

pub async fn ensure_postgres_ready(database_url: &str) -> Result<(String, EmbeddedDb), DbSetupError> {
    let is_local = database_url.contains("localhost") || database_url.contains("127.0.0.1");

    if !is_local {
        eprintln!("INFO: Using external PostgreSQL (DATABASE_URL set).");
        poll_until_connected(database_url).await?;
        return Ok((database_url.to_string(), EmbeddedDb(None)));
    }

    if quick_connect(database_url).await.is_ok() {
        eprintln!("INFO: Using Docker/external PostgreSQL container at {}.", database_url);
        return Ok((database_url.to_string(), EmbeddedDb(None)));
    }

    eprintln!("WARNING: Using embedded PostgreSQL. Not recommended for production or multi-user deployments.");
    eprintln!("         Set DATABASE_URL to point to an external Postgres instance for production use.");
    println!("Starting embedded PostgreSQL (first run downloads ~30 MB of binaries)...");
    let (pg, url) = start_embedded(database_url).await?;
    println!("Embedded PostgreSQL ready.");
    Ok((url, EmbeddedDb(Some(pg))))
}

async fn quick_connect(url: &str) -> Result<(), sqlx::Error> {
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .acquire_timeout(Duration::from_secs(3))
        .connect(url)
        .await?;
    let _ = pool.close().await;
    Ok(())
}

async fn start_embedded(database_url: &str) -> Result<(PgEmbed, String), DbSetupError> {
    let parsed = database_url
        .parse::<url::Url>()
        .map_err(|e| DbSetupError::EmbeddedSetup(format!("invalid url: {}", e)))?;

    let port = parsed.port().unwrap_or(5432);
    let user = {
        let u = parsed.username();
        if u.is_empty() { "ironclad" } else { u }.to_string()
    };
    let password = parsed.password().unwrap_or("ironclad").to_string();
    let db_name = {
        let p = parsed.path().trim_start_matches('/');
        if p.is_empty() { "ironclad" } else { p }.to_string()
    };

    let data_dir = app_data_dir().join("postgres");
    std::fs::create_dir_all(&data_dir)
        .map_err(|e| DbSetupError::EmbeddedSetup(format!("create data dir: {}", e)))?;

    let pg_settings = PgSettings {
        database_dir: data_dir,
        port,
        user: user.clone(),
        password: password.clone(),
        auth_method: PgAuthMethod::Plain,
        persistent: true,
        timeout: Some(Duration::from_secs(60)),
        migration_dir: None,
    };

    let fetch_settings = PgFetchSettings {
        version: PG_V15,
        ..Default::default()
    };

    let mut pg = PgEmbed::new(pg_settings, fetch_settings)
        .await
        .map_err(|e| DbSetupError::EmbeddedSetup(e.to_string()))?;

    pg.setup()
        .await
        .map_err(|e| DbSetupError::EmbeddedSetup(e.to_string()))?;

    pg.start_db()
        .await
        .map_err(|e| DbSetupError::EmbeddedSetup(e.to_string()))?;

    create_database_if_missing(&pg.db_uri, &db_name).await?;

    let db_url = pg.full_db_uri(&db_name);
    Ok((pg, db_url))
}

async fn create_database_if_missing(base_uri: &str, db_name: &str) -> Result<(), DbSetupError> {
    let system_url = format!("{}/postgres", base_uri);
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .connect(&system_url)
        .await
        .map_err(|e| DbSetupError::EmbeddedSetup(e.to_string()))?;

    let exists: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_database WHERE datname = $1)")
            .bind(db_name)
            .fetch_one(&pool)
            .await
            .map_err(|e| DbSetupError::EmbeddedSetup(e.to_string()))?;

    if !exists {
        sqlx::query(&format!("CREATE DATABASE \"{}\"", db_name))
            .execute(&pool)
            .await
            .map_err(|e| DbSetupError::EmbeddedSetup(e.to_string()))?;
    }

    let _ = pool.close().await;
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

fn app_data_dir() -> PathBuf {
    #[cfg(target_os = "macos")]
    {
        let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
        PathBuf::from(home)
            .join("Library")
            .join("Application Support")
            .join("ironclad-agent-ledger")
    }
    #[cfg(target_os = "windows")]
    {
        let appdata = std::env::var("LOCALAPPDATA").unwrap_or_else(|_| ".".to_string());
        PathBuf::from(appdata).join("ironclad-agent-ledger")
    }
    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    {
        let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
        PathBuf::from(home)
            .join(".local")
            .join("share")
            .join("ironclad-agent-ledger")
    }
}

#[derive(Debug)]
pub enum DbSetupError {
    EmbeddedSetup(String),
    Timeout,
}

impl std::fmt::Display for DbSetupError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DbSetupError::EmbeddedSetup(msg) => {
                write!(f, "embedded postgres setup failed: {}", msg)
            }
            DbSetupError::Timeout => write!(
                f,
                "PostgreSQL did not accept connections within {} seconds",
                POLL_MAX_ATTEMPTS
            ),
        }
    }
}

impl std::error::Error for DbSetupError {}
