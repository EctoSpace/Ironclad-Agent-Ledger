use clap::{Parser, Subcommand};
use colored::Colorize;
use ironclad_agent_ledger::agent::{self, AgentLoopConfig};
use ironclad_agent_ledger::config;
use ironclad_agent_ledger::db_setup;
use ironclad_agent_ledger::guard::Guard;
use ironclad_agent_ledger::ledger;
use ironclad_agent_ledger::llm;
use ironclad_agent_ledger::server;
use ironclad_agent_ledger::schema::EventPayload;
use ironclad_agent_ledger::tripwire::{self, Tripwire};
use sqlx::postgres::PgPoolOptions;
use std::path::PathBuf;
use std::net::SocketAddr;
use tokio::net::TcpListener;
use uuid::Uuid;

#[derive(Parser)]
#[command(name = "ironclad-agent-ledger")]
#[command(about = "Cryptographically verified, state-driven agent framework for automated security auditing")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Run the database, migrations, and Observer dashboard on port 3000 (no agent).
    Serve {
        /// Verify full chain from genesis; otherwise only last 1000 events.
        #[arg(long, default_value_t = false)]
        verify_full: bool,
    },

    /// Run a security audit: start the Observer and execute the cognitive loop with the given prompt.
    Audit {
        /// Audit instruction for the agent (e.g. "Read server_config.txt").
        #[arg(required = true)]
        prompt: String,
        /// Verify full chain from genesis; otherwise only last 1000 events.
        #[arg(long, default_value_t = false)]
        verify_full: bool,
    },

    /// Replay events for a session (colored output).
    Replay {
        /// Session UUID to replay.
        session: Uuid,
        /// Stop after this many steps (default: all).
        #[arg(long)]
        to_step: Option<u32>,
    },
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();
    dotenvy::dotenv().ok();
    let cli = Cli::parse();

    let configured_url = config::database_url()?;
    let (database_url, _embedded_pg) = db_setup::ensure_postgres_ready(&configured_url).await?;
    let pool = PgPoolOptions::new()
        .connect(&database_url)
        .await?;

    sqlx::query_scalar::<_, i32>("SELECT 1")
        .fetch_one(&pool)
        .await?;
    println!("Database connected.");

    sqlx::migrate!("./migrations").run(&pool).await?;

    let verify_full = match &cli.command {
        Commands::Serve { verify_full, .. } => *verify_full,
        Commands::Audit { verify_full, .. } => *verify_full,
        Commands::Replay { .. } => false,
    };
    if let Some((latest_seq, _)) = ledger::get_latest(&pool).await? {
        let from = if verify_full { 0 } else { (latest_seq - 999).max(0) };
        let to = latest_seq;
        if !ledger::verify_chain(&pool, from, to).await? {
            eprintln!("Ledger chain verification failed: tampering detected.");
            std::process::exit(1);
        }
    }

    let appended = ledger::ensure_genesis(&pool).await?;
    if appended.sequence == 0 {
        println!("Genesis block created.");
    } else {
        println!("Genesis already present; latest sequence = {}.", appended.sequence);
    }

    let metrics = std::sync::Arc::new(ironclad_agent_ledger::metrics::Metrics::default());
    match cli.command {
        Commands::Serve { .. } => {
            let listener = TcpListener::bind("0.0.0.0:3000").await?;
            println!("Observer dashboard: http://localhost:3000");
            tokio::select! {
                r = axum::serve(
                    listener,
                    server::router(pool.clone(), metrics)
                        .into_make_service_with_connect_info::<SocketAddr>(),
                ) => { r?; }
                _ = tokio::signal::ctrl_c() => {
                    println!("Shutdown signal received.");
                }
            }
        }
        Commands::Audit { prompt, .. } => {
            let client = reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(60))
                .build()?;
            let llm_backend = llm::backend_from_env(&client)?;
            llm_backend.ensure_ready(&client).await?;

            let session = ledger::create_session(
                &pool,
                &prompt,
                llm_backend.backend_name(),
                llm_backend.model_name(),
            )
            .await?;
            metrics.inc_sessions_created();
            let session_id = session.id;

            ledger::append_event(
                &pool,
                EventPayload::Thought {
                    content: format!("Audit goal: {}", prompt),
                },
                Some(session_id),
            )
            .await?;
            metrics.inc_events_appended();

            println!(
                "LLM ready ({} / {}). Starting cognitive loop.",
                llm_backend.backend_name(),
                llm_backend.model_name()
            );

            let pool_observer = pool.clone();
            let metrics_observer = metrics.clone();
            tokio::spawn(async move {
                let listener = TcpListener::bind("0.0.0.0:3000").await.expect("bind 0.0.0.0:3000");
                println!("Observer dashboard: http://localhost:3000");
                axum::serve(
                    listener,
                    server::router(pool_observer, metrics_observer)
                        .into_make_service_with_connect_info::<SocketAddr>(),
                )
                .await
                .expect("axum serve");
            });

            let workspace = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
            let allowed_paths = vec![workspace];
            let allowed_domains: Vec<String> = std::env::var("AGENT_ALLOWED_DOMAINS")
                .ok()
                .map(|s| s.split(',').map(String::from).collect())
                .unwrap_or_default();
            let tripwire = Tripwire::new(
                allowed_paths,
                allowed_domains,
                tripwire::default_banned_command_patterns(),
            );
            let guard = Guard::from_env(&client)
                .map(Some)
                .unwrap_or_else(|e| {
                    tracing::warn!("Guard init failed (running without guard): {}", e);
                    None
                });
            let agent_config = AgentLoopConfig {
                llm: llm_backend,
                tripwire: &tripwire,
                max_steps: Some(config::max_steps()),
                session_id: Some(session_id),
                session_goal: prompt.clone(),
                guard,
                metrics: Some(metrics),
            };
            let aborted = tokio::select! {
                result = agent::run_cognitive_loop(&pool, &client, agent_config) => {
                    let status = if result.is_ok() {
                        "completed"
                    } else {
                        "failed"
                    };
                    let _ = ledger::finish_session(&pool, session_id, status).await;
                    result?;
                    println!("Cognitive loop finished.");
                    false
                }
                _ = tokio::signal::ctrl_c() => {
                    true
                }
            };
            if aborted {
                if let Some((seq, _)) = ledger::get_latest(&pool).await? {
                    let _ = ironclad_agent_ledger::snapshot::snapshot_at_sequence(&pool, seq).await;
                }
                let _ = ledger::finish_session(&pool, session_id, "aborted").await;
                println!("Shutdown signal received; session aborted.");
            }
        }
        Commands::Replay { session, to_step } => {
            let events = ledger::get_events_by_session(&pool, session).await?;
            let limit = to_step.map(|n| n as usize).unwrap_or(events.len());
            for (i, ev) in events.into_iter().take(limit).enumerate() {
                let step = i + 1;
                let (label, color_fn): (&str, fn(&str) -> colored::ColoredString) = match &ev.payload {
                    EventPayload::Genesis { .. } => ("genesis", |s: &str| s.green()),
                    EventPayload::Thought { .. } => ("thought", |s: &str| s.blue()),
                    EventPayload::Action { .. } => ("action", |s: &str| s.yellow()),
                    EventPayload::Observation { .. } => ("observation", |s: &str| s.magenta()),
                };
                let payload_str = serde_json::to_string_pretty(&ev.payload).unwrap_or_default();
                println!("{}", color_fn(&format!("[step {}] {} #{}", step, label, ev.sequence)));
                println!("{}", payload_str);
                println!();
            }
        }
    }

    Ok(())
}
