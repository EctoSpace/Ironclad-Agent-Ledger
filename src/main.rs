use clap::{Parser, Subcommand};
use ironclad_agent_ledger::agent::{self, AgentLoopConfig};
use ironclad_agent_ledger::config;
use ironclad_agent_ledger::db_setup;
use ironclad_agent_ledger::ledger;
use ironclad_agent_ledger::ollama;
use ironclad_agent_ledger::server;
use ironclad_agent_ledger::schema::EventPayload;
use ironclad_agent_ledger::tripwire::{self, Tripwire};
use sqlx::postgres::PgPoolOptions;
use std::path::PathBuf;
use tokio::net::TcpListener;

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
    Serve,

    /// Run a security audit: start the Observer and execute the cognitive loop with the given prompt.
    Audit {
        /// Audit instruction for the agent (e.g. "Read server_config.txt").
        #[arg(required = true)]
        prompt: String,
    },
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    dotenvy::dotenv().ok();
    let cli = Cli::parse();

    let database_url = config::database_url()?;
    db_setup::ensure_postgres_ready(&database_url).await?;
    let pool = PgPoolOptions::new()
        .connect(&database_url)
        .await?;

    sqlx::query_scalar::<_, i32>("SELECT 1")
        .fetch_one(&pool)
        .await?;
    println!("Database connected.");

    sqlx::migrate!("./migrations").run(&pool).await?;

    let appended = ledger::ensure_genesis(&pool).await?;
    if appended.sequence == 0 {
        println!("Genesis block created.");
    } else {
        println!("Genesis already present; latest sequence = {}.", appended.sequence);
    }

    match cli.command {
        Commands::Serve => {
            let listener = TcpListener::bind("0.0.0.0:3000").await?;
            println!("Observer dashboard: http://localhost:3000");
            axum::serve(listener, server::router(pool)).await?;
        }
        Commands::Audit { prompt } => {
            ledger::append_event(
                &pool,
                EventPayload::Thought {
                    content: format!("Audit goal: {}", prompt),
                },
            )
            .await?;

            let base_url = config::ollama_base_url();
            let model = config::ollama_model();
            let client = reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(60))
                .build()?;
            ollama::ensure_ollama_ready(&base_url, &model, &client).await?;
            println!("Ollama ready ({}). Starting cognitive loop.", model);

            let pool_observer = pool.clone();
            tokio::spawn(async move {
                let listener = TcpListener::bind("0.0.0.0:3000").await.expect("bind 0.0.0.0:3000");
                println!("Observer dashboard: http://localhost:3000");
                axum::serve(listener, server::router(pool_observer))
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
            let agent_config = AgentLoopConfig {
                ollama_base_url: &base_url,
                ollama_model: &model,
                tripwire: &tripwire,
                max_steps: std::env::var("AGENT_MAX_STEPS")
                    .ok()
                    .and_then(|s| s.parse().ok()),
            };
            agent::run_cognitive_loop(&pool, &client, agent_config).await?;
            println!("Cognitive loop finished.");
        }
    }

    Ok(())
}
