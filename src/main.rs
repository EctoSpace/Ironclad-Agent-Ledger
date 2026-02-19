use clap::{Parser, Subcommand};
use colored::Colorize;
use ironclad_agent_ledger::agent::{self, AgentLoopConfig};
use ironclad_agent_ledger::config;
use ironclad_agent_ledger::db_setup;
use ironclad_agent_ledger::guard::GuardExecutor;
use ironclad_agent_ledger::guard_process::GuardProcess;
use ironclad_agent_ledger::agent::AgentError;
use ironclad_agent_ledger::ledger::{self, AppendError};
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
        /// Path to audit_policy.toml (policy hash stored in session and genesis).
        #[arg(long)]
        policy: Option<std::path::PathBuf>,
        /// Disable the Guard (not recommended). Requires --no-guard-confirmed to proceed.
        #[arg(long)]
        no_guard: bool,
        /// Explicitly acknowledge running without the Guard. Must be used with --no-guard.
        #[arg(long)]
        no_guard_confirmed: bool,
    },

    /// Replay events for a session (colored output).
    Replay {
        /// Session UUID to replay.
        session: Uuid,
        /// Stop after this many steps (default: all).
        #[arg(long)]
        to_step: Option<u32>,
        /// Inject adversarial observation at sequence (e.g. "seq=3:EVIL PAYLOAD"). Can be repeated.
        #[arg(long)]
        inject_observation: Vec<String>,
    },

    /// Verify event signatures for a session (ed25519).
    VerifySession {
        /// Session UUID.
        session: Uuid,
    },

    /// Export audit report for a session.
    Report {
        /// Session UUID.
        session: Uuid,
        /// Output format: sarif, json, or html.
        #[arg(long, default_value = "json")]
        format: String,
        /// Write to file (default: stdout).
        #[arg(short, long)]
        output: Option<std::path::PathBuf>,
    },

    /// Multi-agent orchestration (recon / analysis / verify with independent ledgers). Planned.
    Orchestrate {
        /// Audit goal for the orchestrator.
        #[arg(required = true)]
        goal: String,
    },

    /// Compare two audit sessions (baseline vs current). Outputs remediation evidence.
    DiffAudit {
        /// Baseline session UUID.
        #[arg(long)]
        baseline: Uuid,
        /// Current session UUID.
        #[arg(long)]
        current: Uuid,
        /// Output path (default: stdout).
        #[arg(short, long)]
        output: Option<std::path::PathBuf>,
    },

    /// Red-team mode: adversarial agent to test defenses. Planned.
    RedTeam {
        #[arg(long)]
        target_session: Uuid,
        #[arg(long, default_value = "50")]
        attack_budget: u32,
    },

    /// Generate ZK proof of audit. Planned.
    ProveAudit {
        session: Uuid,
    },

    /// Anchor session ledger tip to OpenTimestamps. Planned.
    AnchorSession {
        session: Uuid,
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
        Commands::Replay { .. } | Commands::Report { .. } | Commands::VerifySession { .. }
        | Commands::Orchestrate { .. } | Commands::DiffAudit { .. } | Commands::RedTeam { .. }
        | Commands::ProveAudit { .. } | Commands::AnchorSession { .. } => false,
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
        Commands::Audit {
            prompt,
            policy,
            no_guard,
            no_guard_confirmed,
            ..
        } => {
            if no_guard && !no_guard_confirmed {
                eprintln!("⚠️  WARNING: You specified --no-guard. The Guard provides a separate process and model to validate actions.");
                eprintln!("   Running without the Guard reduces security. If you really want to proceed, run with:");
                eprintln!("   cargo run -- audit \"<your goal>\" --no-guard --no-guard-confirmed");
                std::process::exit(1);
            }

            let client = reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(60))
                .build()?;
            let llm_backend = llm::backend_from_env(&client)?;
            llm_backend.ensure_ready(&client).await?;

            let (policy_engine, policy_hash) = if let Some(ref policy_path) = policy {
                let content = std::fs::read(policy_path).map_err(|e| {
                    eprintln!("Failed to read policy file: {}", e);
                    e
                })?;
                let hash = ironclad_agent_ledger::policy::policy_hash_bytes(&content);
                let engine = ironclad_agent_ledger::policy::PolicyEngine::load_from_path(policy_path)
                    .map_err(|e| {
                        eprintln!("Failed to load policy: {}", e);
                        std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string())
                    })?;
                (Some(engine), Some(hash))
            } else {
                (None, None)
            };

            let (session, session_signing_key) = ledger::create_session(
                &pool,
                &prompt,
                llm_backend.backend_name(),
                llm_backend.model_name(),
                policy_hash.as_deref(),
            )
            .await?;
            metrics.inc_sessions_created();
            let session_id = session.id;
            let session_signing_key = std::sync::Arc::new(session_signing_key);

            let goal_thought = if let Some(ref h) = policy_hash {
                format!("Audit goal: {}. Policy hash: {}", prompt, h)
            } else {
                format!("Audit goal: {}", prompt)
            };
            ledger::append_event(
                &pool,
                EventPayload::Thought {
                    content: goal_thought,
                },
                Some(session_id),
                Some(prompt.as_str()),
                Some(session_signing_key.as_ref()),
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

            let guard: Option<Box<dyn GuardExecutor>> = if no_guard && no_guard_confirmed {
                tracing::warn!("Running without Guard (--no-guard --no-guard-confirmed).");
                None
            } else {
                if let Err(e) = config::ensure_guard_config() {
                    eprintln!("Configuration error: {}", e);
                    std::process::exit(1);
                }
                match GuardProcess::spawn() {
                    Ok(g) => Some(Box::new(g)),
                    Err(e) => {
                        eprintln!("Guard process failed to start: {}", e);
                        std::process::exit(1);
                    }
                }
            };

            let agent_config = AgentLoopConfig {
                llm: llm_backend,
                tripwire: &tripwire,
                max_steps: Some(config::max_steps()),
                session_id: Some(session_id),
                session_goal: prompt.clone(),
                guard,
                policy: policy_engine.as_ref(),
                session_signing_key: Some(session_signing_key),
                metrics: Some(metrics),
            };
            let aborted = tokio::select! {
                result = agent::run_cognitive_loop(&pool, &client, agent_config) => {
                    match &result {
                        Ok(()) => {
                            let _ = ledger::finish_session(&pool, session_id, "completed").await;
                            println!("Cognitive loop finished.");
                        }
                        Err(AgentError::Append(AppendError::GoalMismatch)) => {
                            let _ = ledger::append_event(
                                &pool,
                                EventPayload::Thought {
                                    content: "Security: session goal mismatch (possible redirect); aborting.".to_string(),
                                },
                                Some(session_id),
                                None,
                                None,
                            ).await;
                            let _ = ledger::finish_session(&pool, session_id, "aborted").await;
                            eprintln!("Session aborted: goal mismatch.");
                            std::process::exit(1);
                        }
                        Err(AgentError::Append(AppendError::UnverifiedEvidence(ref msg))) => {
                            let _ = ledger::append_event(
                                &pool,
                                EventPayload::Thought {
                                    content: format!("Findings verification failed: {}; commit rejected.", msg),
                                },
                                Some(session_id),
                                None,
                                None,
                            ).await;
                            let _ = ledger::finish_session(&pool, session_id, "failed").await;
                            eprintln!("Session failed: {}", msg);
                            std::process::exit(1);
                        }
                        Err(_) => {
                            let _ = ledger::finish_session(&pool, session_id, "failed").await;
                            result?;
                        }
                    }
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
        Commands::Replay {
            session,
            to_step,
            inject_observation,
        } => {
            let events = ledger::get_events_by_session(&pool, session).await?;
            let limit = to_step.map(|n| n as usize).unwrap_or(events.len());
            let inject_map: std::collections::HashMap<i64, String> = inject_observation
                .iter()
                .filter_map(|s| {
                    let s = s.trim();
                    let rest = s.strip_prefix("seq=")?;
                    let (seq, payload) = rest.split_once(':')?;
                    let seq = seq.trim().parse::<i64>().ok()?;
                    Some((seq, payload.to_string()))
                })
                .collect();
            for (i, ev) in events.into_iter().take(limit).enumerate() {
                let step = i + 1;
                let payload_display = if let Some(injected) = inject_map.get(&ev.sequence) {
                    if let EventPayload::Observation { .. } = &ev.payload {
                        serde_json::to_string_pretty(&EventPayload::Observation {
                            content: format!("[INJECTED] {}", injected),
                        })
                        .unwrap_or_default()
                    } else {
                        serde_json::to_string_pretty(&ev.payload).unwrap_or_default()
                    }
                } else {
                    serde_json::to_string_pretty(&ev.payload).unwrap_or_default()
                };
                let (label, color_fn): (&str, fn(&str) -> colored::ColoredString) = match &ev.payload {
                    EventPayload::Genesis { .. } => ("genesis", |s: &str| s.green()),
                    EventPayload::Thought { .. } => ("thought", |s: &str| s.blue()),
                    EventPayload::Action { .. } => ("action", |s: &str| s.yellow()),
                    EventPayload::Observation { .. } => ("observation", |s: &str| s.magenta()),
                    EventPayload::ApprovalRequired { .. } | EventPayload::ApprovalDecision { .. } => {
                        ("approval", |s: &str| s.cyan())
                    }
                };
                println!("{}", color_fn(&format!("[step {}] {} #{}", step, label, ev.sequence)));
                println!("{}", payload_display);
                println!();
            }
        }
        Commands::VerifySession { session } => {
            let (verified, err) = ledger::verify_session_signatures(&pool, session).await?;
            if let Some(e) = err {
                eprintln!("Verification failed: {} ({} signatures verified)", e, verified);
                std::process::exit(1);
            }
            println!("Verified {} event signatures for session {}.", verified, session);
        }
        Commands::Orchestrate { goal } => {
            eprintln!("Multi-agent orchestration (recon/analysis/verify with independent ledgers) is planned. Goal: {}", goal);
            std::process::exit(1);
        }
        Commands::DiffAudit { baseline, current, output } => {
            let rep_a = ironclad_agent_ledger::report::build_report(&pool, baseline).await?;
            let rep_b = ironclad_agent_ledger::report::build_report(&pool, current).await?;
            let out = format!(
                "Baseline session {} (ledger hash: {}, findings: {})\nCurrent session {} (ledger hash: {}, findings: {})\n",
                baseline, rep_a.ledger_hash, rep_a.findings.len(),
                current, rep_b.ledger_hash, rep_b.findings.len(),
            );
            if let Some(path) = output {
                std::fs::write(&path, &out).map_err(|e| { eprintln!("Write failed: {}", e); e })?;
                println!("Diff summary written to {}", path.display());
            } else {
                print!("{}", out);
            }
        }
        Commands::RedTeam { .. } => {
            eprintln!("Red-team mode (adversarial agent to test defenses) is planned.");
            std::process::exit(1);
        }
        Commands::ProveAudit { .. } => {
            eprintln!("ZK proof-of-audit is planned.");
            std::process::exit(1);
        }
        Commands::AnchorSession { .. } => {
            eprintln!("OpenTimestamps anchoring is planned.");
            std::process::exit(1);
        }
        Commands::Report {
            session,
            format,
            output,
        } => {
            let report = ironclad_agent_ledger::report::build_report(&pool, session).await?;
            let out = match format.to_lowercase().as_str() {
                "sarif" => serde_json::to_string_pretty(&ironclad_agent_ledger::report::report_to_sarif(
                    &report, session,
                ))
                .unwrap_or_default(),
                "html" => ironclad_agent_ledger::report::report_to_html(&report, session),
                _ => serde_json::to_string_pretty(&report).unwrap_or_default(),
            };
            if let Some(path) = output {
                std::fs::write(&path, out).map_err(|e| {
                    eprintln!("Write failed: {}", e);
                    e
                })?;
                println!("Report written to {}", path.display());
            } else {
                println!("{}", out);
            }
        }
    }

    Ok(())
}
