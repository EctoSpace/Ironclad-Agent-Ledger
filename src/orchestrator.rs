// Multi-agent orchestrator: runs three sequential sub-agents (Recon → Analysis → Verify)
// each in their own ledger session, then commits a CrossLedgerSeal event to every session.
//
// The cross-ledger seal hash is sha256(recon_tip || analysis_tip || verify_tip) — a single
// commitment that binds all three ledgers together without merging their event chains.

use crate::agent::{self, AgentLoopConfig, AgentError};
use crate::ledger;
use crate::llm;
use crate::schema::EventPayload;
use crate::tripwire::{self, Tripwire};
use reqwest::Client;
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use std::path::PathBuf;
use std::sync::Arc;
use uuid::Uuid;

// ── Role definitions ───────────────────────────────────────────────────────────

/// The specialisation of a sub-agent within an orchestrated run.
#[derive(Clone, Debug)]
pub enum AgentRole {
    /// Reads files and runs commands; no HTTP access. Its observations are fed to Analysis.
    Recon,
    /// Receives recon observations as context; reads files; produces findings.
    Analysis,
    /// Independently verifies analysis findings before the run is complete.
    Verify,
}

impl AgentRole {
    pub fn name(&self) -> &'static str {
        match self {
            AgentRole::Recon => "recon",
            AgentRole::Analysis => "analysis",
            AgentRole::Verify => "verify",
        }
    }

    /// Returns a dynamically generated TOML policy string that restricts the role
    /// to its permitted action set.
    fn policy_toml(&self) -> String {
        match self {
            AgentRole::Recon => r#"
name = "recon-agent-policy"
max_steps = 30

[[allowed_actions]]
action = "read_file"

[[allowed_actions]]
action = "run_command"

[[allowed_actions]]
action = "complete"

[[forbidden_actions]]
action = "http_get"
"#
            .to_string(),

            AgentRole::Analysis => r#"
name = "analysis-agent-policy"
max_steps = 20

[[allowed_actions]]
action = "read_file"

[[allowed_actions]]
action = "complete"
"#
            .to_string(),

            AgentRole::Verify => r#"
name = "verify-agent-policy"
max_steps = 15

[[allowed_actions]]
action = "read_file"

[[allowed_actions]]
action = "complete"
"#
            .to_string(),
        }
    }
}

// ── Configuration ──────────────────────────────────────────────────────────────

pub struct OrchestratorConfig {
    pub goal: String,
    /// Optional shared policy file path (applied on top of per-role defaults).
    pub policy: Option<PathBuf>,
    /// Maximum steps per sub-agent (overrides per-role policy max_steps if set).
    pub max_steps_per_agent: Option<u32>,
}

// ── Result ─────────────────────────────────────────────────────────────────────

#[derive(Debug)]
pub struct OrchestrationResult {
    pub recon_session_id: Uuid,
    pub analysis_session_id: Uuid,
    pub verify_session_id: Uuid,
    /// sha256(recon_tip || analysis_tip || verify_tip)
    pub seal_hash: String,
}

// ── Errors ─────────────────────────────────────────────────────────────────────

#[derive(Debug)]
pub enum OrchestratorError {
    Agent(AgentError),
    Db(sqlx::Error),
    NoEvents(AgentRole),
    PolicyParse(toml::de::Error),
}

impl std::fmt::Display for OrchestratorError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OrchestratorError::Agent(e) => write!(f, "agent error: {}", e),
            OrchestratorError::Db(e) => write!(f, "db error: {}", e),
            OrchestratorError::NoEvents(r) => write!(f, "no events in {} session", r.name()),
            OrchestratorError::PolicyParse(e) => write!(f, "policy parse error: {}", e),
        }
    }
}

impl std::error::Error for OrchestratorError {}

impl From<AgentError> for OrchestratorError {
    fn from(e: AgentError) -> Self {
        OrchestratorError::Agent(e)
    }
}

// ── Implementation ─────────────────────────────────────────────────────────────

/// Runs a three-stage orchestrated audit:
/// 1. Recon agent — collects raw observations.
/// 2. Analysis agent — processes recon output into findings.
/// 3. Verify agent — independently confirms findings.
/// Each stage runs in its own ledger session. On completion, a `CrossLedgerSeal`
/// event is appended to every session tying them together.
pub async fn run_orchestration(
    pool: &PgPool,
    client: &Client,
    config: OrchestratorConfig,
) -> Result<OrchestrationResult, OrchestratorError> {
    let llm_backend_name = crate::config::llm_backend();
    let llm_model = crate::config::ollama_model();

    // ── Stage 1: Recon ─────────────────────────────────────────────────────────
    println!("[Orchestrator] Starting RECON agent…");
    let recon_id = run_role_agent(
        pool,
        client,
        &config,
        AgentRole::Recon,
        &config.goal,
        &llm_backend_name,
        &llm_model,
    )
    .await?;

    // Collect recon observations as context for the analysis stage.
    let recon_events = ledger::get_events_by_session(pool, recon_id)
        .await
        .map_err(OrchestratorError::Db)?;
    let recon_tip = recon_events
        .last()
        .map(|e| e.content_hash.clone())
        .ok_or_else(|| OrchestratorError::NoEvents(AgentRole::Recon))?;

    let recon_observations: String = recon_events
        .iter()
        .filter_map(|e| {
            if let EventPayload::Observation { content } = &e.payload {
                Some(content.as_str())
            } else {
                None
            }
        })
        .collect::<Vec<_>>()
        .join("\n---\n");

    // ── Stage 2: Analysis ─────────────────────────────────────────────────────
    println!("[Orchestrator] Starting ANALYSIS agent…");
    let analysis_goal = format!(
        "Analyse the following recon observations collected during the audit of \"{goal}\".\n\
         Produce structured findings with severity ratings.\n\n\
         === RECON OBSERVATIONS ===\n{recon_observations}",
        goal = config.goal,
        recon_observations = recon_observations,
    );
    let analysis_id = run_role_agent(
        pool,
        client,
        &config,
        AgentRole::Analysis,
        &analysis_goal,
        &llm_backend_name,
        &llm_model,
    )
    .await?;

    let analysis_events = ledger::get_events_by_session(pool, analysis_id)
        .await
        .map_err(OrchestratorError::Db)?;
    let analysis_tip = analysis_events
        .last()
        .map(|e| e.content_hash.clone())
        .ok_or_else(|| OrchestratorError::NoEvents(AgentRole::Analysis))?;

    let analysis_observations: String = analysis_events
        .iter()
        .filter_map(|e| {
            if let EventPayload::Observation { content } = &e.payload {
                Some(content.as_str())
            } else {
                None
            }
        })
        .collect::<Vec<_>>()
        .join("\n---\n");

    // ── Stage 3: Verify ───────────────────────────────────────────────────────
    println!("[Orchestrator] Starting VERIFY agent…");
    let verify_goal = format!(
        "Independently verify the following security findings for \"{goal}\".\n\
         Confirm each finding with evidence or mark it as unverified.\n\n\
         === ANALYSIS FINDINGS ===\n{analysis_observations}",
        goal = config.goal,
        analysis_observations = analysis_observations,
    );
    let verify_id = run_role_agent(
        pool,
        client,
        &config,
        AgentRole::Verify,
        &verify_goal,
        &llm_backend_name,
        &llm_model,
    )
    .await?;

    let verify_events = ledger::get_events_by_session(pool, verify_id)
        .await
        .map_err(OrchestratorError::Db)?;
    let verify_tip = verify_events
        .last()
        .map(|e| e.content_hash.clone())
        .ok_or_else(|| OrchestratorError::NoEvents(AgentRole::Verify))?;

    // ── Cross-ledger seal ─────────────────────────────────────────────────────
    let seal_hash = compute_seal_hash(&recon_tip, &analysis_tip, &verify_tip);
    let session_ids = vec![recon_id, analysis_id, verify_id];
    let session_tips = vec![recon_tip, analysis_tip, verify_tip];

    let seal_payload = EventPayload::CrossLedgerSeal {
        seal_hash: seal_hash.clone(),
        session_ids: session_ids.clone(),
        session_tip_hashes: session_tips.clone(),
    };

    // Append the seal event to all three sessions.
    for sid in &session_ids {
        if let Err(e) = ledger::append_event(pool, seal_payload.clone(), Some(*sid), None, None).await {
            tracing::warn!("Failed to append CrossLedgerSeal to session {}: {}", sid, e);
        }
    }

    println!("[Orchestrator] Cross-ledger seal: {}", seal_hash);
    println!("[Orchestrator] Recon   session: {}", recon_id);
    println!("[Orchestrator] Analysis session: {}", analysis_id);
    println!("[Orchestrator] Verify  session: {}", verify_id);

    Ok(OrchestrationResult {
        recon_session_id: recon_id,
        analysis_session_id: analysis_id,
        verify_session_id: verify_id,
        seal_hash,
    })
}

// ── Helpers ────────────────────────────────────────────────────────────────────

async fn run_role_agent(
    pool: &PgPool,
    client: &Client,
    config: &OrchestratorConfig,
    role: AgentRole,
    goal: &str,
    llm_backend_name: &str,
    llm_model: &str,
) -> Result<Uuid, OrchestratorError> {
    use crate::policy::PolicyEngine;

    // Build role-specific policy (role defaults; no user policy override for sub-agents).
    let role_policy_toml = role.policy_toml();
    let role_policy: crate::policy::AuditPolicy = toml::from_str(&role_policy_toml)
        .map_err(OrchestratorError::PolicyParse)?;
    let policy_engine = PolicyEngine::new(role_policy);
    let policy_hash = crate::policy::policy_hash_bytes(role_policy_toml.as_bytes());

    let (session, signing_key) = ledger::create_session(
        pool,
        goal,
        llm_backend_name,
        llm_model,
        Some(&policy_hash),
    )
    .await
    .map_err(OrchestratorError::Db)?;

    let session_id = session.id;
    let signing_key_arc = Arc::new(signing_key);

    // Bootstrap genesis for this sub-session.
    let genesis_msg = format!("[{}] {}", role.name(), goal);
    ledger::append_event(
        pool,
        EventPayload::Genesis { message: genesis_msg },
        Some(session_id),
        Some(goal),
        Some(&signing_key_arc),
    )
    .await
    .map_err(|e| OrchestratorError::Db(match e {
        ledger::AppendError::Db(d) => d,
        other => sqlx::Error::Protocol(format!("append genesis: {}", other)),
    }))?;

    let llm = llm::backend_from_env(client)
        .map_err(|e| OrchestratorError::Agent(AgentError::Io(
            std::io::Error::new(std::io::ErrorKind::Other, e.to_string())
        )))?;

    let tripwire = Tripwire::new(vec![], vec![], tripwire::default_banned_command_patterns());
    let loop_config = AgentLoopConfig {
        llm,
        tripwire: &tripwire,
        max_steps: config.max_steps_per_agent,
        session_id: Some(session_id),
        session_goal: goal.to_string(),
        guard: None,
        policy: Some(&policy_engine),
        session_signing_key: Some(signing_key_arc),
        metrics: None,
        egress_tx: None,
    };

    agent::run_cognitive_loop(pool, client, loop_config)
        .await
        .map_err(OrchestratorError::Agent)?;

    ledger::finish_session(pool, session_id, "completed")
        .await
        .map_err(OrchestratorError::Db)?;

    Ok(session_id)
}

/// sha256(recon_tip || analysis_tip || verify_tip)
fn compute_seal_hash(recon_tip: &str, analysis_tip: &str, verify_tip: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(recon_tip.as_bytes());
    hasher.update(analysis_tip.as_bytes());
    hasher.update(verify_tip.as_bytes());
    hex::encode(hasher.finalize())
}
