use crate::cloud_creds::CloudCredentialSet;
use crate::config;
use crate::executor;
use crate::guard::GuardDecision;
use crate::intent::ValidatedIntent;
use crate::ledger::{self, AppendError};
use crate::llm;
use crate::intent::ProposedIntent;
use crate::schema::{EventPayload, LedgerEventRow};
use crate::output_scanner;
use crate::policy::PolicyEngine;
use crate::snapshot;
use crate::tripwire::{Tripwire, TripwireError};
use crate::wakeup::{self, WakeUpError};
use ed25519_dalek::SigningKey;
use reqwest::Client;
use sqlx::PgPool;
use std::sync::Arc;
use uuid::Uuid;

pub struct AgentLoopConfig<'a> {
    pub llm: Box<dyn crate::llm::LlmBackend>,
    pub tripwire: &'a Tripwire,
    pub max_steps: Option<u32>,
    pub session_id: Option<Uuid>,
    pub session_goal: String,
    pub guard: Option<Box<dyn crate::guard::GuardExecutor>>,
    pub policy: Option<&'a PolicyEngine>,
    pub session_signing_key: Option<Arc<SigningKey>>,
    pub metrics: Option<std::sync::Arc<crate::metrics::Metrics>>,
    /// Optional channel to the async webhook egress worker. When set, flagged and aborted
    /// observations are forwarded in the background without blocking the cognitive loop.
    pub egress_tx: Option<tokio::sync::mpsc::Sender<crate::webhook::EgressEvent>>,
    /// Ephemeral cloud credentials injected only into matching child processes.
    pub cloud_creds: Option<Arc<CloudCredentialSet>>,
    /// When true, approval gate decisions are prompted interactively on stdin instead of
    /// waiting for the REST API (Mode A). When false, the shared ApprovalState is polled.
    pub interactive: bool,
    /// Shared approval state from the Observer server, enabling REST-driven gate decisions.
    pub approval_state: Option<Arc<crate::approvals::ApprovalState>>,
}

pub async fn run_cognitive_loop(
    pool: &PgPool,
    _client: &Client,
    mut config: AgentLoopConfig<'_>,
) -> Result<(), AgentError> {
    wakeup::recover_incomplete_actions(pool)
        .await
        .map_err(AgentError::WakeUp)?;
    let session_goal = config
        .session_id
        .as_ref()
        .map(|_| config.session_goal.as_str());

    // Log cloud credential set name (never the values) as an auditable thought.
    if let Some(ref creds) = config.cloud_creds {
        append_thought(
            pool,
            &format!(
                "Cloud credential set loaded: {} (provider: {})",
                creds.name, creds.provider
            ),
            config.session_id,
            session_goal,
            &config,
            config.metrics.as_deref(),
        )
        .await?;
    }

    let mut step: u32 = 0;
    let max_steps = config
        .max_steps
        .or_else(|| config.policy.and_then(|p| p.max_steps()))
        .unwrap_or_else(config::max_steps);
    let llm_error_limit = config::llm_error_limit();
    let guard_denial_limit = config::guard_denial_limit();
    let mut consecutive_llm_errors: u32 = 0;
    let mut consecutive_guard_denials: u32 = 0;

    loop {
        if step >= max_steps {
            break;
        }
        step += 1;

        let state = perceive(pool).await?;
        if detect_loop(&state.replayed_events) {
            append_thought(
                pool,
                "Loop detected (repeated action); completing.",
                config.session_id,
                session_goal,
                &config,
                config.metrics.as_deref(),
            )
            .await?;
            let intent = ProposedIntent {
                action: "complete".to_string(),
                params: serde_json::json!({}),
                justification: "loop detected".to_string(),
                reasoning: String::new(),
            };
            let validated = match config.tripwire.validate(&intent) {
                Ok(v) => v,
                Err(e) => {
                    append_thought(
                        pool,
                        &format!("Tripwire rejected complete: {}", e),
                        config.session_id,
                        session_goal,
                        &config,
                        config.metrics.as_deref(),
                    )
                    .await?;
                    continue;
                }
            };
            let event_id = append_action(pool, &validated, config.session_id, session_goal, &config, config.metrics.as_deref()).await?;
            ledger::mark_action_executing(pool, event_id)
            .await
            .map_err(AgentError::Db)?;
            let _ = executor::execute_with_policy(validated, config.cloud_creds.clone(), config.policy).await;
            ledger::mark_action_completed(pool, event_id)
                .await
                .map_err(AgentError::Db)?;
            append_observation(
                pool,
                "Completed due to loop detection.",
                config.session_id,
                session_goal,
                &config,
                config.metrics.as_deref(),
            )
            .await?;
            break;
        }
        let few_shot = if state.replayed_events.len() <= 2 {
            llm::few_shot_examples()
        } else {
            ""
        };
        let user = format!(
            "Current goal: {}\n\n{}{}",
            config.session_goal,
            few_shot,
            llm::state_to_prompt(&state, 50)
        );
        // Token budget circuit breaker: abort before making the next LLM call if the
        // cumulative approximate token count exceeds AGENT_TOKEN_BUDGET_MAX.
        if let Some(budget) = config::token_budget_max() {
            let used = config.metrics.as_ref().map(|m| m.current_token_count()).unwrap_or(0);
            if used >= budget {
                append_thought(
                    pool,
                    &format!(
                        "Token budget exceeded: ~{} tokens used, limit is {}. Aborting session.",
                        used, budget
                    ),
                    config.session_id,
                    session_goal,
                    &config,
                    config.metrics.as_deref(),
                )
                .await?;
                return Err(AgentError::TokenBudgetExceeded);
            }
        }

        let intent = match config.llm.propose(llm::DEFAULT_SYSTEM_PROMPT, &user).await {
            Ok(i) => {
                // Account for the prompt and response in the token budget.
                if let Some(m) = &config.metrics {
                    m.add_tokens_for_text(&user);
                    m.add_tokens_for_text(&i.action);
                    m.add_tokens_for_text(&i.justification);
                }
                consecutive_llm_errors = 0;
                i
            }
            Err(e) => {
                consecutive_llm_errors += 1;
                append_thought(pool, &format!("LLM error: {}", e), config.session_id, session_goal, &config, config.metrics.as_deref()).await?;
                if consecutive_llm_errors >= llm_error_limit {
                    append_thought(
                        pool,
                        &format!("Circuit breaker: {} consecutive LLM errors; aborting session.", consecutive_llm_errors),
                        config.session_id,
                        session_goal,
                        &config,
                        config.metrics.as_deref(),
                    )
                    .await?;
                    return Err(AgentError::CircuitBreaker);
                }
                continue;
            }
        };

        if let Some(policy) = config.policy {
            if let Err(pv) = policy.validate_intent(&intent, step) {
                if let Some(m) = &config.metrics {
                    m.inc_tripwire_rejections();
                }
                append_thought(
                    pool,
                    &format!("Policy rejected: {}", pv),
                    config.session_id,
                    session_goal,
                    &config,
                    config.metrics.as_deref(),
                )
                .await?;
                continue;
            }

            // Check approval gate rules from policy.
            if let Some(gate) = policy.check_approval_gates(&intent) {
                let gate_id = uuid::Uuid::new_v4().to_string();
                let timeout_secs = gate.timeout_seconds.unwrap_or(300);
                let on_timeout_deny = gate.on_timeout.as_deref() != Some("allow");

                let params_summary = serde_json::to_string(&intent.params)
                    .unwrap_or_else(|_| "{}".to_string());
                ledger::append_event(
                    pool,
                    crate::schema::EventPayload::ApprovalRequired {
                        gate_id: gate_id.clone(),
                        action_name: intent.action.to_string(),
                        action_params_summary: params_summary,
                    },
                    config.session_id,
                    session_goal,
                    config.session_signing_key.as_deref(),
                )
                .await
                .map_err(|e| AgentError::Db(match e {
                    AppendError::Db(d) => d,
                    other => sqlx::Error::Protocol(format!("approval gate event: {}", other)),
                }))?;

                // Collect the human operator's decision.
                let approved = if config.interactive {
                    // Mode A: prompt on stdin (blocks a thread from the blocking pool).
                    let params_str = serde_json::to_string(&intent.params)
                        .unwrap_or_else(|_| "{}".to_string());
                    let action_str = intent.action.to_string();
                    let approved_result = tokio::time::timeout(
                        std::time::Duration::from_secs(timeout_secs),
                        async move {
                            use std::io::Write as _;
                            use tokio::io::AsyncBufReadExt as _;
                            eprintln!();
                            eprintln!("[APPROVAL REQUIRED]");
                            eprintln!("  Action : {}", action_str);
                            eprintln!("  Params : {}", params_str);
                            eprint!("Approve? [y/N] (auto-deny in {}s): ", timeout_secs);
                            let _ = std::io::stderr().flush();
                            let mut line = String::new();
                            let mut reader = tokio::io::BufReader::new(tokio::io::stdin());
                            reader.read_line(&mut line).await.unwrap_or(0);
                            line.trim().to_lowercase() == "y"
                        },
                    )
                    .await
                    .unwrap_or(!on_timeout_deny);
                    approved_result
                } else if let Some(ref approval_state) = config.approval_state {
                    // Mode B: poll the shared ApprovalState (REST API decisions from the dashboard).
                    let poll_session = config.session_id.unwrap_or_default();
                    let poll_gate = gate_id.clone();
                    let poll_state = Arc::clone(approval_state);
                    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(timeout_secs);
                    loop {
                        if let Some((decided, _reason)) = poll_state.take_decision(poll_session, &poll_gate) {
                            break decided;
                        }
                        if std::time::Instant::now() >= deadline {
                            break !on_timeout_deny;
                        }
                        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                    }
                } else {
                    // No approval mechanism configured — apply the timeout policy.
                    !on_timeout_deny
                };

                // Record the decision source in the ledger.
                let operator = if config.interactive { "cli" } else { "api" };
                let _ = ledger::append_event(
                    pool,
                    crate::schema::EventPayload::ApprovalDecision {
                        gate_id: gate_id.clone(),
                        approved,
                        reason: Some(format!("operator:{}", operator)),
                    },
                    config.session_id,
                    session_goal,
                    config.session_signing_key.as_deref(),
                )
                .await;

                if !approved {
                    append_thought(
                        pool,
                        &format!("Approval gate '{}' denied (timeout or operator reject).", gate_id),
                        config.session_id,
                        session_goal,
                        &config,
                        config.metrics.as_deref(),
                    )
                    .await?;
                    continue;
                }
                append_thought(
                    pool,
                    &format!("Approval gate '{}' approved.", gate_id),
                    config.session_id,
                    session_goal,
                    &config,
                    config.metrics.as_deref(),
                )
                .await?;
            }
        }

        let validated = match config.tripwire.validate(&intent) {
            Ok(v) => v,
            Err(e) => {
                if let Some(m) = &config.metrics {
                    m.inc_tripwire_rejections();
                }
                let msg = match &e {
                    TripwireError::PolicyViolation(_) => format!("Policy rejected: {}", e),
                    _ => format!("Tripwire rejected: {}", e),
                };
                append_thought(pool, &msg, config.session_id, session_goal, &config, config.metrics.as_deref()).await?;
                continue;
            }
        };

        if let Some(guard) = &mut config.guard {
            match guard.evaluate(&config.session_goal, &intent).await {
                Ok(GuardDecision::Deny { reason }) => {
                    consecutive_guard_denials += 1;
                    if let Some(m) = &config.metrics {
                        m.inc_guard_denials();
                    }
                    append_thought(
                        pool,
                        &format!("Guard denied: {}", reason),
                        config.session_id,
                        session_goal,
                        &config,
                        config.metrics.as_deref(),
                    )
                    .await?;
                    if consecutive_guard_denials >= guard_denial_limit {
                        append_thought(
                            pool,
                            &format!("Security: Guard denied {} consecutive actions; aborting session.", consecutive_guard_denials),
                            config.session_id,
                            session_goal,
                            &config,
                            config.metrics.as_deref(),
                        )
                        .await?;
                        return Err(AgentError::GuardAbort);
                    }
                    continue;
                }
                Ok(GuardDecision::Allow) => {
                    consecutive_guard_denials = 0;
                }
                Err(e) => {
                    append_thought(
                        pool,
                        &format!("Guard error (allowing): {}", e),
                        config.session_id,
                        session_goal,
                        &config,
                        config.metrics.as_deref(),
                    )
                    .await?;
                }
            }
        }

        let is_complete = validated.action() == "complete";

        if validated.action() == "http_get" {
            if let Some(url) = validated.params().get("url").and_then(|v| v.as_str()) {
                match ledger::find_cached_http_get(pool, url).await {
                    Ok(Some(cached)) => {
                        append_thought(
                            pool,
                            &format!("Idempotency: returning cached http_get for {}", url),
                            config.session_id,
                            session_goal,
                            &config,
                            config.metrics.as_deref(),
                        )
                        .await?;
                        append_observation(pool, &cached, config.session_id, session_goal, &config, config.metrics.as_deref()).await?;
                        continue;
                    }
                    Ok(None) => {}
                    Err(e) => {
                        tracing::warn!("Idempotency check failed (proceeding): {}", e);
                    }
                }
            }
        }

        let event_id = append_action(pool, &validated, config.session_id, session_goal, &config, config.metrics.as_deref()).await?;
        ledger::mark_action_executing(pool, event_id)
            .await
            .map_err(AgentError::Db)?;
        let observation = match executor::execute_with_policy(
            validated,
            config.cloud_creds.clone(),
            config.policy,
        )
        .await
        {
            Ok(s) => s,
            Err(e) => {
                let msg = format!("Execution error: {}", e);
                let _ = ledger::mark_action_failed(pool, event_id, &msg).await;
                append_observation(pool, &msg, config.session_id, session_goal, &config, config.metrics.as_deref()).await?;
                continue;
            }
        };
        ledger::mark_action_completed(pool, event_id)
            .await
            .map_err(AgentError::Db)?;
        let scan = output_scanner::scan_observation(&observation);
        if scan.is_suspicious {
            append_thought(
                pool,
                &format!("Security: suspicious content detected ({:?})", scan.matched_patterns),
                config.session_id,
                session_goal,
                &config,
                config.metrics.as_deref(),
            )
            .await?;
        }

        // Apply policy observation rules (redact / flag / abort).
        let final_observation = if let Some(policy) = config.policy {
            use crate::policy::ObservationOutcome;
            match policy.validate_observation(&scan.sanitized_content) {
                ObservationOutcome::Clean => scan.sanitized_content.clone(),
                ObservationOutcome::Redacted(redacted) => {
                    append_thought(
                        pool,
                        "Policy: sensitive content redacted from observation.",
                        config.session_id,
                        session_goal,
                        &config,
                        config.metrics.as_deref(),
                    )
                    .await?;
                    redacted
                }
                ObservationOutcome::Flagged(labels) => {
                    append_thought(
                        pool,
                        &format!("Policy: observation flagged ({}); continuing.", labels),
                        config.session_id,
                        session_goal,
                        &config,
                        config.metrics.as_deref(),
                    )
                    .await?;
                    if let Some(ref tx) = config.egress_tx {
                        let preview = observation.chars().take(200).collect::<String>();
                        let _ = tx.try_send(crate::webhook::EgressEvent {
                            session_id: config.session_id.unwrap_or_default(),
                            severity: "flag".to_string(),
                            rule_label: labels.clone(),
                            observation_preview: preview,
                        });
                    }
                    scan.sanitized_content.clone()
                }
                ObservationOutcome::Abort(reason) => {
                    append_thought(
                        pool,
                        &format!("Policy: aborting session — {}.", reason),
                        config.session_id,
                        session_goal,
                        &config,
                        config.metrics.as_deref(),
                    )
                    .await?;
                    if let Some(ref tx) = config.egress_tx {
                        let preview = observation.chars().take(200).collect::<String>();
                        let _ = tx.try_send(crate::webhook::EgressEvent {
                            session_id: config.session_id.unwrap_or_default(),
                            severity: "abort".to_string(),
                            rule_label: reason.clone(),
                            observation_preview: preview,
                        });
                    }
                    return Err(AgentError::PolicyAbort(reason.clone()));
                }
            }
        } else {
            scan.sanitized_content.clone()
        };

        append_observation(pool, &final_observation, config.session_id, session_goal, &config, config.metrics.as_deref()).await?;

        let interval = config::snapshot_interval();
        if step.is_multiple_of(interval) {
            if let Some((seq, _)) = ledger::get_latest(pool).await.map_err(AgentError::Db)? {
                if snapshot::snapshot_at_sequence(pool, seq).await.is_ok() {
                    if let Some(m) = &config.metrics {
                        m.inc_snapshots_created();
                    }
                }
            }
        }

        if is_complete {
            break;
        }
    }
    Ok(())
}

/// Returns true if the last 6 actions contain 3 or more repeats of the same (action, params).
///
/// Uses a frequency-counter hash map for O(n) complexity instead of O(n²) nested iteration.
fn detect_loop(events: &[LedgerEventRow]) -> bool {
    // Collect the last 6 action events as (name, serialised-params) pairs.
    // Params are serialised to String so they can be used as HashMap keys
    // (serde_json::Value does not implement Hash).
    let last: Vec<(String, String)> = events
        .iter()
        .filter_map(|e| {
            if let EventPayload::Action { name, params } = &e.payload {
                let params_key = serde_json::to_string(params).unwrap_or_default();
                Some((name.clone(), params_key))
            } else {
                None
            }
        })
        .rev()
        .take(6)
        .collect();

    if last.len() < 3 {
        return false;
    }

    let mut counts: std::collections::HashMap<(&str, &str), u32> =
        std::collections::HashMap::with_capacity(last.len());
    for (action, params) in &last {
        let n = counts.entry((action.as_str(), params.as_str())).or_insert(0);
        *n += 1;
        if *n >= 3 {
            return true;
        }
    }
    false
}

async fn perceive(pool: &PgPool) -> Result<crate::schema::RestoredState, AgentError> {
    match wakeup::restore_state(pool, false).await {
        Ok(s) => Ok(s),
        Err(WakeUpError::NoSnapshot) => wakeup::restore_state_from_genesis(pool)
            .await
            .map_err(AgentError::WakeUp),
        Err(e) => Err(AgentError::WakeUp(e)),
    }
}

async fn append_thought(
    pool: &PgPool,
    content: &str,
    session_id: Option<Uuid>,
    session_goal: Option<&str>,
    config: &AgentLoopConfig<'_>,
    metrics: Option<&crate::metrics::Metrics>,
) -> Result<(), AgentError> {
    ledger::append_event(
        pool,
        EventPayload::Thought {
            content: content.to_string(),
        },
        session_id,
        session_goal,
        config.session_signing_key.as_deref(),
    )
    .await
    .map_err(AgentError::Append)?;
    if let Some(m) = metrics {
        m.inc_events_appended();
    }
    Ok(())
}

async fn append_action(
    pool: &PgPool,
    validated: &ValidatedIntent,
    session_id: Option<Uuid>,
    session_goal: Option<&str>,
    config: &AgentLoopConfig<'_>,
    metrics: Option<&crate::metrics::Metrics>,
) -> Result<i64, AgentError> {
    let name = validated.action().to_string();
    let params = validated.params().clone();
    let appended = ledger::append_event(
        pool,
        EventPayload::Action { name, params },
        session_id,
        session_goal,
        config.session_signing_key.as_deref(),
    )
    .await
    .map_err(AgentError::Append)?;
    if let Some(m) = metrics {
        m.inc_events_appended();
    }
    Ok(appended.id)
}

async fn append_observation(
    pool: &PgPool,
    content: &str,
    session_id: Option<Uuid>,
    session_goal: Option<&str>,
    config: &AgentLoopConfig<'_>,
    metrics: Option<&crate::metrics::Metrics>,
) -> Result<(), AgentError> {
    ledger::append_event(
        pool,
        EventPayload::Observation {
            content: content.to_string(),
        },
        session_id,
        session_goal,
        config.session_signing_key.as_deref(),
    )
    .await
    .map_err(AgentError::Append)?;
    if let Some(m) = metrics {
        m.inc_events_appended();
    }
    Ok(())
}

#[derive(Debug)]
pub enum AgentError {
    WakeUp(WakeUpError),
    Db(sqlx::Error),
    Append(AppendError),
    CircuitBreaker,
    GuardAbort,
    TokenBudgetExceeded,
    /// Policy observation rule triggered an abort.
    PolicyAbort(String),
    /// Generic I/O error (used by orchestrator to wrap errors).
    Io(std::io::Error),
}

impl std::fmt::Display for AgentError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AgentError::WakeUp(e) => write!(f, "wakeup: {}", e),
            AgentError::Db(e) => write!(f, "db: {}", e),
            AgentError::Append(e) => write!(f, "append: {}", e),
            AgentError::CircuitBreaker => write!(f, "circuit breaker: too many consecutive LLM errors"),
            AgentError::GuardAbort => write!(f, "guard abort: too many consecutive denials"),
            AgentError::TokenBudgetExceeded => write!(f, "token budget exceeded: AGENT_TOKEN_BUDGET_MAX reached"),
            AgentError::PolicyAbort(r) => write!(f, "policy abort: {}", r),
            AgentError::Io(e) => write!(f, "io: {}", e),
        }
    }
}

impl std::error::Error for AgentError {}
