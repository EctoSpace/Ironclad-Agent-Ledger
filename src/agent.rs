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
            let _ = executor::execute(validated).await;
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
        let intent = match config.llm.propose(llm::DEFAULT_SYSTEM_PROMPT, &user).await {
            Ok(i) => {
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
        let observation = match executor::execute(validated).await {
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
        append_observation(pool, &scan.sanitized_content, config.session_id, session_goal, &config, config.metrics.as_deref()).await?;

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
fn detect_loop(events: &[LedgerEventRow]) -> bool {
    let actions: Vec<(&str, &serde_json::Value)> = events
        .iter()
        .filter_map(|e| {
            if let EventPayload::Action { name, params } = &e.payload {
                Some((name.as_str(), params))
            } else {
                None
            }
        })
        .collect();
    let last: Vec<_> = actions.iter().rev().take(6).rev().copied().collect();
    if last.len() < 3 {
        return false;
    }
    for (action, params) in &last {
        let count = last
            .iter()
            .filter(|(a, p)| *a == *action && *p == *params)
            .count();
        if count >= 3 {
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
}

impl std::fmt::Display for AgentError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AgentError::WakeUp(e) => write!(f, "wakeup: {}", e),
            AgentError::Db(e) => write!(f, "db: {}", e),
            AgentError::Append(e) => write!(f, "append: {}", e),
            AgentError::CircuitBreaker => write!(f, "circuit breaker: too many consecutive LLM errors"),
            AgentError::GuardAbort => write!(f, "guard abort: too many consecutive denials"),
        }
    }
}

impl std::error::Error for AgentError {}
