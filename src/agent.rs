use crate::executor;
use crate::intent::ValidatedIntent;
use crate::ledger::{self, AppendError};
use crate::llm;
use crate::schema::EventPayload;
use crate::tripwire::Tripwire;
use crate::wakeup::{self, WakeUpError};
use reqwest::Client;
use sqlx::PgPool;

pub struct AgentLoopConfig<'a> {
    pub ollama_base_url: &'a str,
    pub ollama_model: &'a str,
    pub tripwire: &'a Tripwire,
    pub max_steps: Option<u32>,
}

pub async fn run_cognitive_loop(
    pool: &PgPool,
    client: &Client,
    config: AgentLoopConfig<'_>,
) -> Result<(), AgentError> {
    let mut step: u32 = 0;
    loop {
        if let Some(max) = config.max_steps {
            if step >= max {
                break;
            }
        }
        step += 1;

        let state = perceive(pool).await?;
        let intent = match llm::propose_intent(
            &state,
            client,
            config.ollama_base_url,
            config.ollama_model,
        )
        .await
        {
            Ok(i) => i,
            Err(e) => {
                append_thought(pool, &format!("LLM error: {}", e)).await?;
                continue;
            }
        };

        let validated = match config.tripwire.validate(&intent) {
            Ok(v) => v,
            Err(e) => {
                append_thought(pool, &format!("Tripwire rejected: {}", e)).await?;
                continue;
            }
        };

        let is_complete = validated.action() == "complete";
        append_action(pool, &validated).await?;
        let observation = match executor::execute(validated).await {
            Ok(s) => s,
            Err(e) => format!("Execution error: {}", e),
        };
        append_observation(pool, &observation).await?;

        if is_complete {
            break;
        }
    }
    Ok(())
}

async fn perceive(pool: &PgPool) -> Result<crate::schema::RestoredState, AgentError> {
    match wakeup::restore_state(pool, false).await {
        Ok(s) => Ok(s),
        Err(WakeUpError::NoSnapshot) => wakeup::restore_state_from_genesis(pool)
            .await
            .map_err(AgentError::Db),
        Err(e) => Err(AgentError::WakeUp(e)),
    }
}

async fn append_thought(pool: &PgPool, content: &str) -> Result<(), AgentError> {
    ledger::append_event(
        pool,
        EventPayload::Thought {
            content: content.to_string(),
        },
    )
    .await
    .map_err(AgentError::Append)?;
    Ok(())
}

async fn append_action(pool: &PgPool, validated: &ValidatedIntent) -> Result<(), AgentError> {
    let name = validated.action().to_string();
    let params = validated.params().clone();
    ledger::append_event(
        pool,
        EventPayload::Action { name, params },
    )
    .await
    .map_err(AgentError::Append)?;
    Ok(())
}

async fn append_observation(pool: &PgPool, content: &str) -> Result<(), AgentError> {
    ledger::append_event(
        pool,
        EventPayload::Observation {
            content: content.to_string(),
        },
    )
    .await
    .map_err(AgentError::Append)?;
    Ok(())
}

#[derive(Debug)]
pub enum AgentError {
    WakeUp(WakeUpError),
    Db(sqlx::Error),
    Append(AppendError),
}

impl std::fmt::Display for AgentError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AgentError::WakeUp(e) => write!(f, "wakeup: {}", e),
            AgentError::Db(e) => write!(f, "db: {}", e),
            AgentError::Append(e) => write!(f, "append: {}", e),
        }
    }
}

impl std::error::Error for AgentError {}
