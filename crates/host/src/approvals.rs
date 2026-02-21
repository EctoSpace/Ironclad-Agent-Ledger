// Human-in-the-loop approval gates: in-memory state and types.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::RwLock;
use uuid::Uuid;

#[derive(Clone, Debug, Serialize)]
pub struct PendingApproval {
    pub gate_id: String,
    pub action_name: String,
    pub action_params_summary: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct ApprovalDecisionRequest {
    pub gate_id: String,
    pub approved: bool,
    pub reason: Option<String>,
}

pub struct ApprovalState {
    pending: RwLock<HashMap<Uuid, PendingApproval>>,
    decisions: RwLock<HashMap<(Uuid, String), (bool, Option<String>)>>,
}

impl ApprovalState {
    pub fn new() -> Self {
        Self {
            pending: RwLock::new(HashMap::new()),
            decisions: RwLock::new(HashMap::new()),
        }
    }

    pub fn set_pending(&self, session_id: Uuid, approval: PendingApproval) {
        self.pending.write().unwrap().insert(session_id, approval);
    }

    pub fn get_pending(&self, session_id: Uuid) -> Option<PendingApproval> {
        self.pending.read().unwrap().get(&session_id).cloned()
    }

    pub fn record_decision(
        &self,
        session_id: Uuid,
        gate_id: String,
        approved: bool,
        reason: Option<String>,
    ) {
        self.decisions
            .write()
            .unwrap()
            .insert((session_id, gate_id), (approved, reason));
        self.pending.write().unwrap().remove(&session_id);
    }

    pub fn take_decision(&self, session_id: Uuid, gate_id: &str) -> Option<(bool, Option<String>)> {
        self.decisions
            .write()
            .unwrap()
            .remove(&(session_id, gate_id.to_string()))
    }
}

impl Default for ApprovalState {
    fn default() -> Self {
        Self::new()
    }
}
