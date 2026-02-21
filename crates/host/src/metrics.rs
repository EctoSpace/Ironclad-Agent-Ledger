use std::sync::atomic::{AtomicU64, Ordering};

#[derive(Default)]
pub struct Metrics {
    pub events_appended: AtomicU64,
    pub tripwire_rejections: AtomicU64,
    pub guard_denials: AtomicU64,
    pub sessions_created: AtomicU64,
    pub snapshots_created: AtomicU64,
    /// Approximate token count (character count / 4). Used by the token budget circuit breaker.
    pub token_count: AtomicU64,
    /// Number of output scanner detections (injection / exfiltration patterns found).
    pub scanner_detections: AtomicU64,
    /// Number of guard process detections (guard said DENY).
    pub guard_detections: AtomicU64,
    /// Number of tripwire rule violations (distinct from guard denials).
    pub tripwire_detections: AtomicU64,
}

impl Metrics {
    pub fn prometheus_text(&self) -> String {
        format!(
            "# HELP ironclad_events_appended_total Total events appended to the ledger.\n\
             # TYPE ironclad_events_appended_total counter\n\
             ironclad_events_appended_total {}\n\
             # HELP ironclad_tripwire_rejections_total Total tripwire rejections.\n\
             # TYPE ironclad_tripwire_rejections_total counter\n\
             ironclad_tripwire_rejections_total {}\n\
             # HELP ironclad_guard_denials_total Total guard denials.\n\
             # TYPE ironclad_guard_denials_total counter\n\
             ironclad_guard_denials_total {}\n\
             # HELP ironclad_sessions_created_total Total sessions created.\n\
             # TYPE ironclad_sessions_created_total counter\n\
             ironclad_sessions_created_total {}\n\
             # HELP ironclad_snapshots_created_total Total snapshots created.\n\
             # TYPE ironclad_snapshots_created_total counter\n\
             ironclad_snapshots_created_total {}\n\
             # HELP ironclad_token_count_total Approximate token count consumed (chars/4).\n\
             # TYPE ironclad_token_count_total counter\n\
             ironclad_token_count_total {}\n\
             # HELP ironclad_scanner_detections_total Output scanner detections.\n\
             # TYPE ironclad_scanner_detections_total counter\n\
             ironclad_scanner_detections_total {}\n\
             # HELP ironclad_guard_detections_total Guard DENY decisions.\n\
             # TYPE ironclad_guard_detections_total counter\n\
             ironclad_guard_detections_total {}\n\
             # HELP ironclad_tripwire_detections_total Tripwire rule violations.\n\
             # TYPE ironclad_tripwire_detections_total counter\n\
             ironclad_tripwire_detections_total {}\n",
            self.events_appended.load(Ordering::Relaxed),
            self.tripwire_rejections.load(Ordering::Relaxed),
            self.guard_denials.load(Ordering::Relaxed),
            self.sessions_created.load(Ordering::Relaxed),
            self.snapshots_created.load(Ordering::Relaxed),
            self.token_count.load(Ordering::Relaxed),
            self.scanner_detections.load(Ordering::Relaxed),
            self.guard_detections.load(Ordering::Relaxed),
            self.tripwire_detections.load(Ordering::Relaxed),
        )
    }

    pub fn inc_events_appended(&self) {
        self.events_appended.fetch_add(1, Ordering::Relaxed);
    }
    pub fn inc_tripwire_rejections(&self) {
        self.tripwire_rejections.fetch_add(1, Ordering::Relaxed);
    }
    pub fn inc_guard_denials(&self) {
        self.guard_denials.fetch_add(1, Ordering::Relaxed);
    }
    pub fn inc_sessions_created(&self) {
        self.sessions_created.fetch_add(1, Ordering::Relaxed);
    }
    pub fn inc_snapshots_created(&self) {
        self.snapshots_created.fetch_add(1, Ordering::Relaxed);
    }
    /// Add an approximate token count (len / 4) for a prompt or response text.
    pub fn add_tokens_for_text(&self, text: &str) {
        let approx = (text.len() as u64).saturating_add(3) / 4;
        self.token_count.fetch_add(approx, Ordering::Relaxed);
    }
    pub fn inc_scanner_detections(&self) {
        self.scanner_detections.fetch_add(1, Ordering::Relaxed);
    }
    pub fn inc_guard_detections(&self) {
        self.guard_detections.fetch_add(1, Ordering::Relaxed);
    }
    pub fn inc_tripwire_detections(&self) {
        self.tripwire_detections.fetch_add(1, Ordering::Relaxed);
    }
    /// Current approximate token count.
    pub fn current_token_count(&self) -> u64 {
        self.token_count.load(Ordering::Relaxed)
    }
}
