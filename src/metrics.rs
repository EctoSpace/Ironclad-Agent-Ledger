use std::sync::atomic::{AtomicU64, Ordering};

#[derive(Default)]
pub struct Metrics {
    pub events_appended: AtomicU64,
    pub tripwire_rejections: AtomicU64,
    pub guard_denials: AtomicU64,
    pub sessions_created: AtomicU64,
    pub snapshots_created: AtomicU64,
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
             ironclad_snapshots_created_total {}\n",
            self.events_appended.load(Ordering::Relaxed),
            self.tripwire_rejections.load(Ordering::Relaxed),
            self.guard_denials.load(Ordering::Relaxed),
            self.sessions_created.load(Ordering::Relaxed),
            self.snapshots_created.load(Ordering::Relaxed),
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
}
