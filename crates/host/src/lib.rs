pub mod agent;
pub mod approvals;
pub mod cloud_creds;
pub mod red_team;
pub mod certificate;
pub mod config;
pub mod db_setup;
pub mod ledger;
pub mod llm;
pub mod executor;
pub mod guard;
pub mod guard_process;
pub mod metrics;
pub mod ollama;
pub mod orchestrator;
pub mod ots;
pub mod output_scanner;
pub mod policy;
pub mod report;
pub mod sandbox;
pub mod tripwire;
pub mod schema;
pub mod server;
pub mod signing;
pub mod snapshot;
pub mod wakeup;
pub mod webhook;

// Re-export ironclad_core's pure-logic modules into this crate's namespace.
// - `hash` / `merkle`: all `use crate::hash::*` and `use crate::merkle::*` calls resolve transparently.
// - `intent`: eliminates the wrapper file; `use crate::intent::ProposedIntent` etc. still work.
pub use ironclad_core::hash;
pub use ironclad_core::intent;
pub use ironclad_core::merkle;
