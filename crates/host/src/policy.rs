// Host-side policy module.
//
// All pure evaluation types and the PolicyEngine are defined in `ironclad_core::policy`
// and re-exported here so that existing `use crate::policy::*` imports resolve unchanged.
//
// This module adds the TOML file-loading layer (`PolicyLoadError`, `load_policy_engine`)
// which requires std file I/O and is therefore kept out of the no-I/O-dependency core crate.

pub use ironclad_core::policy::*;

use std::path::Path;

// ── Load error (host-only) ─────────────────────────────────────────────────────

#[derive(Debug)]
pub enum PolicyLoadError {
    Io(std::io::Error),
    Toml(toml::de::Error),
}

impl std::fmt::Display for PolicyLoadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PolicyLoadError::Io(e) => write!(f, "io: {}", e),
            PolicyLoadError::Toml(e) => write!(f, "toml: {}", e),
        }
    }
}

impl std::error::Error for PolicyLoadError {}

// ── File loader (host-only) ────────────────────────────────────────────────────

/// Parse an `AuditPolicy` from a TOML file and wrap it in a `PolicyEngine`.
///
/// The `PolicyEngine` itself lives in `ironclad_core` (no file I/O).
/// This free function is the host-side entry point for loading policies from disk.
pub fn load_policy_engine(path: &Path) -> Result<PolicyEngine, PolicyLoadError> {
    let s = std::fs::read_to_string(path).map_err(PolicyLoadError::Io)?;
    let policy: AuditPolicy = toml::from_str(&s).map_err(PolicyLoadError::Toml)?;
    Ok(PolicyEngine::new(policy))
}
