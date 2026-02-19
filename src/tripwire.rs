use crate::intent::{ProposedIntent, ValidatedIntent};
use std::path::{Component, Path, PathBuf};

#[derive(Clone, Debug)]
pub struct Tripwire {
    allowed_path_prefixes: Vec<PathBuf>,
    allowed_domains: Vec<String>,
    banned_command_patterns: Vec<String>,
    require_https: bool,
}

impl Tripwire {
    pub fn new(
        allowed_path_prefixes: Vec<PathBuf>,
        allowed_domains: Vec<String>,
        banned_command_patterns: Vec<String>,
    ) -> Self {
        Tripwire {
            allowed_path_prefixes,
            allowed_domains,
            banned_command_patterns,
            require_https: true,
        }
    }

    pub fn with_require_https(mut self, require: bool) -> Self {
        self.require_https = require;
        self
    }

    pub fn validate(&self, intent: &ProposedIntent) -> Result<ValidatedIntent, TripwireError> {
        let action = intent.action.as_str();
        if action != "complete" {
            let just = intent.justification.trim();
            if just.len() < 5 {
                return Err(TripwireError::InsufficientJustification);
            }
        }
        match action {
            "run_command" => self.validate_command(intent),
            "read_file" => self.validate_path(intent),
            "http_get" => self.validate_url(intent),
            "complete" => Ok(ValidatedIntent::from_proposed(intent.clone())),
            _ => Err(TripwireError::UnknownAction(intent.action.clone())),
        }
    }

    fn validate_command(&self, intent: &ProposedIntent) -> Result<ValidatedIntent, TripwireError> {
        let cmd = intent
            .params_command()
            .ok_or(TripwireError::MissingParam("command"))?;
        let cmd_lower = cmd.to_lowercase();
        for banned in &self.banned_command_patterns {
            if cmd_lower.contains(&banned.to_lowercase()) {
                return Err(TripwireError::BannedCommand(cmd.to_string()));
            }
        }
        Ok(ValidatedIntent::from_proposed(intent.clone()))
    }

    fn validate_path(&self, intent: &ProposedIntent) -> Result<ValidatedIntent, TripwireError> {
        validate_path_strict(
            intent.params_path()
                .ok_or(TripwireError::MissingParam("path"))?,
            &self.allowed_path_prefixes,
        )
        .map(|_| ValidatedIntent::from_proposed(intent.clone()))
    }

    fn validate_url(&self, intent: &ProposedIntent) -> Result<ValidatedIntent, TripwireError> {
        let url_str = intent
            .params_url()
            .ok_or(TripwireError::MissingParam("url"))?;
        let url = url_str
            .parse::<url::Url>()
            .map_err(|_| TripwireError::InvalidUrl(url_str.to_string()))?;
        if self.require_https && url.scheme() != "https" {
            return Err(TripwireError::HttpsRequired(url_str.to_string()));
        }
        let host = url
            .host_str()
            .ok_or(TripwireError::InvalidUrl(url_str.to_string()))?;
        let allowed = self
            .allowed_domains
            .iter()
            .any(|d| host == d.as_str() || host.ends_with(&format!(".{}", d)));
        if !allowed {
            return Err(TripwireError::DomainNotAllowed(host.to_string()));
        }
        Ok(ValidatedIntent::from_proposed(intent.clone()))
    }
}

/// Normalizes a path without requiring filesystem access: removes `.` components
/// and collapses redundant slashes. Does not resolve `..` (caller must reject those first).
fn normalize_path(p: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for comp in p.components() {
        match comp {
            Component::Prefix(_) | Component::RootDir => out.push(comp.as_os_str()),
            Component::CurDir => {}
            Component::ParentDir => {
                out.pop();
            }
            Component::Normal(s) => out.push(s),
        }
    }
    if out.as_os_str().is_empty() {
        out.push(".");
    }
    out
}

/// Strict path validation: reject `..` before any canonicalization, resolve without
/// requiring existence, then for existing paths verify canonical form and symlink targets.
pub fn validate_path_strict(
    path_str: &str,
    allowed_prefixes: &[PathBuf],
) -> Result<PathBuf, TripwireError> {
    let raw = Path::new(path_str);
    for component in raw.components() {
        if component == Component::ParentDir {
            return Err(TripwireError::PathTraversal(path_str.to_string()));
        }
    }
    let absolute = if raw.is_absolute() {
        raw.to_path_buf()
    } else {
        std::env::current_dir()
            .map_err(|_| TripwireError::InvalidPath(path_str.to_string()))?
            .join(raw)
    };
    let normalized = normalize_path(&absolute);
    let check_path = if normalized.exists() {
        let canonical = normalized
            .canonicalize()
            .map_err(|_| TripwireError::InvalidPath(path_str.to_string()))?;
        if !allowed_prefixes
            .iter()
            .any(|p| canonical.starts_with(p))
        {
            return Err(TripwireError::SymlinkEscape(
                canonical.display().to_string(),
            ));
        }
        canonical
    } else {
        normalized.clone()
    };
    if !allowed_prefixes
        .iter()
        .any(|p| check_path.starts_with(p))
    {
        return Err(TripwireError::PathNotAllowed(
            check_path.display().to_string(),
        ));
    }
    Ok(check_path)
}

pub fn default_banned_command_patterns() -> Vec<String> {
    vec![
        "rm -rf".to_string(),
        "sudo".to_string(),
        "mkfs".to_string(),
        "dd ".to_string(),
        "/dev/sda".to_string(),
        "chmod 777".to_string(),
        "> /dev/".to_string(),
        "wget ".to_string(),
        "curl | sh".to_string(),
    ]
}

#[derive(Debug)]
pub enum TripwireError {
    UnknownAction(String),
    MissingParam(&'static str),
    BannedCommand(String),
    PathTraversal(String),
    InvalidPath(String),
    PathNotAllowed(String),
    SymlinkEscape(String),
    PolicyViolation(String),
    InvalidUrl(String),
    HttpsRequired(String),
    DomainNotAllowed(String),
    InsufficientJustification,
}

impl std::fmt::Display for TripwireError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TripwireError::UnknownAction(a) => write!(f, "unknown action: {}", a),
            TripwireError::MissingParam(p) => write!(f, "missing param: {}", p),
            TripwireError::BannedCommand(c) => write!(f, "banned command: {}", c),
            TripwireError::PathTraversal(p) => write!(f, "path traversal: {}", p),
            TripwireError::InvalidPath(p) => write!(f, "invalid path: {}", p),
            TripwireError::PathNotAllowed(p) => write!(f, "path not allowed: {}", p),
            TripwireError::SymlinkEscape(p) => write!(f, "symlink escapes allowed path: {}", p),
            TripwireError::PolicyViolation(p) => write!(f, "policy violation: {}", p),
            TripwireError::InvalidUrl(u) => write!(f, "invalid url: {}", u),
            TripwireError::HttpsRequired(u) => write!(f, "https required: {}", u),
            TripwireError::DomainNotAllowed(d) => write!(f, "domain not allowed: {}", d),
            TripwireError::InsufficientJustification => {
                write!(f, "justification missing or too short (min 5 chars)")
            }
        }
    }
}

impl std::error::Error for TripwireError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tripwire_rejects_banned_command() {
        let tw = Tripwire::new(
            vec![],
            vec![],
            vec!["sudo".to_string(), "rm -rf".to_string()],
        );
        let intent = ProposedIntent {
            action: "run_command".to_string(),
            params: serde_json::json!({ "command": "sudo ls" }),
            justification: "elevated privilege check".to_string(),
            reasoning: String::new(),
        };
        assert!(tw.validate(&intent).is_err());
    }

    #[test]
    fn tripwire_rejects_empty_justification() {
        let tw = Tripwire::new(vec![], vec![], vec![]);
        let intent = ProposedIntent {
            action: "run_command".to_string(),
            params: serde_json::json!({ "command": "ls -la" }),
            justification: String::new(),
            reasoning: String::new(),
        };
        assert!(matches!(tw.validate(&intent), Err(TripwireError::InsufficientJustification)));
    }

    #[test]
    fn tripwire_accepts_safe_command() {
        let tw = Tripwire::new(
            vec![],
            vec![],
            vec!["sudo".to_string()],
        );
        let intent = ProposedIntent {
            action: "run_command".to_string(),
            params: serde_json::json!({ "command": "ls -la" }),
            justification: "listing directory contents".to_string(),
            reasoning: String::new(),
        };
        assert!(tw.validate(&intent).is_ok());
    }

    #[test]
    fn tripwire_complete_always_ok() {
        let tw = Tripwire::new(vec![], vec![], vec!["sudo".to_string()]);
        let intent = ProposedIntent {
            action: "complete".to_string(),
            params: serde_json::Value::Object(serde_json::Map::new()),
            justification: String::new(),
            reasoning: String::new(),
        };
        assert!(tw.validate(&intent).is_ok());
    }
}
