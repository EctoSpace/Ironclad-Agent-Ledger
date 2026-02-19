// Guard worker binary: reads one HMAC-authenticated JSON line per request from stdin,
// verifies the HMAC, evaluates the intent, and writes an HMAC-signed
// "ALLOW\t<hmac>" or "DENY: <reason>\t<hmac>" line to stdout.
// Running in a separate process provides real guard isolation.

use hmac::{Hmac, Mac};
use ironclad_agent_ledger::guard::Guard;
use ironclad_agent_ledger::intent::ProposedIntent;
use sha2::Sha256;
use std::io::{BufRead, BufReader, Write};

type HmacSha256 = Hmac<Sha256>;

const HMAC_KEY_ENV: &str = "GUARD_HMAC_KEY";

#[derive(serde::Deserialize)]
struct GuardRequest {
    goal: String,
    intent: IntentPart,
    #[serde(default)]
    #[allow(dead_code)]
    nonce: u64,
}

#[derive(serde::Deserialize)]
struct IntentPart {
    action: String,
    params: serde_json::Value,
    #[serde(default)]
    justification: Option<String>,
    #[serde(default)]
    reasoning: Option<String>,
}

fn compute_hmac(key: &[u8], nonce: u64, body: &str) -> String {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key size");
    mac.update(nonce.to_string().as_bytes());
    mac.update(b":");
    mac.update(body.as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

fn verify_hmac(key: &[u8], nonce: u64, body: &str, expected_hex: &str) -> bool {
    let Ok(expected_bytes) = hex::decode(expected_hex) else { return false; };
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key size");
    mac.update(nonce.to_string().as_bytes());
    mac.update(b":");
    mac.update(body.as_bytes());
    mac.verify_slice(&expected_bytes).is_ok()
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Apply seccomp filter before any user-controlled input is processed.
    // On non-Linux or without the sandbox feature this is a no-op.
    if let Err(e) = ironclad_agent_ledger::sandbox::apply_guard_worker_seccomp() {
        eprintln!("guard-worker: seccomp setup failed: {}; continuing without filter", e);
    }

    // Load the session-scoped HMAC key injected by the parent process.
    let hmac_key: Vec<u8> = std::env::var(HMAC_KEY_ENV)
        .ok()
        .and_then(|s| hex::decode(s).ok())
        .unwrap_or_default();

    let hmac_enabled = hmac_key.len() == 32;
    if !hmac_enabled {
        eprintln!("guard-worker: {} not set or invalid; running without HMAC authentication", HMAC_KEY_ENV);
    }

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(60))
        .build()?;
    let guard = Guard::from_env(&client)?;
    let stdin = std::io::stdin();
    let mut reader = BufReader::new(stdin.lock());
    let mut stdout = std::io::stdout();
    let mut line = String::new();

    while reader.read_line(&mut line)? > 0 {
        let trimmed = line.trim().to_string();
        line.clear();
        if trimmed.is_empty() {
            continue;
        }

        // Parse `<json>\t<hmac_hex>` (or plain JSON if HMAC was not set).
        let (json_part, maybe_hmac) = match trimmed.rsplit_once('\t') {
            Some((j, h)) => (j, Some(h)),
            None => (trimmed.as_str(), None),
        };

        // Extract nonce from the raw JSON before full deserialization so we can
        // verify HMAC (which covers the original json_part including the nonce).
        let nonce: u64 = serde_json::from_str::<serde_json::Value>(json_part)
            .ok()
            .and_then(|v| v.get("nonce").and_then(|n| n.as_u64()))
            .unwrap_or(0);

        // Verify HMAC when authentication is enabled.
        if hmac_enabled {
            match maybe_hmac {
                Some(recv_mac) if verify_hmac(&hmac_key, nonce, json_part, recv_mac) => {}
                _ => {
                    let verdict = "DENY: request HMAC verification failed";
                    let resp_mac = compute_hmac(&hmac_key, nonce, verdict);
                    writeln!(stdout, "{}\t{}", verdict, resp_mac)?;
                    stdout.flush()?;
                    continue;
                }
            }
        }

        let req: GuardRequest = match serde_json::from_str(json_part) {
            Ok(r) => r,
            Err(e) => {
                let verdict = format!("DENY: invalid request JSON: {}", e);
                if hmac_enabled {
                    let resp_mac = compute_hmac(&hmac_key, nonce, &verdict);
                    writeln!(stdout, "{}\t{}", verdict, resp_mac)?;
                } else {
                    writeln!(stdout, "{}", verdict)?;
                }
                stdout.flush()?;
                continue;
            }
        };

        let intent = ProposedIntent {
            action: req.intent.action,
            params: req.intent.params,
            justification: req.intent.justification.unwrap_or_default(),
            reasoning: req.intent.reasoning.unwrap_or_default(),
        };
        let decision = match guard.evaluate(&req.goal, &intent).await {
            Ok(d) => d,
            Err(e) => {
                let verdict = format!("DENY: guard error: {}", e);
                if hmac_enabled {
                    let resp_mac = compute_hmac(&hmac_key, nonce, &verdict);
                    writeln!(stdout, "{}\t{}", verdict, resp_mac)?;
                } else {
                    writeln!(stdout, "{}", verdict)?;
                }
                stdout.flush()?;
                continue;
            }
        };

        let verdict = match decision {
            ironclad_agent_ledger::guard::GuardDecision::Allow => "ALLOW".to_string(),
            ironclad_agent_ledger::guard::GuardDecision::Deny { reason } => {
                format!("DENY: {}", reason)
            }
        };

        if hmac_enabled {
            let resp_mac = compute_hmac(&hmac_key, nonce, &verdict);
            writeln!(stdout, "{}\t{}", verdict, resp_mac)?;
        } else {
            writeln!(stdout, "{}", verdict)?;
        }
        stdout.flush()?;
    }
    Ok(())
}
