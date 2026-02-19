// Guard worker binary: reads one JSON line per request from stdin,
// writes "ALLOW" or "DENY: <reason>" to stdout. Runs in a separate process
// for real guard isolation (separate credentials, different model class).

use ironclad_agent_ledger::guard::Guard;
use ironclad_agent_ledger::intent::ProposedIntent;
use std::io::{BufRead, BufReader, Write};

#[derive(serde::Deserialize)]
struct GuardRequest {
    goal: String,
    intent: IntentPart,
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

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
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
        let req: GuardRequest = match serde_json::from_str(&trimmed) {
            Ok(r) => r,
            Err(e) => {
                writeln!(stdout, "DENY: invalid request JSON: {}", e)?;
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
                writeln!(stdout, "DENY: guard error: {}", e)?;
                stdout.flush()?;
                continue;
            }
        };
        let out = match decision {
            ironclad_agent_ledger::guard::GuardDecision::Allow => "ALLOW".to_string(),
            ironclad_agent_ledger::guard::GuardDecision::Deny { reason } => {
                format!("DENY: {}", reason)
            }
        };
        writeln!(stdout, "{}", out)?;
        stdout.flush()?;
    }
    Ok(())
}
