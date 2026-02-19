// Async webhook / SIEM egress dispatcher.
//
// When WEBHOOK_URL is set, security events (policy flag, observation abort) are forwarded
// to an external endpoint in the background without blocking the cognitive loop.
//
// Supported SIEM_FORMAT values:
//   json  — standard JSON body (default, works with Slack, custom endpoints, Splunk HEC)
//   cef   — ArcSight Common Event Format (syslog-style header line)
//   leef  — IBM LEEF 2.0 (tab-separated key-value pairs)

use crate::config::WebhookConfig;
use tokio::sync::mpsc;
use uuid::Uuid;

const CHANNEL_CAPACITY: usize = 256;

/// A security event dispatched from the cognitive loop to the egress worker.
#[derive(Clone, Debug)]
pub struct EgressEvent {
    pub session_id: Uuid,
    /// `"flag"` when an observation rule triggers a warning, `"abort"` when it terminates the session.
    pub severity: String,
    /// Short label from the `ObservationRule` that matched (e.g. `"credential_leak"`).
    pub rule_label: String,
    /// First 200 chars of the sanitized observation content (no raw secrets).
    pub observation_preview: String,
}

/// Spawns the background egress worker and returns the sender end of its channel.
/// The worker runs until all senders are dropped.
pub fn spawn_egress_worker(config: WebhookConfig) -> mpsc::Sender<EgressEvent> {
    let (tx, rx) = mpsc::channel::<EgressEvent>(CHANNEL_CAPACITY);
    tokio::spawn(egress_loop(config, rx));
    tx
}

async fn egress_loop(config: WebhookConfig, mut rx: mpsc::Receiver<EgressEvent>) {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .unwrap_or_default();

    while let Some(event) = rx.recv().await {
        let body = format_event(&event, &config.siem_format);
        let mut req = client.post(&config.url).header("Content-Type", content_type(&config.siem_format));
        if let Some(ref token) = config.bearer_token {
            req = req.header("Authorization", format!("Bearer {}", token));
        }
        req = req.body(body);
        if let Err(e) = req.send().await {
            tracing::warn!(
                "Webhook egress failed (session={} label={}): {}",
                event.session_id, event.rule_label, e
            );
        }
    }
}

fn content_type(format: &str) -> &'static str {
    match format {
        "cef" | "leef" => "text/plain",
        _ => "application/json",
    }
}

fn format_event(event: &EgressEvent, format: &str) -> String {
    match format {
        "cef" => format_cef(event),
        "leef" => format_leef(event),
        _ => format_json(event),
    }
}

fn format_json(event: &EgressEvent) -> String {
    serde_json::json!({
        "source": "ironclad-agent-ledger",
        "session_id": event.session_id.to_string(),
        "severity": event.severity,
        "rule_label": event.rule_label,
        "observation_preview": event.observation_preview,
        "timestamp": chrono::Utc::now().to_rfc3339(),
    })
    .to_string()
}

/// ArcSight CEF (Common Event Format): syslog-like header + key-value extension.
fn format_cef(event: &EgressEvent) -> String {
    let cef_severity = if event.severity == "abort" { "9" } else { "5" };
    format!(
        "CEF:0|Ironclad|AgentLedger|1.0|observation_policy|{rule}|{sev}|session={sid} label={label} preview={prev}",
        rule = event.rule_label,
        sev = cef_severity,
        sid = event.session_id,
        label = event.rule_label,
        prev = event.observation_preview.replace('|', "\\|"),
    )
}

/// IBM LEEF 2.0: tab-separated key-value attributes after a header.
fn format_leef(event: &EgressEvent) -> String {
    format!(
        "LEEF:2.0|Ironclad|AgentLedger|1.0|observation_policy|\tsrc=ironclad\tsessionId={sid}\tseverity={sev}\truleLabel={label}\tobservation={prev}",
        sid = event.session_id,
        sev = event.severity,
        label = event.rule_label,
        prev = event.observation_preview.replace('\t', " "),
    )
}
