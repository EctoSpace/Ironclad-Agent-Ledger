// Audit report export: SARIF 2.1, JSON, HTML.

use crate::ledger;
use crate::schema::{AuditFinding, EventPayload, LedgerEventRow, SessionRow};
use serde::Serialize;
use sqlx::PgPool;
use uuid::Uuid;

#[derive(Clone, Debug, Serialize)]
pub struct AuditReport {
    pub session: SessionRow,
    pub ledger_hash: String,
    pub verification_status: ChainVerificationStatus,
    pub findings: Vec<VerifiedFinding>,
    pub timeline: Vec<AuditEventSummary>,
    pub metrics: AuditMetrics,
}

#[derive(Clone, Debug, Serialize)]
pub enum ChainVerificationStatus {
    Verified,
    Failed,
    NotChecked,
}

#[derive(Clone, Debug, Serialize)]
pub struct VerifiedFinding {
    pub severity: String,
    pub title: String,
    pub evidence: String,
    pub recommendation: String,
    pub evidence_sequences: Vec<i64>,
}

#[derive(Clone, Debug, Serialize)]
pub struct AuditEventSummary {
    pub sequence: i64,
    pub kind: String,
    pub summary: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct AuditMetrics {
    pub event_count: usize,
    pub finding_count: usize,
}

pub async fn build_report(pool: &PgPool, session_id: Uuid) -> Result<AuditReport, ReportError> {
    let session = ledger::list_sessions(pool)
        .await
        .map_err(ReportError::Db)?
        .into_iter()
        .find(|s| s.id == session_id)
        .ok_or(ReportError::SessionNotFound(session_id))?;

    let events = ledger::get_events_by_session(pool, session_id)
        .await
        .map_err(ReportError::Db)?;

    let ledger_hash = events
        .last()
        .map(|e| e.content_hash.clone())
        .unwrap_or_else(|| "none".to_string());

    let (from, to) = match (events.first(), events.last()) {
        (Some(a), Some(b)) => (a.sequence, b.sequence),
        _ => (0, 0),
    };
    let verification_status = if events.is_empty() {
        ChainVerificationStatus::NotChecked
    } else if ledger::verify_chain(pool, from, to)
        .await
        .map_err(ReportError::Db)?
    {
        ChainVerificationStatus::Verified
    } else {
        ChainVerificationStatus::Failed
    };

    let mut findings = Vec::new();
    for ev in &events {
        if let EventPayload::Action { name, params } = &ev.payload {
            if name == "complete" {
                if let Some(fv) = params.get("findings") {
                    if let Ok(fs) = serde_json::from_value::<Vec<AuditFinding>>(fv.clone()) {
                        for f in fs {
                            findings.push(VerifiedFinding {
                                severity: format!("{:?}", f.severity).to_lowercase(),
                                title: f.title,
                                evidence: f.evidence,
                                recommendation: f.recommendation,
                                evidence_sequences: f.evidence_sequence,
                            });
                        }
                    }
                }
            }
        }
    }

    let timeline: Vec<AuditEventSummary> = events
        .iter()
        .map(|e| event_summary(e))
        .collect();

    let metrics = AuditMetrics {
        event_count: events.len(),
        finding_count: findings.len(),
    };

    Ok(AuditReport {
        session,
        ledger_hash,
        verification_status,
        findings,
        timeline,
        metrics,
    })
}

fn event_summary(e: &LedgerEventRow) -> AuditEventSummary {
    let (kind, summary) = match &e.payload {
        EventPayload::Genesis { message } => ("genesis", message.clone()),
        EventPayload::Thought { content } => (
            "thought",
            if content.len() > 80 {
                format!("{}...", &content[..80])
            } else {
                content.clone()
            },
        ),
        EventPayload::Action { name, params } => {
            ("action", format!("{} {:?}", name, params))
        }
        EventPayload::Observation { content } => (
            "observation",
            if content.len() > 80 {
                format!("{}...", &content[..80])
            } else {
                content.clone()
            },
        ),
        EventPayload::ApprovalRequired {
            gate_id,
            action_name,
            action_params_summary,
        } => (
            "approval_required",
            format!("gate {}: {} {}", gate_id, action_name, action_params_summary),
        ),
        EventPayload::ApprovalDecision {
            gate_id,
            approved,
            reason,
        } => (
            "approval_decision",
            format!(
                "gate {}: {} {}",
                gate_id,
                if *approved { "approved" } else { "denied" },
                reason.as_deref().unwrap_or("")
            ),
        ),
        EventPayload::CrossLedgerSeal { seal_hash, session_ids, .. } => (
            "cross_ledger_seal",
            format!("seal {} covering {} sessions", &seal_hash[..16], session_ids.len()),
        ),
        EventPayload::Anchor { ledger_tip_hash, bitcoin_block_height, .. } => (
            "anchor",
            format!(
                "OTS anchor tip {} block {:?}",
                &ledger_tip_hash[..16],
                bitcoin_block_height
            ),
        ),
    };
    AuditEventSummary {
        sequence: e.sequence,
        kind: kind.to_string(),
        summary,
    }
}

pub fn report_to_sarif(report: &AuditReport, session_id: Uuid) -> serde_json::Value {
    let results: Vec<serde_json::Value> = report
        .findings
        .iter()
        .enumerate()
        .map(|(i, f)| {
            let rule_id = format!("finding-{}", i + 1);
            let level = match f.severity.as_str() {
                "critical" => "error",
                "high" => "error",
                "medium" => "warning",
                _ => "note",
            };
            let locations: Vec<serde_json::Value> = f
                .evidence_sequences
                .iter()
                .map(|&seq| {
                    serde_json::json!({
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": format!("ledger://session/{}/sequence/{}", session_id, seq)
                            },
                            "region": { "startLine": 1 }
                        }
                    })
                })
                .collect();
            serde_json::json!({
                "ruleId": rule_id,
                "level": level,
                "message": { "text": f.title },
                "locations": if locations.is_empty() {
                    vec![serde_json::json!({ "physicalLocation": { "artifactLocation": { "uri": "ledger://" } } })]
                } else {
                    locations
                }
            })
        })
        .collect();

    serde_json::json!({
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "Ironclad Agent Ledger",
                    "version": env!("CARGO_PKG_VERSION"),
                    "informationUri": "https://github.com/bjornkohlberger/Ironclad-Agent-Ledger",
                    "rules": report.findings.iter().enumerate().map(|(i, f)| {
                        serde_json::json!({
                            "id": format!("finding-{}", i + 1),
                            "name": f.title,
                            "shortDescription": { "text": f.evidence },
                            "defaultConfiguration": { "level": "warning" }
                        })
                    }).collect::<Vec<_>>()
                }
            },
            "results": results,
            "properties": {
                "ledgerHash": report.ledger_hash,
                "verificationStatus": format!("{:?}", report.verification_status),
                "sessionId": report.session.id.to_string()
            }
        }]
    })
}

pub fn report_to_html(report: &AuditReport, session_id: Uuid) -> String {
    let status_class = match &report.verification_status {
        crate::report::ChainVerificationStatus::Verified => "verified",
        crate::report::ChainVerificationStatus::Failed => "failed",
        crate::report::ChainVerificationStatus::NotChecked => "unknown",
    };
    let findings_rows: String = report
        .findings
        .iter()
        .map(|f| {
            let seq_links: String = f
                .evidence_sequences
                .iter()
                .map(|seq| format!(
                    "<a href=\"#seq-{}\">#{}</a> ",
                    seq, seq
                ))
                .collect();
            format!(
                r#"<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>"#,
                f.severity,
                html_escape(&f.title),
                html_escape(&f.evidence),
                html_escape(&f.recommendation),
                seq_links
            )
        })
        .collect();
    let timeline_rows: String = report
        .timeline
        .iter()
        .map(|e| {
            format!(
                r#"<tr id="seq-{}"><td>{}</td><td>{}</td><td>{}</td></tr>"#,
                e.sequence,
                e.sequence,
                e.kind,
                html_escape(&e.summary)
            )
        })
        .collect();

    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"/><title>Audit Report — {}</title>
<style>
  body {{ font-family: system-ui; margin: 24px; background: #0d1117; color: #c9d1d9; }}
  .hash {{ font-family: monospace; word-break: break-all; }}
  .verified {{ color: #3fb950; }}
  .failed {{ color: #f85149; }}
  table {{ border-collapse: collapse; width: 100%; margin-top: 12px; }}
  th, td {{ border: 1px solid #30363d; padding: 8px; text-align: left; }}
  th {{ background: #21262d; }}
  a {{ color: #58a6ff; }}
</style>
</head>
<body>
<h1>Audit Report</h1>
<p><strong>Session:</strong> {}<br/>
<strong>Goal:</strong> {}<br/>
<strong>Ledger hash:</strong> <span class="hash">{}</span><br/>
<strong>Chain verification:</strong> <span class="{}">{:?}</span></p>
<h2>Findings ({})</h2>
<table><thead><tr><th>Severity</th><th>Title</th><th>Evidence</th><th>Recommendation</th><th>Ledger refs</th></tr></thead>
<tbody>{}</tbody></table>
<h2>Timeline</h2>
<table><thead><tr><th>Seq</th><th>Kind</th><th>Summary</th></tr></thead>
<tbody>{}</tbody></table>
</body></html>"#,
        session_id,
        session_id,
        html_escape(&report.session.goal),
        report.ledger_hash,
        status_class,
        report.verification_status,
        report.findings.len(),
        findings_rows,
        timeline_rows
    )
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

#[derive(Debug)]
pub enum ReportError {
    Db(sqlx::Error),
    SessionNotFound(Uuid),
}

impl std::fmt::Display for ReportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ReportError::Db(e) => write!(f, "db: {}", e),
            ReportError::SessionNotFound(id) => write!(f, "session not found: {}", id),
        }
    }
}

impl std::error::Error for ReportError {}
