use crate::error::{PlensError, Result};
use crate::model::ScanSummary;
use serde_json::json;

pub fn export_json(summary: &ScanSummary) -> Result<String> {
    let mut val = serde_json::to_value(summary).map_err(|e| PlensError::Other(e.to_string()))?;
    if let Some(obj) = val.as_object_mut() {
        obj.insert("schema".to_string(), json!("plens.scan/1"));
    }
    serde_json::to_string_pretty(&val).map_err(|e| PlensError::Other(e.to_string()))
}

pub fn export_csv(summary: &ScanSummary) -> Result<String> {
    let mut wtr = csv::Writer::from_writer(vec![]);
    wtr.write_record([
        "host", "port", "protocol", "state", "service", "version", "verdict",
    ])
    .map_err(|e| PlensError::Other(e.to_string()))?;

    for host in &summary.hosts {
        for p in &host.ports {
            let srv_name = p
                .service
                .as_ref()
                .map(|s| s.name.as_str())
                .unwrap_or("unknown");
            let srv_ver = p
                .service
                .as_ref()
                .and_then(|s| s.version.as_deref())
                .unwrap_or("");
            let verdict = p.verdict.map(|v| v.as_str()).unwrap_or("");
            wtr.write_record([
                &host.target,
                &p.number.to_string(),
                &p.protocol.to_string(),
                &p.state.to_string(),
                srv_name,
                srv_ver,
                verdict,
            ])
            .map_err(|e| PlensError::Other(e.to_string()))?;
        }
    }

    let bytes = wtr
        .into_inner()
        .map_err(|e| PlensError::Other(e.to_string()))?;
    String::from_utf8(bytes).map_err(|e| PlensError::Other(e.to_string()))
}

pub fn export_markdown(summary: &ScanSummary) -> Result<String> {
    let mut md = String::new();
    md.push_str("# PortLens Exposure Audit Report\n\n");
    md.push_str(&format!("- **Scan ID:** `{}`\n", summary.scan_id));
    md.push_str(&format!("- **Targets:** `{}`\n", summary.targets.join(", ")));
    md.push_str(&format!("- **Preset:** `{}`\n", summary.preset));
    if let Some(ref prof) = summary.profile {
        md.push_str(&format!("- **Profile:** `{prof}`\n"));
    }
    md.push_str(&format!("- **Duration:** {:.2}s\n", summary.duration_ms as f64 / 1000.0));
    md.push_str(&format!(
        "- **Risk Posture:** Grade **{}** (Score: **{}/100**)\n",
        summary.risk_score.grade, summary.risk_score.score
    ));
    if let Some(ref trend) = summary.risk_score.trend_description {
        md.push_str(&format!("- **Trend:** {trend}\n"));
    }
    md.push_str("\n---\n\n");

    md.push_str("## Open Ports & Visibilities\n\n");
    md.push_str("| Host | Port | Protocol | State | Service | Version | Verdict |\n");
    md.push_str("|---|---|---|---|---|---|---|\n");
    for host in &summary.hosts {
        for p in &host.ports {
            let srv = p
                .service
                .as_ref()
                .map(|s| s.name.as_str())
                .unwrap_or("unknown");
            let ver = p
                .service
                .as_ref()
                .and_then(|s| s.version.as_deref())
                .unwrap_or("-");
            let verdict = p.verdict.map(|v| v.as_str()).unwrap_or("-");
            md.push_str(&format!(
                "| {} | {} | {} | {} | {} | {} | {} |\n",
                host.target, p.number, p.protocol, p.state, srv, ver, verdict
            ));
        }
    }
    md.push('\n');

    if !summary.findings.is_empty() {
        md.push_str("## Security Findings & Recommended Fixes\n\n");
        for f in &summary.findings {
            let port_str = f.port.map(|p| format!(" (Port {p})")).unwrap_or_default();
            md.push_str(&format!(
                "### [{}] {}{}\n\n",
                f.severity.as_str().to_uppercase(),
                f.message,
                port_str
            ));
            md.push_str(&format!("**Impact / Why:** {}\n\n", f.why));
            if let Some(ref fix) = f.fix {
                md.push_str("**Remediation:**\n\n");
                if let Some(ref ufw) = fix.ufw {
                    md.push_str(&format!("- **UFW:** `{ufw}`\n"));
                }
                if let Some(ref ipt) = fix.iptables {
                    md.push_str(&format!("- **iptables:** `{ipt}`\n"));
                }
                if let Some(ref cfg) = fix.config {
                    md.push_str(&format!("- **Config:**\n```\n{cfg}\n```\n"));
                }
                if let Some(ref dck) = fix.docker {
                    md.push_str(&format!("- **Docker:**\n```yaml\n{dck}\n```\n"));
                }
            }
            md.push_str("\n---\n\n");
        }
    }

    Ok(md)
}

pub fn export_html(summary: &ScanSummary) -> Result<String> {
    let mut html = String::new();
    html.push_str("<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n");
    html.push_str("<meta charset=\"UTF-8\">\n<meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">\n");
    html.push_str(&format!("<title>PortLens Audit Report - {}</title>\n", summary.targets.join(", ")));
    html.push_str(r#"<style>
body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; background: #0f172a; color: #f8fafc; margin: 0; padding: 2rem; }
.container { max-width: 960px; margin: 0 auto; }
.header { border-bottom: 2px solid #334155; padding-bottom: 1rem; margin-bottom: 2rem; display: flex; justify-content: space-between; align-items: center; }
.card { background: #1e293b; border-radius: 8px; padding: 1.5rem; margin-bottom: 1.5rem; border: 1px solid #334155; }
.badge { display: inline-block; padding: 0.25rem 0.5rem; border-radius: 4px; font-weight: bold; font-size: 0.85rem; }
.badge-crit { background: #ef4444; color: #fff; }
.badge-high { background: #f97316; color: #fff; }
.badge-med { background: #eab308; color: #000; }
.badge-low { background: #06b6d4; color: #fff; }
.badge-info { background: #64748b; color: #fff; }
table { width: 100%; border-collapse: collapse; margin-top: 1rem; }
th, td { text-align: left; padding: 0.75rem; border-bottom: 1px solid #334155; }
th { background: #0f172a; color: #94a3b8; font-size: 0.85rem; text-transform: uppercase; }
pre { background: #0f172a; padding: 0.75rem; border-radius: 4px; overflow-x: auto; color: #38bdf8; }
.score-circle { font-size: 2.5rem; font-weight: bold; text-align: center; }
</style>
</head>
<body>
<div class="container">
<div class="header">
  <div>
    <h1 style="margin: 0; color: #38bdf8;">PortLens Security Exposure Report</h1>
    <p style="margin: 0.25rem 0 0 0; color: #94a3b8;">Target: <strong>"#);
    html.push_str(&summary.targets.join(", "));
    html.push_str("</strong> | Scan ID: ");
    html.push_str(&summary.scan_id);
    html.push_str(r#"</p>
  </div>
  <div class="score-circle">
    Grade "#);
    html.push_str(&summary.risk_score.grade);
    html.push_str(r#"<div style="font-size: 1rem; color: #94a3b8;">Score: "#);
    html.push_str(&summary.risk_score.score.to_string());
    html.push_str(r#"/100</div>
  </div>
</div>
<div class="card" style="font-size: 0.9rem; color: #94a3b8;">
  <strong>Scoring Methodology:</strong> "#);
    html.push_str(&summary.risk_score.formula);
    if let Some(ref trend) = summary.risk_score.trend_description {
        html.push_str(&format!("<br><strong>Historical Trend:</strong> {trend}"));
    }
    html.push_str(r#"
</div>
<div class="card">
  <h2>Host Exposure Table</h2>
  <table>
    <thead><tr><th>Port</th><th>State</th><th>Service</th><th>Version</th><th>Verdict</th></tr></thead>
    <tbody>"#);

    for host in &summary.hosts {
        for p in &host.ports {
            let srv = p.service.as_ref().map(|s| s.name.as_str()).unwrap_or("unknown");
            let ver = p.service.as_ref().and_then(|s| s.version.as_deref()).unwrap_or("-");
            let verdict = p.verdict.map(|v| v.as_str()).unwrap_or("-");
            html.push_str(&format!(
                "<tr><td>{}/{}</td><td>{}</td><td>{}</td><td>{}</td><td><strong>{}</strong></td></tr>",
                p.number, p.protocol, p.state, srv, ver, verdict
            ));
        }
    }

    html.push_str(r#"
    </tbody>
  </table>
</div>
"#);

    if !summary.findings.is_empty() {
        html.push_str("<div class=\"card\"><h2>Security Findings & Remediation</h2>");
        for f in &summary.findings {
            let badge_class = match f.severity {
                crate::model::Severity::Critical => "badge-crit",
                crate::model::Severity::High => "badge-high",
                crate::model::Severity::Medium => "badge-med",
                crate::model::Severity::Low => "badge-low",
                crate::model::Severity::Info => "badge-info",
            };
            html.push_str(&format!(
                "<div style=\"margin-bottom: 1.5rem;\"><span class=\"badge {}\">{}</span> <strong>{}</strong> (Port {})<p><em>Why:</em> {}</p>",
                badge_class, f.severity.as_str().to_uppercase(), f.message, f.port.unwrap_or(0), f.why
            ));
            if let Some(ref fix) = f.fix {
                if let Some(ref ufw) = fix.ufw {
                    html.push_str(&format!("<p><strong>UFW:</strong> <code>{}</code></p>", ufw));
                }
                if let Some(ref cfg) = fix.config {
                    html.push_str(&format!("<pre>{}</pre>", cfg));
                }
            }
            html.push_str("</div>");
        }
        html.push_str("</div>");
    }

    html.push_str("</div></body></html>");
    Ok(html)
}
