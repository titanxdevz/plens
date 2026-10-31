use crate::model::{Host, PortVerdict, RiskScore, ScanSummary, Severity};
use comfy_table::modifiers::UTF8_ROUND_CORNERS;
use comfy_table::presets::UTF8_FULL;
use comfy_table::{Cell, Color, Row, Table};

pub fn get_terminal_width() -> u16 {
    if let Ok((cols, _)) = crossterm::terminal::size() {
        cols
    } else {
        100
    }
}

pub fn render_host_table(host: &Host, no_color: bool) -> String {
    let width = get_terminal_width();
    let is_narrow = width < 75;

    if is_narrow {
        let mut out = String::new();
        out.push_str(&format!("Target: {}\n", host.target));
        out.push_str(&format!("{:-<40}\n", ""));
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
                .unwrap_or("");
            let verdict_str = p.verdict.map(|v| v.as_str()).unwrap_or("");
            out.push_str(&format!(
                "{}/{} {:<7} {:<10} {:<10} {}\n",
                p.number, p.protocol, p.state, srv, ver, verdict_str
            ));
        }
        return out;
    }

    let mut table = Table::new();
    table
        .load_preset(UTF8_FULL)
        .apply_modifier(UTF8_ROUND_CORNERS)
        .set_header(vec!["PORT", "STATE", "SERVICE", "VERSION", "VERDICT"]);

    for p in &host.ports {
        let port_str = format!("{}/{}", p.number, p.protocol);
        let state_str = p.state.to_string();
        let service_name = p
            .service
            .as_ref()
            .map(|s| s.name.clone())
            .unwrap_or_else(|| "unknown".into());
        let version_str = p
            .service
            .as_ref()
            .and_then(|s| {
                if let (Some(prod), Some(v)) = (&s.product, &s.version) {
                    Some(format!("{prod} {v}"))
                } else {
                    s.version.clone().or_else(|| s.product.clone())
                }
            })
            .unwrap_or_default();

        let verdict_str = p
            .verdict
            .map(|v| v.as_str().to_string())
            .unwrap_or_else(|| {
                if p.state == crate::model::PortState::Open {
                    "OPEN".into()
                } else {
                    "-".into()
                }
            });

        let verdict_cell = if no_color {
            Cell::new(&verdict_str)
        } else if let Some(v) = p.verdict {
            match v {
                PortVerdict::Exposed => Cell::new(&verdict_str).fg(Color::Red),
                PortVerdict::Filtered => Cell::new(&verdict_str).fg(Color::Yellow),
                PortVerdict::LocalOnly => Cell::new(&verdict_str).fg(Color::Green),
                PortVerdict::Ghost => Cell::new(&verdict_str).fg(Color::Magenta),
            }
        } else {
            Cell::new(&verdict_str)
        };

        let row = Row::from(vec![
            Cell::new(port_str),
            Cell::new(&state_str),
            Cell::new(service_name),
            Cell::new(version_str),
            verdict_cell,
        ]);

        table.add_row(row);
    }

    table.to_string()
}

pub fn render_summary_card(summary: &ScanSummary, no_color: bool) -> String {
    let mut out = String::new();
    out.push_str("\n=======================================================\n");
    out.push_str(&format!(
        " PORTLENS EXPOSURE AUDIT SUMMARY (Scan ID: {})\n",
        &summary.scan_id[..8]
    ));
    out.push_str("=======================================================\n");
    out.push_str(&format!(
        "Targets:          {}\n",
        summary.targets.join(", ")
    ));
    out.push_str(&format!(
        "Duration:         {:.2}s\n",
        summary.duration_ms as f64 / 1000.0
    ));
    out.push_str(&format!("Preset:           {}\n", summary.preset));
    if let Some(ref prof) = summary.profile {
        out.push_str(&format!("Profile:          {}\n", prof));
    }

    let RiskScore {
        score,
        ref grade,
        ref trend_description,
        ..
    } = &summary.risk_score;

    let grade_colored = if no_color {
        format!("{grade} (Score: {score}/100)")
    } else {
        match grade.as_str() {
            "A" => format!("\x1b[32m{grade} (Score: {score}/100 - LOW EXPOSURE)\x1b[0m"),
            "B" => format!("\x1b[32m{grade} (Score: {score}/100 - MODERATE)\x1b[0m"),
            "C" => format!("\x1b[33m{grade} (Score: {score}/100 - CONCERNING)\x1b[0m"),
            "D" => format!("\x1b[31m{grade} (Score: {score}/100 - HIGH RISK)\x1b[0m"),
            _ => format!("\x1b[35;1m{grade} (Score: {score}/100 - CRITICAL RISK)\x1b[0m"),
        }
    };

    out.push_str(&format!("Risk Posture:     {}\n", grade_colored));
    if let Some(ref trend) = trend_description {
        out.push_str(&format!("Trend:            {}\n", trend));
    }
    out.push_str("-------------------------------------------------------\n\n");

    for host in &summary.hosts {
        out.push_str(&render_host_table(host, no_color));
        out.push('\n');
    }

    if !summary.findings.is_empty() {
        out.push_str("=======================================================\n");
        out.push_str(" SECURITY FINDINGS & REMEDIATION\n");
        out.push_str("=======================================================\n");

        let mut sorted_findings = summary.findings.clone();
        sorted_findings.sort_by_key(|b| std::cmp::Reverse(b.severity));

        for f in &sorted_findings {
            let sev_badge = format_severity_badge(f.severity, no_color);
            let port_str = f
                .port
                .map(|p| format!(" on port {p}"))
                .unwrap_or_default();
            out.push_str(&format!("{} {}{}\n", sev_badge, f.message, port_str));
            out.push_str(&format!("  [Why]: {}\n", f.why));
            if let Some(ref fix) = f.fix {
                if let Some(ref ufw) = fix.ufw {
                    out.push_str(&format!("  [UFW]:        {ufw}\n"));
                }
                if let Some(ref ipt) = fix.iptables {
                    out.push_str(&format!("  [iptables]:   {ipt}\n"));
                }
                if let Some(ref cfg) = fix.config {
                    out.push_str(&format!("  [Config]:     {}\n", cfg.replace('\n', "\n                ")));
                }
                if let Some(ref dck) = fix.docker {
                    out.push_str(&format!("  [Docker]:     {}\n", dck.replace('\n', "\n                ")));
                }
            }
            out.push('\n');
        }
    } else {
        out.push_str("✓ No high or critical security exposure findings detected.\n\n");
    }

    out.push_str("Next steps:\n");
    out.push_str(&format!("  • Save as baseline:       plens baseline set {}\n", summary.targets.first().cloned().unwrap_or_default()));
    out.push_str(&format!("  • Export report:          plens export {} --format html -o report.html\n", summary.scan_id));
    out.push_str(&format!("  • Continuous watch:       plens watch {}\n\n", summary.targets.first().cloned().unwrap_or_default()));

    out
}

pub fn format_severity_badge(sev: Severity, no_color: bool) -> String {
    if no_color {
        format!("[{}]", sev.as_str().to_uppercase())
    } else {
        match sev {
            Severity::Critical => "\x1b[41;1;37m CRITICAL \x1b[0m".to_string(),
            Severity::High => "\x1b[31;1m HIGH \x1b[0m".to_string(),
            Severity::Medium => "\x1b[33m MEDIUM \x1b[0m".to_string(),
            Severity::Low => "\x1b[36m LOW \x1b[0m".to_string(),
            Severity::Info => "\x1b[37m INFO \x1b[0m".to_string(),
        }
    }
}
