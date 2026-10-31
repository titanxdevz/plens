use crate::model::{Port, ScanSummary};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DriftReport {
    pub target: String,
    pub new_open: Vec<Port>,
    pub newly_closed: Vec<Port>,
    pub service_changed: Vec<(u16, String, String)>,
    pub verdict_changed: Vec<(u16, String, String)>,
    pub score_delta: i32,
    pub score_a: u32,
    pub score_b: u32,
    pub grade_a: String,
    pub grade_b: String,
    pub first_seen_note: Option<String>,
}

impl DriftReport {
    pub fn has_drift(&self) -> bool {
        !self.new_open.is_empty()
            || !self.newly_closed.is_empty()
            || !self.service_changed.is_empty()
            || !self.verdict_changed.is_empty()
    }
}

pub fn diff_scans(scan_a: &ScanSummary, scan_b: &ScanSummary) -> DriftReport {
    let target = scan_b
        .targets
        .first()
        .cloned()
        .unwrap_or_else(|| "unknown".into());

    let mut ports_a: HashMap<u16, &Port> = HashMap::new();
    for h in &scan_a.hosts {
        for p in &h.ports {
            ports_a.insert(p.number, p);
        }
    }

    let mut ports_b: HashMap<u16, &Port> = HashMap::new();
    for h in &scan_b.hosts {
        for p in &h.ports {
            ports_b.insert(p.number, p);
        }
    }

    let mut new_open = Vec::new();
    let mut newly_closed = Vec::new();
    let mut service_changed = Vec::new();
    let mut verdict_changed = Vec::new();

    for (port_num, port_b) in &ports_b {
        match ports_a.get(port_num) {
            Some(port_a) => {
                if port_a.state != crate::model::PortState::Open && port_b.state == crate::model::PortState::Open && port_b.confirmed {
                    new_open.push((*port_b).clone());
                } else if port_a.state == crate::model::PortState::Open && port_b.state != crate::model::PortState::Open {
                    newly_closed.push((*port_a).clone());
                }

                let srv_a = port_a.service.as_ref().map(|s| {
                    if let Some(ref v) = s.version {
                        format!("{} {}", s.name, v)
                    } else {
                        s.name.clone()
                    }
                }).unwrap_or_else(|| "unknown".into());

                let srv_b = port_b.service.as_ref().map(|s| {
                    if let Some(ref v) = s.version {
                        format!("{} {}", s.name, v)
                    } else {
                        s.name.clone()
                    }
                }).unwrap_or_else(|| "unknown".into());

                if srv_a != srv_b && !srv_a.is_empty() && !srv_b.is_empty() {
                    service_changed.push((*port_num, srv_a, srv_b));
                }

                let v_a = port_a.verdict.map(|v| v.to_string()).unwrap_or_default();
                let v_b = port_b.verdict.map(|v| v.to_string()).unwrap_or_default();
                if v_a != v_b && !v_a.is_empty() && !v_b.is_empty() {
                    verdict_changed.push((*port_num, v_a, v_b));
                }
            }
            None => {
                if port_b.state == crate::model::PortState::Open && port_b.confirmed {
                    new_open.push((*port_b).clone());
                }
            }
        }
    }

    for (port_num, port_a) in &ports_a {
        if !ports_b.contains_key(port_num) && port_a.state == crate::model::PortState::Open {
            newly_closed.push((*port_a).clone());
        }
    }

    let score_a = scan_a.risk_score.score;
    let score_b = scan_b.risk_score.score;
    let score_delta = score_b as i32 - score_a as i32;

    DriftReport {
        target,
        new_open,
        newly_closed,
        service_changed,
        verdict_changed,
        score_delta,
        score_a,
        score_b,
        grade_a: scan_a.risk_score.grade.clone(),
        grade_b: scan_b.risk_score.grade.clone(),
        first_seen_note: Some(format!("Comparison between Scan #{} and #{}", &scan_a.scan_id[..8.min(scan_a.scan_id.len())], &scan_b.scan_id[..8.min(scan_b_id_len(&scan_b.scan_id))])),
    }
}

fn scan_b_id_len(id: &str) -> usize {
    id.len()
}

pub fn render_diff_card(diff: &DriftReport, scan_a_id: &str, scan_b_id: &str, no_color: bool) -> String {
    let mut out = String::new();
    out.push_str("=======================================================\n");
    out.push_str(&format!(
        " PORTLENS DRIFT & EXPOSURE DIFF ({} -> {})\n",
        &scan_a_id[..8.min(scan_a_id.len())],
        &scan_b_id[..8.min(scan_b_id.len())]
    ));
    out.push_str("=======================================================\n");
    out.push_str(&format!("Target: {}\n", diff.target));

    let score_change = if diff.score_delta > 0 {
        if no_color {
            format!("{}/100 ({}) -> {}/100 ({}) [+{} DEGRADED]", diff.score_a, diff.grade_a, diff.score_b, diff.grade_b, diff.score_delta)
        } else {
            format!("{}/100 ({}) -> {}/100 ({}) \x1b[31;1m[+{} DEGRADED]\x1b[0m", diff.score_a, diff.grade_a, diff.score_b, diff.grade_b, diff.score_delta)
        }
    } else if diff.score_delta < 0 {
        if no_color {
            format!("{}/100 ({}) -> {}/100 ({}) [{} IMPROVED]", diff.score_a, diff.grade_a, diff.score_b, diff.grade_b, diff.score_delta)
        } else {
            format!("{}/100 ({}) -> {}/100 ({}) \x1b[32;1m[{} IMPROVED]\x1b[0m", diff.score_a, diff.grade_a, diff.score_b, diff.grade_b, diff.score_delta)
        }
    } else {
        format!("{}/100 ({}) [UNCHANGED]", diff.score_b, diff.grade_b)
    };

    out.push_str(&format!("Risk Score Delta: {}\n\n", score_change));

    if !diff.has_drift() {
        out.push_str("✓ No exposure drift detected between scans. State is stable.\n\n");
        return out;
    }

    if !diff.new_open.is_empty() {
        let header = if no_color {
            "[+] NEW OPEN PORTS (Attack Surface Increased):\n"
        } else {
            "\x1b[31;1m[+] NEW OPEN PORTS (Attack Surface Increased):\x1b[0m\n"
        };
        out.push_str(header);
        for p in &diff.new_open {
            let srv = p.service.as_ref().map(|s| s.name.as_str()).unwrap_or("unknown");
            let v = p.verdict.map(|v| v.to_string()).unwrap_or_else(|| "EXPOSED".into());
            let line = format!("  + Port {}/{} ({}): {}\n", p.number, p.protocol, srv, v);
            if no_color {
                out.push_str(&line);
            } else {
                out.push_str(&format!("\x1b[31m{line}\x1b[0m"));
            }
        }
        out.push('\n');
    }

    if !diff.newly_closed.is_empty() {
        let header = if no_color {
            "[-] NEWLY CLOSED PORTS:\n"
        } else {
            "\x1b[32;1m[-] NEWLY CLOSED PORTS:\x1b[0m\n"
        };
        out.push_str(header);
        for p in &diff.newly_closed {
            let srv = p.service.as_ref().map(|s| s.name.as_str()).unwrap_or("unknown");
            let line = format!("  - Port {}/{} ({})\n", p.number, p.protocol, srv);
            if no_color {
                out.push_str(&line);
            } else {
                out.push_str(&format!("\x1b[32m{line}\x1b[0m"));
            }
        }
        out.push('\n');
    }

    if !diff.verdict_changed.is_empty() {
        let header = if no_color {
            "[~] VERDICT / VISIBILITY CHANGES:\n"
        } else {
            "\x1b[33;1m[~] VERDICT / VISIBILITY CHANGES:\x1b[0m\n"
        };
        out.push_str(header);
        for (port, old_v, new_v) in &diff.verdict_changed {
            out.push_str(&format!("  * Port {port}: {old_v} -> {new_v}\n"));
        }
        out.push('\n');
    }

    if !diff.service_changed.is_empty() {
        out.push_str("[*] SERVICE / VERSION CHANGES:\n");
        for (port, old_s, new_s) in &diff.service_changed {
            out.push_str(&format!("  * Port {port}: {old_s} -> {new_s}\n"));
        }
        out.push('\n');
    }

    out
}
