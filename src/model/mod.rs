use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info = 0,
    Low = 1,
    Medium = 2,
    High = 3,
    Critical = 4,
}

impl Severity {
    pub fn as_str(&self) -> &'static str {
        match self {
            Severity::Info => "info",
            Severity::Low => "low",
            Severity::Medium => "medium",
            Severity::High => "high",
            Severity::Critical => "critical",
        }
    }
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str().to_uppercase())
    }
}

impl std::str::FromStr for Severity {
    type Err = String;
    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "info" => Ok(Severity::Info),
            "low" => Ok(Severity::Low),
            "med" | "medium" => Ok(Severity::Medium),
            "high" => Ok(Severity::High),
            "crit" | "critical" => Ok(Severity::Critical),
            other => Err(format!("Unknown severity level: {other}")),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PortVerdict {
    Exposed,
    Filtered,
    LocalOnly,
    Ghost,
}

impl PortVerdict {
    pub fn as_str(&self) -> &'static str {
        match self {
            PortVerdict::Exposed => "EXPOSED",
            PortVerdict::Filtered => "FILTERED",
            PortVerdict::LocalOnly => "LOCAL_ONLY",
            PortVerdict::Ghost => "GHOST",
        }
    }

    pub fn explanation(&self) -> &'static str {
        match self {
            PortVerdict::Exposed => "Bound to 0.0.0.0/:: and directly reachable from outside",
            PortVerdict::Filtered => "Bound to 0.0.0.0/:: but blocked by firewall or network filter",
            PortVerdict::LocalOnly => "Bound safely to loopback address (127.0.0.1 / ::1)",
            PortVerdict::Ghost => "Reachable externally but no local listener found (NAT, port forwarding, or docker-proxy)",
        }
    }
}

impl fmt::Display for PortVerdict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    Tcp,
    Udp,
}

impl fmt::Display for Protocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Protocol::Tcp => write!(f, "tcp"),
            Protocol::Udp => write!(f, "udp"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PortState {
    Open,
    Closed,
    Filtered,
}

impl fmt::Display for PortState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PortState::Open => write!(f, "open"),
            PortState::Closed => write!(f, "closed"),
            PortState::Filtered => write!(f, "filtered"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Service {
    pub name: String,
    pub product: Option<String>,
    pub version: Option<String>,
    pub extra_info: Option<String>,
    pub cpe: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProbeResult {
    pub service: String,
    pub verified_insecure: bool,
    pub status: String,
    pub details: String,
    pub banner: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ListeningSocket {
    pub protocol: Protocol,
    pub bind_addr: String,
    pub port: u16,
    pub pid: Option<u32>,
    pub process_name: Option<String>,
    pub inode: Option<u64>,
    pub is_docker: bool,
}

fn default_confirmed() -> bool {
    true
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Port {
    pub number: u16,
    pub protocol: Protocol,
    pub state: PortState,
    pub service: Option<Service>,
    pub probe_result: Option<ProbeResult>,
    pub bind_addr: Option<String>,
    pub process_name: Option<String>,
    pub pid: Option<u32>,
    pub verdict: Option<PortVerdict>,
    #[serde(default = "default_confirmed")]
    pub confirmed: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Host {
    pub id: String,
    pub target: String,
    pub ip: Option<String>,
    pub hostname: Option<String>,
    pub ports: Vec<Port>,
    pub listening_sockets: Vec<ListeningSocket>,
    pub is_up: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FixRemedy {
    pub ufw: Option<String>,
    pub iptables: Option<String>,
    pub nftables: Option<String>,
    pub config: Option<String>,
    pub docker: Option<String>,
    pub notes: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Finding {
    pub id: String,
    pub rule_id: String,
    pub target: String,
    pub port: Option<u16>,
    pub severity: Severity,
    pub message: String,
    pub why: String,
    pub fix: Option<FixRemedy>,
    pub suppressed: bool,
    pub suppress_reason: Option<String>,
    pub suppress_until: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RiskScore {
    pub score: u32,
    pub grade: String,
    pub formula: String,
    pub previous_score: Option<u32>,
    pub trend_description: Option<String>,
}

impl RiskScore {
    pub fn compute(findings: &[Finding], previous_score: Option<u32>) -> Self {
        let active_findings: Vec<&Finding> = findings.iter().filter(|f| !f.suppressed).collect();
        if active_findings.is_empty() {
            let grade = "A".to_string();
            let trend_description = previous_score.map(|prev| {
                if prev == 0 {
                    "0 → 0 unchanged".to_string()
                } else {
                    format!("{prev} → 0 improved")
                }
            });
            return Self {
                score: 0,
                grade,
                formula: "Weighted severity with diminishing returns: Sum(w_i * 0.75^(n_i-1)) capped at 100".to_string(),
                previous_score,
                trend_description,
            };
        }

        // Weighted sum with diminishing returns per severity tier
        // Critical: 40, High: 25, Medium: 12, Low: 4, Info: 1
        let mut counts: BTreeMap<Severity, u32> = BTreeMap::new();
        for f in active_findings {
            *counts.entry(f.severity).or_insert(0) += 1;
        }

        let mut total_points = 0.0f64;
        for (sev, count) in counts {
            let base_weight = match sev {
                Severity::Critical => 40.0,
                Severity::High => 25.0,
                Severity::Medium => 12.0,
                Severity::Low => 4.0,
                Severity::Info => 1.0,
            };

            for i in 0..count {
                total_points += base_weight * (0.75f64).powi(i as i32);
            }
        }

        let score = (total_points.round() as u32).min(100);
        let grade = match score {
            0..=15 => "A",
            16..=35 => "B",
            36..=60 => "C",
            61..=80 => "D",
            _ => "F",
        }
        .to_string();

        let trend_description = previous_score.map(|prev| {
            if prev > score {
                format!("{prev} → {score} improved")
            } else if prev < score {
                format!("{prev} → {score} degraded")
            } else {
                format!("{score} unchanged")
            }
        });

        Self {
            score,
            grade,
            formula: "Weighted severity with diminishing returns: Sum(w_i * 0.75^(n_i-1)) capped at 100".to_string(),
            previous_score,
            trend_description,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ScanSummary {
    pub scan_id: String,
    pub targets: Vec<String>,
    pub start_time: DateTime<Utc>,
    pub end_time: DateTime<Utc>,
    pub duration_ms: u64,
    pub preset: String,
    pub profile: Option<String>,
    pub hosts: Vec<Host>,
    pub findings: Vec<Finding>,
    pub risk_score: RiskScore,
    pub partial: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ScanPlan {
    pub target: String,
    pub preset: String,
    pub profile: Option<String>,
    pub phase1_ports: String,
    pub phase1_concurrency: usize,
    pub phase1_timeout_ms: u64,
    pub phase2_enabled: bool,
    pub phase2_command: Option<String>,
    pub probes_enabled: bool,
}
