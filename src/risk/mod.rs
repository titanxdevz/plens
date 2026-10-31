use crate::error::{PlensError, Result};
use crate::model::{Finding, FixRemedy, Host, PortVerdict, Severity};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;
use uuid::Uuid;

pub const DEFAULT_RULES_YAML: &str = include_str!("../../rules/default.yaml");

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleMatch {
    pub service: Option<String>,
    pub probe: Option<String>,
    pub port: Option<u16>,
    pub special: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FixDefinition {
    pub ufw: Option<String>,
    pub iptables: Option<String>,
    pub nftables: Option<String>,
    pub config: Option<String>,
    pub docker: Option<String>,
    pub notes: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskRule {
    pub id: String,
    pub match_criteria: Option<RuleMatch>,
    #[serde(rename = "match")]
    pub match_alias: Option<RuleMatch>,
    pub severity: Severity,
    pub message: String,
    pub why: String,
    pub fix: Option<FixDefinition>,
}

impl RiskRule {
    pub fn get_match(&self) -> Option<&RuleMatch> {
        self.match_criteria.as_ref().or(self.match_alias.as_ref())
    }
}

pub struct OutdatedVersionCheck {
    pub service_prefix: &'static str,
    pub min_safe_version: &'static str,
    pub why: &'static str,
}

pub const KNOWN_OUTDATED_VERSIONS: &[OutdatedVersionCheck] = &[
    OutdatedVersionCheck {
        service_prefix: "redis",
        min_safe_version: "7.0.0",
        why: "Redis versions prior to 7.0 lack modern security hardening and have kno   wn memory vulnerabilities.",
    },
    OutdatedVersionCheck {
        service_prefix: "nginx",
        min_safe_version: "1.24.0",
        why: "Nginx releases before 1.24.0 are vulnerable to multiple HTTP/2 and HTTP/3 denial of service issues.",
    },
    OutdatedVersionCheck {
        service_prefix: "openssh",
        min_safe_version: "8.9",
        why: "Legacy OpenSSH versions contain known security flaws including regreSSHion (CVE-2024-6387).",
    },
];

pub fn load_rules(custom_path: Option<&Path>) -> Result<Vec<RiskRule>> {
    let content = if let Some(path) = custom_path {
        if path.exists() {
            fs::read_to_string(path).map_err(|e| PlensError::Config {
                message: format!("Failed to read rules file {}: {}", path.display(), e),
            })?
        } else {
            DEFAULT_RULES_YAML.to_string()
        }
    } else {
        DEFAULT_RULES_YAML.to_string()
    };

    serde_yaml::from_str::<Vec<RiskRule>>(&content).map_err(|e| PlensError::Config {
        message: format!("Failed to parse rules YAML: {e}"),
    })
}

pub fn evaluate_findings(host: &Host, rules: &[RiskRule]) -> Vec<Finding> {
    let mut findings = Vec::new();

    for port in &host.ports {
        let is_open = port.state == crate::model::PortState::Open;
        if !is_open {
            continue;
        }

        let is_loopback = port
            .bind_addr
            .as_deref()
            .map(|b| b == "127.0.0.1" || b == "::1" || b == "localhost")
            .unwrap_or(false);

        if is_loopback || port.verdict == Some(PortVerdict::LocalOnly) {
            continue;
        }

        let srv_name = port
            .service
            .as_ref()
            .map(|s| s.name.to_lowercase())
            .unwrap_or_default();

        let probe_status = port
            .probe_result
            .as_ref()
            .map(|pr| pr.status.to_lowercase())
            .unwrap_or_default();

        let probe_service = port
            .probe_result
            .as_ref()
            .map(|pr| pr.service.to_lowercase())
            .unwrap_or_default();

        for rule in rules {
            if let Some(m) = rule.get_match() {
                let mut matches = true;

                if let Some(ref s) = m.service {
                    let s_low = s.to_lowercase();
                    if srv_name != s_low && probe_service != s_low {
                        matches = false;
                    }
                }

                if let Some(ref pr) = m.probe {
                    let pr_low = pr.to_lowercase();
                    if probe_status != pr_low {
                        matches = false;
                    }
                }

                if let Some(p) = m.port {
                    if port.number != p {
                        matches = false;
                    }
                }

                if matches {
                    let fix_remedy = rule.fix.as_ref().map(|f| FixRemedy {
                        ufw: f.ufw.clone().map(|s| s.replace("<port>", &port.number.to_string())),
                        iptables: f.iptables.clone().map(|s| s.replace("<port>", &port.number.to_string())),
                        nftables: f.nftables.clone().map(|s| s.replace("<port>", &port.number.to_string())),
                        config: f.config.clone(),
                        docker: f.docker.clone(),
                        notes: f.notes.clone(),
                    });

                    let adjusted_severity = if port.verdict == Some(PortVerdict::Filtered) && rule.severity > Severity::Low {
                        match rule.severity {
                            Severity::Critical => Severity::High,
                            Severity::High => Severity::Medium,
                            Severity::Medium => Severity::Low,
                            other => other,
                        }
                    } else {
                        rule.severity
                    };

                    findings.push(Finding {
                        id: Uuid::new_v4().to_string(),
                        rule_id: rule.id.clone(),
                        target: host.target.clone(),
                        port: Some(port.number),
                        severity: adjusted_severity,
                        message: rule.message.clone(),
                        why: rule.why.clone(),
                        fix: fix_remedy,
                        suppressed: false,
                        suppress_reason: None,
                        suppress_until: None,
                    });
                }
            }
        }

        if let Some(ref srv) = port.service {
            if let Some(ref ver) = srv.version {
                for check in KNOWN_OUTDATED_VERSIONS {
                    if srv.name.to_lowercase().starts_with(check.service_prefix) && is_older_version(ver, check.min_safe_version) {
                        findings.push(Finding {
                            id: Uuid::new_v4().to_string(),
                            rule_id: format!("{}-outdated-version", check.service_prefix),
                            target: host.target.clone(),
                            port: Some(port.number),
                            severity: Severity::Medium,
                            message: format!(
                                "Detected outdated {} version {} (recommended minimum: {})",
                                srv.name, ver, check.min_safe_version
                            ),
                            why: check.why.to_string(),
                            fix: Some(FixRemedy {
                                ufw: None,
                                iptables: None,
                                nftables: None,
                                config: Some(format!("Upgrade {} to latest supported release via package manager", srv.name)),
                                docker: None,
                                notes: None,
                            }),
                            suppressed: false,
                            suppress_reason: None,
                            suppress_until: None,
                        });
                    }
                }
            }
        }
    }

    findings
}

fn is_older_version(current: &str, safe_min: &str) -> bool {
    let curr_parts: Vec<u32> = current
        .split('.')
        .filter_map(|s| s.chars().take_while(|c| c.is_ascii_digit()).collect::<String>().parse::<u32>().ok())
        .collect();
    let min_parts: Vec<u32> = safe_min
        .split('.')
        .filter_map(|s| s.parse::<u32>().ok())
        .collect();

    let max_len = curr_parts.len().max(min_parts.len());
    for i in 0..max_len {
        let c = curr_parts.get(i).copied().unwrap_or(0);
        let m = min_parts.get(i).copied().unwrap_or(0);
        if c < m {
            return true;
        }
        if c > m {
            return false;
        }
    }
    false
}
