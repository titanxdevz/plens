use crate::error::{PlensError, Result};
use crate::model::{Finding, FixRemedy, Host, PortState, PortVerdict, Severity};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fs;
use std::path::Path;
use uuid::Uuid;

pub const PTERODACTYL_PANEL_TOML: &str = include_str!("../../profiles/pterodactyl-panel.toml");
pub const PTERODACTYL_NODE_TOML: &str = include_str!("../../profiles/pterodactyl-node.toml");
pub const WEB_SERVER_TOML: &str = include_str!("../../profiles/web-server.toml");
pub const DATABASE_SERVER_TOML: &str = include_str!("../../profiles/database-server.toml");
pub const MINIMAL_TOML: &str = include_str!("../../profiles/minimal.toml");

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostingProfile {
    pub name: String,
    pub description: String,
    #[serde(default)]
    pub expected_ports: Vec<u16>,
    #[serde(default)]
    pub allowed_port_ranges: Vec<String>,
    #[serde(default)]
    pub allowed_source_ranges: Vec<String>,
    #[serde(default)]
    pub local_only_services: Vec<String>,
}

impl HostingProfile {
    pub fn is_port_allowed(&self, port: u16) -> bool {
        if self.expected_ports.contains(&port) {
            return true;
        }

        for range in &self.allowed_port_ranges {
            if let Some((start_s, end_s)) = range.split_once('-') {
                if let (Ok(start), Ok(end)) = (start_s.trim().parse::<u16>(), end_s.trim().parse::<u16>()) {
                    if port >= start && port <= end {
                        return true;
                    }
                }
            } else if let Ok(p) = range.trim().parse::<u16>() {
                if p == port {
                    return true;
                }
            }
        }

        false
    }
}

pub fn load_profile(name: &str, custom_dir: Option<&Path>) -> Result<HostingProfile> {
    let lower_name = name.to_lowercase();

    if let Some(dir) = custom_dir {
        let custom_file = dir.join(format!("{lower_name}.toml"));
        if custom_file.exists() {
            let content = fs::read_to_string(&custom_file).map_err(|e| PlensError::Config {
                message: format!("Failed to read custom profile {}: {e}", custom_file.display()),
            })?;
            return toml::from_str(&content).map_err(|e| PlensError::Config {
                message: format!("Failed to parse profile {}: {e}", custom_file.display()),
            });
        }
    }

    let toml_str = match lower_name.as_str() {
        "pterodactyl-panel" => PTERODACTYL_PANEL_TOML,
        "pterodactyl-node" => PTERODACTYL_NODE_TOML,
        "web-server" | "web" => WEB_SERVER_TOML,
        "database-server" | "db" => DATABASE_SERVER_TOML,
        "minimal" => MINIMAL_TOML,
        other => {
            return Err(PlensError::ProfileNotFound {
                name: other.to_string(),
            });
        }
    };

    toml::from_str(toml_str).map_err(|e| PlensError::Config {
        message: format!("Failed to parse built-in profile: {e}"),
    })
}

pub fn evaluate_profile_compliance(
    host: &Host,
    profile: &HostingProfile,
) -> Vec<Finding> {
    let mut findings = Vec::new();
    let mut found_ports = HashSet::new();

    for p in &host.ports {
        if p.state == PortState::Open {
            found_ports.insert(p.number);

            let is_loopback = p.bind_addr.as_deref().map(|b| b == "127.0.0.1" || b == "::1").unwrap_or(false);
            if !is_loopback && p.verdict != Some(PortVerdict::LocalOnly) {
                if !profile.is_port_allowed(p.number) {
                    findings.push(Finding {
                        id: Uuid::new_v4().to_string(),
                        rule_id: "unexpected-port".into(),
                        target: host.target.clone(),
                        port: Some(p.number),
                        severity: Severity::Medium,
                        message: format!(
                            "Port {} is exposed but not allowed in '{}' profile",
                            p.number, profile.name
                        ),
                        why: format!("Profile '{}' only expects ports {:?} and ranges {:?}.", profile.name, profile.expected_ports, profile.allowed_port_ranges),
                        fix: Some(FixRemedy {
                            ufw: Some(format!("ufw deny {}", p.number)),
                            iptables: Some(format!("iptables -A INPUT -p tcp --dport {} -j DROP", p.number)),
                            nftables: None,
                            config: None,
                            docker: None,
                            notes: Some(format!("If this service is required, add {} to the profile allowed ports.", p.number)),
                        }),
                        suppressed: false,
                        suppress_reason: None,
                        suppress_until: None,
                    });
                }

                if let Some(ref srv) = p.service {
                    let srv_lower = srv.name.to_lowercase();
                    for local_svc in &profile.local_only_services {
                        if srv_lower.contains(&local_svc.to_lowercase()) {
                            findings.push(Finding {
                                id: Uuid::new_v4().to_string(),
                                rule_id: format!("{}-must-be-local", local_svc),
                                target: host.target.clone(),
                                port: Some(p.number),
                                severity: Severity::High,
                                message: format!(
                                    "Service '{}' on port {} violates profile: must be strictly local-only",
                                    srv.name, p.number
                                ),
                                why: format!("The '{}' profile requires {} database/daemon to be bound only to 127.0.0.1.", profile.name, local_svc),
                                fix: Some(FixRemedy {
                                    ufw: Some(format!("ufw deny {}", p.number)),
                                    iptables: Some(format!("iptables -A INPUT -p tcp --dport {} ! -s 127.0.0.1 -j DROP", p.number)),
                                    nftables: None,
                                    config: Some("bind 127.0.0.1 ::1".into()),
                                    docker: Some(format!("ports:\n  - '127.0.0.1:{}:{}'", p.number, p.number)),
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
    }

    for exp in &profile.expected_ports {
        if !found_ports.contains(exp) {
            findings.push(Finding {
                id: Uuid::new_v4().to_string(),
                rule_id: "missing-expected".into(),
                target: host.target.clone(),
                port: Some(*exp),
                severity: Severity::Info,
                message: format!(
                    "Expected service port {exp} in '{}' profile is not responding",
                    profile.name
                ),
                why: "Service might be down, failed to start, or blocked by local firewall.".into(),
                fix: Some(FixRemedy {
                    ufw: None,
                    iptables: None,
                    nftables: None,
                    config: Some(format!("systemctl status <service-on-port-{exp}>")),
                    docker: None,
                    notes: None,
                }),
                suppressed: false,
                suppress_reason: None,
                suppress_until: None,
            });
        }
    }

    findings
}
