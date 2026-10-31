use crate::model::Finding;
use std::collections::{BTreeMap, HashSet};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FirewallEnv {
    Ufw,
    Iptables,
    Nftables,
    Firewalld,
    Generic,
}

pub fn detect_firewall_env() -> FirewallEnv {
    if std::process::Command::new("ufw")
        .arg("status")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
    {
        return FirewallEnv::Ufw;
    }
    if std::process::Command::new("firewall-cmd")
        .arg("--state")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
    {
        return FirewallEnv::Firewalld;
    }
    if std::process::Command::new("nft")
        .arg("list")
        .arg("ruleset")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
    {
        return FirewallEnv::Nftables;
    }
    if std::process::Command::new("iptables")
        .arg("-L")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
    {
        return FirewallEnv::Iptables;
    }
    FirewallEnv::Generic
}

pub fn generate_grouped_fixes(findings: &[Finding]) -> String {
    let mut out = String::new();
    out.push_str("=======================================================\n");
    out.push_str(" PORTLENS RECOMMENDED HARDENING & REMEDIATION COMMANDS\n");
    out.push_str("=======================================================\n");
    out.push_str("Review and execute the commands below on your target host:\n\n");

    let fw = detect_firewall_env();

    let mut ufw_rules = HashSet::new();
    let mut ipt_rules = HashSet::new();
    let mut config_snippets = BTreeMap::new();
    let mut docker_notes = Vec::new();

    for f in findings {
        if f.suppressed {
            continue;
        }
        if let Some(ref fix) = f.fix {
            if let Some(ref u) = fix.ufw {
                ufw_rules.insert(u.clone());
            }
            if let Some(ref i) = fix.iptables {
                ipt_rules.insert(i.clone());
            }
            if let Some(ref c) = fix.config {
                let service = f
                    .port
                    .map(|p| format!("Service on port {p} ({})", f.rule_id))
                    .unwrap_or_else(|| f.rule_id.clone());
                config_snippets.insert(service, c.clone());
            }
            if let Some(ref d) = fix.docker {
                docker_notes.push((f.port, d.clone()));
            }
        }
    }

    if !ufw_rules.is_empty() && (fw == FirewallEnv::Ufw || fw == FirewallEnv::Generic) {
        out.push_str("--- [1] UFW Firewall Rules ---\n");
        for rule in &ufw_rules {
            out.push_str(&format!("sudo {rule}\n"));
        }
        out.push_str("sudo ufw reload\n\n");
    }

    if !ipt_rules.is_empty() && (fw == FirewallEnv::Iptables || fw == FirewallEnv::Generic) {
        out.push_str("--- [2] iptables Firewall Rules ---\n");
        for rule in &ipt_rules {
            out.push_str(&format!("sudo {rule}\n"));
        }
        out.push('\n');
    }

    if !config_snippets.is_empty() {
        out.push_str("--- [3] Service Configuration Hardening ---\n");
        for (svc, snippet) in config_snippets {
            out.push_str(&format!("# {}\n", svc));
            out.push_str(&snippet);
            out.push_str("\n\n");
        }
    }

    if !docker_notes.is_empty() {
        out.push_str("--- [4] Docker Port Bindings (Caution: Docker bypasses UFW by default) ---\n");
        out.push_str("# In docker-compose.yml or container run args, bind strictly to 127.0.0.1:\n");
        for (port, dck) in docker_notes {
            if let Some(p) = port {
                out.push_str(&format!("# Port {p}:\n"));
            }
            out.push_str(&dck);
            out.push_str("\n\n");
        }
    }

    out
}
