use crate::error::{PlensError, Result};
use chrono::Utc;
use rusqlite::{params, Connection};
use std::io::{stdin, stdout, Write};
use std::net::IpAddr;

pub fn is_private_ip(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_private() || v4.is_loopback() || v4.is_link_local(),
        IpAddr::V6(v6) => v6.is_loopback(),
    }
}

pub fn check_target_safety(
    target: &str,
    allowlist: &[String],
    auto_yes: bool,
    db_conn: Option<&Connection>,
) -> Result<()> {
    if target.contains(';') || target.contains('&') || target.contains('|') || target.contains('`') || target.contains('$') {
        return Err(PlensError::InvalidArgument {
            message: format!("Target contains invalid characters: '{target}'"),
        });
    }

    if !allowlist.is_empty() {
        let mut allowed = false;
        for entry in allowlist {
            if entry == target || target.starts_with(entry) {
                allowed = true;
                break;
            }
        }
        if !allowed {
            return Err(PlensError::AllowlistViolation {
                target: target.to_string(),
            });
        }
    }

    if auto_yes {
        return Ok(());
    }

    if let Some(conn) = db_conn {
        let res: std::result::Result<i32, _> = conn.query_row(
            "SELECT count(*) FROM ack_targets WHERE target = ?1",
            params![target],
            |row| row.get(0),
        );
        if let Ok(count) = res {
            if count > 0 {
                return Ok(());
            }
        }
    }

    println!("\n[!] TARGET AUTHORIZATION CHECK:");
    println!("    Target: {}", target);

    if let Ok(ip) = target.parse::<IpAddr>() {
        if !is_private_ip(&ip) {
            println!("    [WARNING]: Target is a PUBLIC IP address on the internet.");
        }
    }

    print!("    Do you own or have written permission to scan this target? [y/N]: ");
    let _ = stdout().flush();

    let mut input = String::new();
    stdin()
        .read_line(&mut input)
        .map_err(|e| PlensError::Other(e.to_string()))?;

    let trimmed = input.trim().to_lowercase();
    if trimmed == "y" || trimmed == "yes" {
        if let Some(conn) = db_conn {
            let _ = conn.execute(
                "INSERT OR REPLACE INTO ack_targets (target, acknowledged_at) VALUES (?1, ?2)",
                params![target, Utc::now().to_rfc3339()],
            );
        }
        Ok(())
    } else {
        Err(PlensError::AuthorizationDeclined {
            target: target.to_string(),
        })
    }
}

pub fn log_audit_event(
    conn: &Connection,
    action: &str,
    target: &str,
    details: &str,
) -> Result<()> {
    let _ = conn.execute(
        "CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            action TEXT NOT NULL,
            target TEXT NOT NULL,
            details TEXT NOT NULL
        )",
        [],
    );

    conn.execute(
        "INSERT INTO audit_log (timestamp, action, target, details) VALUES (?1, ?2, ?3, ?4)",
        params![Utc::now().to_rfc3339(), action, target, details],
    )
    .map_err(|e| PlensError::Database {
        message: e.to_string(),
    })?;

    Ok(())
}
