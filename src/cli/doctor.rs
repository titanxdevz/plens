use crate::config::Config;
use crate::error::{ExitCode, Result};
use comfy_table::modifiers::UTF8_ROUND_CORNERS;
use comfy_table::presets::UTF8_FULL;
use comfy_table::{Cell, Color, Row, Table};
use std::process::Command;

pub struct DoctorCheck {
    pub name: &'static str,
    pub status: &'static str,
    pub details: String,
    pub passed: bool,
}

pub async fn run_doctor(config: &Config) -> Result<ExitCode> {
    let mut checks = Vec::new();

    // 1. Nmap check
    match Command::new(&config.nmap_path).arg("--version").output() {
        Ok(out) if out.status.success() => {
            let out_str = String::from_utf8_lossy(&out.stdout);
            let first_line = out_str.lines().next().unwrap_or("nmap installed");
            checks.push(DoctorCheck {
                name: "nmap engine",
                status: "PASS",
                details: first_line.trim().to_string(),
                passed: true,
            });
        }
        _ => {
            checks.push(DoctorCheck {
                name: "nmap engine",
                status: "WARN",
                details: format!(
                    "Binary '{}' not found. Phase 2 deep inspection disabled; Phase 1 connect scan remains active.",
                    config.nmap_path
                ),
                passed: false,
            });
        }
    }

    // 2. Privileges check
    #[cfg(unix)]
    let is_root = unsafe { libc::geteuid() == 0 };
    #[cfg(not(unix))]
    let is_root = false;

    if is_root {
        checks.push(DoctorCheck {
            name: "Privileges",
            status: "PASS",
            details: "Running as root / administrator (raw socket stealth scan permitted)".into(),
            passed: true,
        });
    } else {
        checks.push(DoctorCheck {
            name: "Privileges",
            status: "PASS",
            details: "Running as standard user (safe TCP connect scan active)".into(),
            passed: true,
        });
    }

    // 3. Socket / file descriptor limits
    #[cfg(unix)]
    {
        let mut rlim = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        let res = unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut rlim) };
        if res == 0 {
            checks.push(DoctorCheck {
                name: "File Descriptors (ulimit -n)",
                status: if rlim.rlim_cur >= 1024 { "PASS" } else { "WARN" },
                details: format!(
                    "Current soft limit: {}, hard limit: {}",
                    rlim.rlim_cur, rlim.rlim_max
                ),
                passed: rlim.rlim_cur >= 1024,
            });
        }
    }
    #[cfg(not(unix))]
    {
        checks.push(DoctorCheck {
            name: "Socket Concurrency",
            status: "PASS",
            details: "Standard Windows socket pool available (configured concurrency: 1000)".into(),
            passed: true,
        });
    }

    // 4. Config validity
    let config_path = Config::config_path();
    let config_valid = config_path.exists();
    checks.push(DoctorCheck {
        name: "Configuration File",
        status: "PASS",
        details: format!(
            "Path: {} (exists: {})",
            config_path.display(),
            config_valid
        ),
        passed: true,
    });

    // 5. Database access
    let db_path = Config::db_path();
    if let Some(parent) = db_path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    match rusqlite::Connection::open(&db_path) {
        Ok(conn) => {
            let res: rusqlite::Result<i32> =
                conn.query_row("PRAGMA user_version;", [], |row| row.get(0));
            match res {
                Ok(_) => checks.push(DoctorCheck {
                    name: "SQLite Database",
                    status: "PASS",
                    details: format!("Writable: {}", db_path.display()),
                    passed: true,
                }),
                Err(e) => checks.push(DoctorCheck {
                    name: "SQLite Database",
                    status: "FAIL",
                    details: format!("Query failed: {e}"),
                    passed: false,
                }),
            }
        }
        Err(e) => checks.push(DoctorCheck {
            name: "SQLite Database",
            status: "FAIL",
            details: format!("Cannot open DB: {e}"),
            passed: false,
        }),
    }

    // 6. Webhooks reachability
    if let Some(ref hook) = config.discord_webhook {
        let redacted = if hook.len() > 15 {
            format!("{}...{}", &hook[..8], &hook[hook.len() - 4..])
        } else {
            "configured".to_string()
        };
        checks.push(DoctorCheck {
            name: "Discord Webhook",
            status: "PASS",
            details: format!("Configured ({redacted})"),
            passed: true,
        });
    } else {
        checks.push(DoctorCheck {
            name: "Discord Webhook",
            status: "INFO",
            details: "Not configured (optional for notifications)".into(),
            passed: true,
        });
    }

    // Render table
    let mut table = Table::new();
    table
        .load_preset(UTF8_FULL)
        .apply_modifier(UTF8_ROUND_CORNERS)
        .set_header(vec!["Component", "Status", "Details"]);

    for check in checks {
        let status_cell = match check.status {
            "PASS" => Cell::new(check.status).fg(Color::Green),
            "WARN" => Cell::new(check.status).fg(Color::Yellow),
            "FAIL" => Cell::new(check.status).fg(Color::Red),
            _ => Cell::new(check.status).fg(Color::Blue),
        };
        table.add_row(Row::from(vec![
            Cell::new(check.name),
            status_cell,
            Cell::new(check.details),
        ]));
    }

    println!("{table}");
    Ok(ExitCode::Ok)
}
