use crate::config::Config;
use crate::engine::ScanEngine;
use crate::error::{PlensError, Result};
use chrono::{DateTime, Utc};
use cron::Schedule;
use rusqlite::{params, Connection};
use std::str::FromStr;
use std::time::Duration;

#[derive(Debug, Clone)]
pub struct ScheduleJob {
    pub name: String,
    pub target: String,
    pub cron_expr: String,
    pub preset: String,
    pub profile: Option<String>,
    pub last_run: Option<String>,
    pub next_run: Option<String>,
    pub active: bool,
}

pub fn parse_cron_schedule(expr: &str) -> Result<Schedule> {
    let parts: Vec<&str> = expr.split_whitespace().collect();
    let normalized = if parts.len() == 5 {
        format!("0 {} *", expr)
    } else if parts.len() == 6 {
        format!("{} *", expr)
    } else {
        expr.to_string()
    };

    Schedule::from_str(&normalized).map_err(|e| PlensError::InvalidArgument {
        message: format!("Invalid cron expression '{expr}': {e}"),
    })
}

pub fn compute_next_run(expr: &str) -> Result<DateTime<Utc>> {
    let sched = parse_cron_schedule(expr)?;
    let next = sched.upcoming(Utc).next().ok_or_else(|| {
        PlensError::InvalidArgument {
            message: format!("No upcoming execution time for cron '{expr}'"),
        }
    })?;
    Ok(next)
}

pub fn add_schedule(conn: &Connection, job: &ScheduleJob) -> Result<()> {
    let next_run = compute_next_run(&job.cron_expr)?.to_rfc3339();

    conn.execute(
        "INSERT OR REPLACE INTO schedules (
            name, target, cron_expr, preset, profile, last_run, next_run, active
        ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        params![
            job.name,
            job.target,
            job.cron_expr,
            job.preset,
            job.profile,
            job.last_run,
            next_run,
            if job.active { 1 } else { 0 },
        ],
    )
    .map_err(|e| PlensError::Database {
        message: e.to_string(),
    })?;

    Ok(())
}

pub fn list_schedules(conn: &Connection) -> Result<Vec<ScheduleJob>> {
    let mut stmt = conn
        .prepare("SELECT name, target, cron_expr, preset, profile, last_run, next_run, active FROM schedules ORDER BY name ASC")
        .map_err(|e| PlensError::Database {
            message: e.to_string(),
        })?;

    let rows = stmt
        .query_map([], |row| {
            let active_int: i32 = row.get(7)?;
            Ok(ScheduleJob {
                name: row.get(0)?,
                target: row.get(1)?,
                cron_expr: row.get(2)?,
                preset: row.get(3)?,
                profile: row.get(4)?,
                last_run: row.get(5)?,
                next_run: row.get(6)?,
                active: active_int != 0,
            })
        })
        .map_err(|e| PlensError::Database {
            message: e.to_string(),
        })?;

    let mut result = Vec::new();
    for r in rows.flatten() {
        result.push(r);
    }
    Ok(result)
}

pub fn remove_schedule(conn: &Connection, name: &str) -> Result<()> {
    conn.execute("DELETE FROM schedules WHERE name = ?1", params![name])
        .map_err(|e| PlensError::Database {
            message: e.to_string(),
        })?;
    Ok(())
}

pub fn update_schedule_run(
    conn: &Connection,
    name: &str,
    last_run: &DateTime<Utc>,
    next_run: &DateTime<Utc>,
) -> Result<()> {
    conn.execute(
        "UPDATE schedules SET last_run = ?1, next_run = ?2 WHERE name = ?3",
        params![last_run.to_rfc3339(), next_run.to_rfc3339(), name],
    )
    .map_err(|e| PlensError::Database {
        message: e.to_string(),
    })?;
    Ok(())
}

pub fn generate_systemd_unit() -> String {
    r#"[Unit]
Description=PortLens Exposure Auditor Daemon
Documentation=https://github.com/portlens/plens
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/plens daemon
Restart=always
RestartSec=15
User=root
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
"#
    .to_string()
}

pub async fn run_daemon(config: &Config) -> Result<()> {
    println!("PortLens exposure auditor daemon started.");
    println!("Loaded configuration from {}", Config::config_path().display());
    println!("Press Ctrl+C to stop.");

    let alert_mgr = crate::alert::AlertManager::new();

    loop {
        if let Ok(conn) = crate::store::open_db(&Config::db_path()) {
            if let Ok(jobs) = list_schedules(&conn) {
                let now = Utc::now();
                for job in jobs {
                    if !job.active {
                        continue;
                    }

                    let should_run = if let Some(ref nr_str) = job.next_run {
                        if let Ok(nr_dt) = DateTime::parse_from_rfc3339(nr_str) {
                            now >= nr_dt
                        } else {
                            false
                        }
                    } else {
                        true
                    };

                    if should_run {
                        println!("[+] Running scheduled scan job: '{}' on {}", job.name, job.target);

                        // Result cache & Incremental mode (D.1, D.2)
                        let known_open = if let Ok(Some(prev)) = crate::store::get_latest_scan_for_target(&conn, &job.target) {
                            prev.hosts.iter().flat_map(|h| &h.ports)
                                .filter(|p| p.state == crate::model::PortState::Open)
                                .map(|p| p.number)
                                .collect::<Vec<u16>>()
                        } else {
                            Vec::new()
                        };

                        let custom_ports = if !known_open.is_empty() {
                            let base_ports = crate::engine::discover::TOP_100_PORTS.to_vec();
                            let prioritized = crate::engine::discover::prioritize_cached_ports(&known_open, base_ports);
                            Some(prioritized.iter().map(|p| p.to_string()).collect::<Vec<_>>().join(","))
                        } else {
                            None
                        };

                        let scan_req = crate::engine::ScanRequest {
                            targets: vec![job.target.clone()],
                            preset: job.preset.clone(),
                            profile: job.profile.clone(),
                            custom_ports,
                            speed: None,
                            no_probe: false,
                            raw_args: None,
                        };

                        let engine = crate::engine::DefaultScanEngine::new(config.clone());
                        if let Ok(plan) = engine.plan(&scan_req) {
                            use futures::StreamExt;
                            let mut stream = Box::pin(engine.run(plan));
                            let mut scan_res = None;
                            while let Some(event) = stream.next().await {
                                if let crate::engine::ScanEvent::Finished(s) = event {
                                    scan_res = Some(s);
                                }
                            }

                            if let Some(summary) = scan_res {
                                let _ = crate::store::save_scan(&conn, &summary);

                                if let Ok(Some(baseline)) = crate::store::get_baseline(&conn, &job.target) {
                                    let drift = crate::diff::diff_scans(&baseline, &summary);
                                    if drift.has_drift() {
                                        // Dual confirmation: re-check newly appeared ports before alerting (C.4)
                                        let mut confirmed_new_open = Vec::new();
                                        if let Ok(addr) = crate::engine::discover::resolve_target(&job.target).await {
                                            for port in &drift.new_open {
                                                if crate::engine::discover::dual_confirm_port(addr.ip(), port.number).await {
                                                    confirmed_new_open.push(port.clone());
                                                }
                                            }
                                        } else {
                                            confirmed_new_open = drift.new_open.clone();
                                        }

                                        let has_confirmed_changes = !confirmed_new_open.is_empty()
                                            || !drift.newly_closed.is_empty()
                                            || !drift.service_changed.is_empty()
                                            || !drift.verdict_changed.is_empty();

                                        if has_confirmed_changes {
                                            let alert = crate::alert::AlertPayload {
                                                target: job.target.clone(),
                                                scan_id: summary.scan_id.clone(),
                                                title: format!("Baseline drift detected for {}", job.target),
                                                summary: format!("New open ports or visibility changes observed on {}", job.target),
                                                severity: crate::model::Severity::High,
                                                risk_score: summary.risk_score.score,
                                                risk_grade: summary.risk_score.grade.clone(),
                                                score_delta: Some(drift.score_delta),
                                                changes: confirmed_new_open.iter().map(|p| format!("+ Port {}/{}", p.number, p.protocol)).collect(),
                                            };
                                            let _ = alert_mgr.dispatch_alert(
                                                config.discord_webhook.as_deref(),
                                                config.generic_webhook.as_deref(),
                                                &alert,
                                            ).await;
                                        }
                                    }
                                }

                                if let Ok(next) = compute_next_run(&job.cron_expr) {
                                    let _ = update_schedule_run(&conn, &job.name, &now, &next);
                                }
                            }
                        }
                    }
                }
            }
        }

        tokio::time::sleep(Duration::from_secs(10)).await;
    }
}
