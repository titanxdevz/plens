use crate::error::{PlensError, Result};
use crate::model::ScanSummary;
use crate::model::Finding;
use chrono::{DateTime, Utc};
use rusqlite::{params, Connection};
use std::path::Path;

pub fn open_db(path: &Path) -> Result<Connection> {
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }

    let conn = Connection::open(path).map_err(|e| PlensError::Database {
        message: format!("Failed to open SQLite database {}: {e}", path.display()),
    })?;

    conn.execute_batch(
        "PRAGMA journal_mode = WAL;
         PRAGMA synchronous = NORMAL;
         PRAGMA foreign_keys = ON;
         PRAGMA busy_timeout = 5000;",
    )
    .map_err(|e| PlensError::Database {
        message: format!("Failed to configure SQLite pragmas: {e}"),
    })?;

    run_migrations(&conn)?;
    Ok(conn)
}

fn run_migrations(conn: &Connection) -> Result<()> {
    let version: i32 = conn
        .query_row("PRAGMA user_version;", [], |row| row.get(0))
        .map_err(|e| PlensError::Database {
            message: e.to_string(),
        })?;

    if version < 1 {
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS scans (
                id TEXT PRIMARY KEY,
                targets TEXT NOT NULL,
                start_time TEXT NOT NULL,
                end_time TEXT NOT NULL,
                duration_ms INTEGER NOT NULL,
                preset TEXT NOT NULL,
                profile TEXT,
                risk_score INTEGER NOT NULL,
                risk_grade TEXT NOT NULL,
                partial INTEGER NOT NULL DEFAULT 0,
                data_json TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS baselines (
                target TEXT PRIMARY KEY,
                scan_id TEXT NOT NULL,
                set_at TEXT NOT NULL,
                data_json TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS ignores (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                rule_or_port TEXT NOT NULL,
                target TEXT,
                reason TEXT NOT NULL,
                until TEXT,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS schedules (
                name TEXT PRIMARY KEY,
                target TEXT NOT NULL,
                cron_expr TEXT NOT NULL,
                preset TEXT NOT NULL,
                profile TEXT,
                last_run TEXT,
                next_run TEXT,
                active INTEGER NOT NULL DEFAULT 1
            );

            CREATE TABLE IF NOT EXISTS ack_targets (
                target TEXT PRIMARY KEY,
                acknowledged_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                action TEXT NOT NULL,
                target TEXT NOT NULL,
                details TEXT NOT NULL
            );

            PRAGMA user_version = 1;",
        )
        .map_err(|e| PlensError::Database {
            message: format!("Migration v1 failed: {e}"),
        })?;
    }

    Ok(())
}

pub fn save_scan(conn: &Connection, summary: &ScanSummary) -> Result<()> {
    let targets_str = summary.targets.join(",");
    let data_json = serde_json::to_string(summary).map_err(|e| PlensError::Other(e.to_string()))?;

    conn.execute(
        "INSERT OR REPLACE INTO scans (
            id, targets, start_time, end_time, duration_ms, preset, profile, risk_score, risk_grade, partial, data_json
        ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
        params![
            summary.scan_id,
            targets_str,
            summary.start_time.to_rfc3339(),
            summary.end_time.to_rfc3339(),
            summary.duration_ms as i64,
            summary.preset,
            summary.profile,
            summary.risk_score.score as i64,
            summary.risk_score.grade,
            if summary.partial { 1 } else { 0 },
            data_json,
        ],
    )
    .map_err(|e| PlensError::Database {
        message: format!("Failed to insert scan into database: {e}"),
    })?;

    Ok(())
}

pub fn get_scan(conn: &Connection, scan_id: &str) -> Result<Option<ScanSummary>> {
    let mut stmt = conn
        .prepare("SELECT data_json FROM scans WHERE id = ?1 OR id LIKE ?2 LIMIT 1")
        .map_err(|e| PlensError::Database {
            message: e.to_string(),
        })?;

    let prefix_match = format!("{}%", scan_id);
    let mut rows = stmt
        .query(params![scan_id, prefix_match])
        .map_err(|e| PlensError::Database {
            message: e.to_string(),
        })?;

    if let Some(row) = rows.next().map_err(|e| PlensError::Database {
        message: e.to_string(),
    })? {
        let json_str: String = row.get(0).map_err(|e| PlensError::Database {
            message: e.to_string(),
        })?;
        let summary: ScanSummary = serde_json::from_str(&json_str).map_err(|e| PlensError::Other(e.to_string()))?;
        Ok(Some(summary))
    } else {
        Ok(None)
    }
}

pub fn get_latest_scan_for_target(conn: &Connection, target: &str) -> Result<Option<ScanSummary>> {
    let mut stmt = conn
        .prepare(
            "SELECT data_json FROM scans 
             WHERE targets LIKE ?1 
             ORDER BY start_time DESC LIMIT 1",
        )
        .map_err(|e| PlensError::Database {
            message: e.to_string(),
        })?;

    let pattern = format!("%{}%", target);
    let mut rows = stmt
        .query(params![pattern])
        .map_err(|e| PlensError::Database {
            message: e.to_string(),
        })?;

    if let Some(row) = rows.next().map_err(|e| PlensError::Database {
        message: e.to_string(),
    })? {
        let json_str: String = row.get(0).map_err(|e| PlensError::Database {
            message: e.to_string(),
        })?;
        let summary: ScanSummary = serde_json::from_str(&json_str).map_err(|e| PlensError::Other(e.to_string()))?;
        Ok(Some(summary))
    } else {
        Ok(None)
    }
}

pub struct HistoryItem {
    pub id: String,
    pub targets: String,
    pub start_time: String,
    pub preset: String,
    pub risk_score: u32,
    pub risk_grade: String,
    pub findings_count: usize,
}

pub fn list_history(
    conn: &Connection,
    target: Option<&str>,
    since: Option<&str>,
    has_findings_only: bool,
    limit: usize,
) -> Result<Vec<HistoryItem>> {
    let mut query = "SELECT id, targets, start_time, preset, risk_score, risk_grade, data_json FROM scans WHERE 1=1".to_string();
    let mut params_vec: Vec<rusqlite::types::Value> = Vec::new();

    if let Some(t) = target {
        query.push_str(" AND targets LIKE ?");
        params_vec.push(format!("%{t}%").into());
    }
    if let Some(s) = since {
        query.push_str(" AND start_time >= ?");
        params_vec.push(s.to_string().into());
    }

    query.push_str(" ORDER BY start_time DESC LIMIT ?");
    params_vec.push((limit as i64).into());

    let mut stmt = conn.prepare(&query).map_err(|e| PlensError::Database {
        message: e.to_string(),
    })?;

    let rusqlite_params: Vec<&dyn rusqlite::ToSql> = params_vec.iter().map(|v| v as &dyn rusqlite::ToSql).collect();
    let rows = stmt
        .query_map(&*rusqlite_params, |row| {
            let id: String = row.get(0)?;
            let targets: String = row.get(1)?;
            let start_time: String = row.get(2)?;
            let preset: String = row.get(3)?;
            let risk_score: i64 = row.get(4)?;
            let risk_grade: String = row.get(5)?;
            let json_str: String = row.get(6)?;

            let findings_count = if let Ok(s) = serde_json::from_str::<ScanSummary>(&json_str) {
                s.findings.len()
            } else {
                0
            };

            Ok(HistoryItem {
                id,
                targets,
                start_time,
                preset,
                risk_score: risk_score as u32,
                risk_grade,
                findings_count,
            })
        })
        .map_err(|e| PlensError::Database {
            message: e.to_string(),
        })?;

    let mut results = Vec::new();
    for r in rows.flatten() {
        if has_findings_only && r.findings_count == 0 {
            continue;
        }
        results.push(r);
    }

    Ok(results)
}

pub fn set_baseline(conn: &Connection, target: &str, summary: &ScanSummary) -> Result<()> {
    let json = serde_json::to_string(summary).map_err(|e| PlensError::Other(e.to_string()))?;
    conn.execute(
        "INSERT OR REPLACE INTO baselines (target, scan_id, set_at, data_json) VALUES (?1, ?2, ?3, ?4)",
        params![target, summary.scan_id, Utc::now().to_rfc3339(), json],
    )
    .map_err(|e| PlensError::Database {
        message: e.to_string(),
    })?;

    Ok(())
}

pub fn get_baseline(conn: &Connection, target: &str) -> Result<Option<ScanSummary>> {
    let mut stmt = conn
        .prepare("SELECT data_json FROM baselines WHERE target = ?1")
        .map_err(|e| PlensError::Database {
            message: e.to_string(),
        })?;

    let mut rows = stmt.query(params![target]).map_err(|e| PlensError::Database {
        message: e.to_string(),
    })?;

    if let Some(row) = rows.next().map_err(|e| PlensError::Database {
        message: e.to_string(),
    })? {
        let json_str: String = row.get(0).map_err(|e| PlensError::Database {
            message: e.to_string(),
        })?;
        let summary: ScanSummary = serde_json::from_str(&json_str).map_err(|e| PlensError::Other(e.to_string()))?;
        Ok(Some(summary))
    } else {
        Ok(None)
    }
}

pub fn clear_baseline(conn: &Connection, target: &str) -> Result<()> {
    conn.execute("DELETE FROM baselines WHERE target = ?1", params![target])
        .map_err(|e| PlensError::Database {
            message: e.to_string(),
        })?;
    Ok(())
}

pub struct IgnoreEntry {
    pub id: i64,
    pub rule_or_port: String,
    pub target: Option<String>,
    pub reason: String,
    pub until: Option<String>,
    pub created_at: String,
}

pub fn add_ignore(
    conn: &Connection,
    rule_or_port: &str,
    target: Option<&str>,
    reason: &str,
    until: Option<&str>,
) -> Result<()> {
    conn.execute(
        "INSERT INTO ignores (rule_or_port, target, reason, until, created_at) VALUES (?1, ?2, ?3, ?4, ?5)",
        params![rule_or_port, target, reason, until, Utc::now().to_rfc3339()],
    )
    .map_err(|e| PlensError::Database {
        message: e.to_string(),
    })?;

    Ok(())
}

pub fn list_ignores(conn: &Connection) -> Result<Vec<IgnoreEntry>> {
    let mut stmt = conn
        .prepare("SELECT id, rule_or_port, target, reason, until, created_at FROM ignores ORDER BY id DESC")
        .map_err(|e| PlensError::Database {
            message: e.to_string(),
        })?;

    let rows = stmt
        .query_map([], |row| {
            Ok(IgnoreEntry {
                id: row.get(0)?,
                rule_or_port: row.get(1)?,
                target: row.get(2)?,
                reason: row.get(3)?,
                until: row.get(4)?,
                created_at: row.get(5)?,
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

pub fn remove_ignore(conn: &Connection, id: i64) -> Result<()> {
    conn.execute("DELETE FROM ignores WHERE id = ?1", params![id])
        .map_err(|e| PlensError::Database {
            message: e.to_string(),
        })?;
    Ok(())
}

pub fn filter_and_apply_ignores(
    conn: &Connection,
    target: &str,
    findings: &mut [Finding],
) -> Result<()> {
    let ignores = list_ignores(conn)?;
    let now = Utc::now();

    for f in findings.iter_mut() {
        for ign in &ignores {
            if let Some(ref t) = ign.target {
                if t != target {
                    continue;
                }
            }

            if let Some(ref until_str) = ign.until {
                if let Ok(until_dt) = DateTime::parse_from_rfc3339(until_str) {
                    if now > until_dt {
                        continue;
                    }
                } else if let Ok(until_naive) = chrono::NaiveDate::parse_from_str(until_str, "%Y-%m-%d") {
                    let until_dt = until_naive.and_hms_opt(23, 59, 59).unwrap().and_utc();
                    if now > until_dt {
                        continue;
                    }
                }
            }

            let matches_rule = f.rule_id == ign.rule_or_port;
            let matches_port = f.port.map(|p| p.to_string()) == Some(ign.rule_or_port.clone());

            if matches_rule || matches_port {
                f.suppressed = true;
                f.suppress_reason = Some(ign.reason.clone());
            }
        }
    }

    Ok(())
}

pub fn apply_retention(conn: &Connection, max_days: u32, max_scans: u32) -> Result<()> {
    let cutoff = Utc::now() - chrono::Duration::days(max_days as i64);
    let _ = conn.execute(
        "DELETE FROM scans WHERE start_time < ?1",
        params![cutoff.to_rfc3339()],
    );

    let _ = conn.execute(
        "DELETE FROM scans WHERE id NOT IN (
            SELECT id FROM scans ORDER BY start_time DESC LIMIT ?1
        )",
        params![max_scans as i64],
    );

    Ok(())
}

pub fn checkpoint_wal(conn: &Connection) -> Result<()> {
    conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
        .map_err(|e| PlensError::Database {
            message: format!("WAL checkpoint failed: {e}"),
        })?;
    Ok(())
}

/// Batch executes inserts in transactions (chunks of 500-1000 items) without holding full scan in memory (B.3)
pub fn batch_insert_chunks<T, F>(conn: &Connection, items: &[T], chunk_size: usize, mut insert_fn: F) -> Result<()>
where
    F: FnMut(&rusqlite::Transaction, &[T]) -> Result<()>,
{
    let size = chunk_size.clamp(500, 1000);
    for chunk in items.chunks(size) {
        let tx = conn.unchecked_transaction().map_err(|e| PlensError::Database {
            message: format!("Failed to begin batch transaction: {e}"),
        })?;
        insert_fn(&tx, chunk)?;
        tx.commit().map_err(|e| PlensError::Database {
            message: format!("Failed to commit batch transaction: {e}"),
        })?;
    }
    Ok(())
}
