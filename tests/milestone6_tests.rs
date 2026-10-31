use plens::alert::AlertManager;
use plens::schedule::{
    add_schedule, compute_next_run, generate_systemd_unit, list_schedules, parse_cron_schedule,
    remove_schedule, ScheduleJob,
};
use plens::store::open_db;
use std::time::Duration;
use tempfile::NamedTempFile;

#[test]
fn test_cron_parsing_5_part_and_next_run() {
    let sched = parse_cron_schedule("0 0 * * *").expect("Failed to parse standard 5-part cron");
    assert!(sched.upcoming(chrono::Utc).next().is_some());

    let next = compute_next_run("0 12 * * *").expect("Failed to compute next run");
    assert!(next > chrono::Utc::now());
}

#[test]
fn test_schedule_crud() {
    let tmp = NamedTempFile::new().unwrap();
    let conn = open_db(tmp.path()).expect("Failed to open DB");

    let job = ScheduleJob {
        name: "nightly-audit".into(),
        target: "10.0.0.5".into(),
        cron_expr: "0 2 * * *".into(),
        preset: "full".into(),
        profile: Some("web-server".into()),
        last_run: None,
        next_run: None,
        active: true,
    };

    add_schedule(&conn, &job).expect("Failed to add schedule");

    let list = list_schedules(&conn).expect("Failed to list schedules");
    assert_eq!(list.len(), 1);
    assert_eq!(list[0].name, "nightly-audit");
    assert_eq!(list[0].target, "10.0.0.5");
    assert!(list[0].next_run.is_some());

    remove_schedule(&conn, "nightly-audit").expect("Failed to remove schedule");
    let list_after = list_schedules(&conn).expect("Failed to list schedules");
    assert!(list_after.is_empty());
}

#[test]
fn test_systemd_unit_generation() {
    let unit = generate_systemd_unit();
    assert!(unit.contains("[Unit]"));
    assert!(unit.contains("Description=PortLens Exposure Auditor Daemon"));
    assert!(unit.contains("ExecStart=/usr/local/bin/plens daemon"));
    assert!(unit.contains("[Install]"));
    assert!(unit.contains("WantedBy=multi-user.target"));
}

#[test]
fn test_alert_manager_dedup_and_rate_limit() {
    let mgr = AlertManager::new();
    let key = "target1:redis-noauth";

    // First alert should not be suppressed
    assert!(!mgr.should_suppress(key, Duration::from_secs(60)));

    // Second immediate alert should be suppressed (rate limited / deduped)
    assert!(mgr.should_suppress(key, Duration::from_secs(60)));
}
