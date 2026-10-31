use chrono::Utc;
use plens::diff::diff_scans;
use plens::model::{Host, Port, PortState, PortVerdict, Protocol, RiskScore, ScanSummary};
use plens::store::{
    add_ignore, clear_baseline, filter_and_apply_ignores, get_baseline, get_scan, list_history,
    list_ignores, open_db, save_scan, set_baseline,
};
use tempfile::NamedTempFile;

fn create_scan(id: &str, target: &str, ports: Vec<Port>) -> ScanSummary {
    let host = Host {
        id: format!("host-{id}"),
        target: target.to_string(),
        ip: Some(target.to_string()),
        hostname: Some("node".into()),
        ports,
        listening_sockets: Vec::new(),
        is_up: true,
    };

    ScanSummary {
        scan_id: id.to_string(),
        targets: vec![target.to_string()],
        start_time: Utc::now(),
        end_time: Utc::now(),
        duration_ms: 1000,
        preset: "standard".into(),
        profile: None,
        hosts: vec![host],
        findings: Vec::new(),
        risk_score: RiskScore::compute(&[], None),
        partial: false,
    }
}

#[test]
fn test_sqlite_save_and_retrieve_scan() {
    let tmp = NamedTempFile::new().unwrap();
    let conn = open_db(tmp.path()).expect("Failed to open temp DB");

    let port80 = Port {
        number: 80,
        protocol: Protocol::Tcp,
        state: PortState::Open,
        service: None,
        probe_result: None,
        bind_addr: Some("0.0.0.0".into()),
        process_name: Some("nginx".into()),
        pid: Some(10),
        verdict: Some(PortVerdict::Exposed),
        confirmed: true,
    };

    let scan = create_scan("scan-001", "10.0.0.1", vec![port80]);
    save_scan(&conn, &scan).expect("Failed to save scan");

    let retrieved = get_scan(&conn, "scan-001").expect("Failed to get scan");
    assert!(retrieved.is_some());
    let s = retrieved.unwrap();
    assert_eq!(s.scan_id, "scan-001");
    assert_eq!(s.targets[0], "10.0.0.1");
    assert_eq!(s.hosts[0].ports.len(), 1);

    let history = list_history(&conn, None, None, false, 10).expect("History list failed");
    assert_eq!(history.len(), 1);
    assert_eq!(history[0].id, "scan-001");
}

#[test]
fn test_baseline_storage_and_drift() {
    let tmp = NamedTempFile::new().unwrap();
    let conn = open_db(tmp.path()).expect("Failed to open temp DB");

    let port80 = Port {
        number: 80,
        protocol: Protocol::Tcp,
        state: PortState::Open,
        service: None,
        probe_result: None,
        bind_addr: Some("0.0.0.0".into()),
        process_name: Some("nginx".into()),
        pid: Some(10),
        verdict: Some(PortVerdict::Exposed),
        confirmed: true,
    };

    let scan1 = create_scan("scan-base", "10.0.0.1", vec![port80.clone()]);
    set_baseline(&conn, "10.0.0.1", &scan1).expect("Failed to set baseline");

    let loaded_base = get_baseline(&conn, "10.0.0.1")
        .expect("Failed to get baseline")
        .expect("Baseline missing");
    assert_eq!(loaded_base.scan_id, "scan-base");

    // Scan 2 with newly exposed port 6379
    let port6379 = Port {
        number: 6379,
        protocol: Protocol::Tcp,
        state: PortState::Open,
        service: None,
        probe_result: None,
        bind_addr: Some("0.0.0.0".into()),
        process_name: Some("redis-server".into()),
        pid: Some(20),
        verdict: Some(PortVerdict::Exposed),
        confirmed: true,
    };

    let scan2 = create_scan("scan-new", "10.0.0.1", vec![port80, port6379]);

    let drift = diff_scans(&loaded_base, &scan2);
    assert!(drift.has_drift());
    assert_eq!(drift.new_open.len(), 1);
    assert_eq!(drift.new_open[0].number, 6379);

    clear_baseline(&conn, "10.0.0.1").expect("Clear baseline failed");
    assert!(get_baseline(&conn, "10.0.0.1").unwrap().is_none());
}

#[test]
fn test_ignore_rules_and_expiry() {
    let tmp = NamedTempFile::new().unwrap();
    let conn = open_db(tmp.path()).expect("Failed to open temp DB");

    add_ignore(
        &conn,
        "redis-noauth",
        Some("10.0.0.1"),
        "Testing exception",
        Some("2099-12-31"),
    )
    .expect("Add ignore failed");

    let list = list_ignores(&conn).expect("List ignores failed");
    assert_eq!(list.len(), 1);
    assert_eq!(list[0].rule_or_port, "redis-noauth");

    let mut findings = vec![plens::model::Finding {
        id: "f-1".into(),
        rule_id: "redis-noauth".into(),
        target: "10.0.0.1".into(),
        port: Some(6379),
        severity: plens::model::Severity::Critical,
        message: "No auth Redis".into(),
        why: "RCE".into(),
        fix: None,
        suppressed: false,
        suppress_reason: None,
        suppress_until: None,
    }];

    filter_and_apply_ignores(&conn, "10.0.0.1", &mut findings).expect("Apply ignores failed");
    assert!(findings[0].suppressed);
    assert_eq!(findings[0].suppress_reason.as_deref(), Some("Testing exception"));
}
