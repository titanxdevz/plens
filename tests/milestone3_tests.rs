use chrono::Utc;
use plens::model::{Host, Port, PortState, PortVerdict, Protocol, RiskScore, ScanSummary, Service};
use plens::render::{export_csv, export_html, export_json, export_markdown, render_host_table, render_summary_card};

fn create_sample_summary() -> ScanSummary {
    let port80 = Port {
        number: 80,
        protocol: Protocol::Tcp,
        state: PortState::Open,
        service: Some(Service {
            name: "http".into(),
            product: Some("nginx".into()),
            version: Some("1.24.0".into()),
            extra_info: None,
            cpe: None,
        }),
        probe_result: None,
        bind_addr: Some("0.0.0.0".into()),
        process_name: Some("nginx".into()),
        pid: Some(1234),
        verdict: Some(PortVerdict::Exposed),
        confirmed: true,
    };

    let host = Host {
        id: "host-1".into(),
        target: "192.168.1.100".into(),
        ip: Some("192.168.1.100".into()),
        hostname: Some("web.local".into()),
        ports: vec![port80],
        listening_sockets: Vec::new(),
        is_up: true,
    };

    ScanSummary {
        scan_id: "test-scan-12345678".into(),
        targets: vec!["192.168.1.100".into()],
        start_time: Utc::now(),
        end_time: Utc::now(),
        duration_ms: 1500,
        preset: "standard".into(),
        profile: Some("web-server".into()),
        hosts: vec![host],
        findings: Vec::new(),
        risk_score: RiskScore::compute(&[], None),
        partial: false,
    }
}

#[test]
fn test_render_host_table() {
    let summary = create_sample_summary();
    let table_str = render_host_table(&summary.hosts[0], true);
    assert!(table_str.contains("80/tcp"));
    assert!(table_str.contains("open"));
    assert!(table_str.contains("nginx 1.24.0"));
    assert!(table_str.contains("EXPOSED"));
}

#[test]
fn test_render_summary_card() {
    let summary = create_sample_summary();
    let card = render_summary_card(&summary, true);
    assert!(card.contains("PORTLENS EXPOSURE AUDIT SUMMARY"));
    assert!(card.contains("192.168.1.100"));
    assert!(card.contains("Risk Posture:"));
    assert!(card.contains("A (Score: 0/100)"));
}

#[test]
fn test_export_json_schema() {
    let summary = create_sample_summary();
    let json_str = export_json(&summary).expect("Failed to export JSON");
    let val: serde_json::Value = serde_json::from_str(&json_str).expect("Valid JSON");
    assert_eq!(val["schema"], "plens.scan/1");
    assert_eq!(val["scan_id"], "test-scan-12345678");
    assert_eq!(val["targets"][0], "192.168.1.100");
}

#[test]
fn test_export_csv() {
    let summary = create_sample_summary();
    let csv_str = export_csv(&summary).expect("Failed to export CSV");
    assert!(csv_str.starts_with("host,port,protocol,state,service,version,verdict") || csv_str.contains("host,port,protocol"));
    assert!(csv_str.contains("192.168.1.100,80,tcp,open,http,1.24.0,EXPOSED"));
}

#[test]
fn test_export_markdown() {
    let summary = create_sample_summary();
    let md = export_markdown(&summary).expect("Failed to export Markdown");
    assert!(md.contains("# PortLens Exposure Audit Report"));
    assert!(md.contains("| 192.168.1.100 | 80 | tcp | open | http | 1.24.0 | EXPOSED |"));
}

#[test]
fn test_export_html_self_contained() {
    let summary = create_sample_summary();
    let html = export_html(&summary).expect("Failed to export HTML");
    assert!(html.contains("<!DOCTYPE html>"));
    assert!(html.contains("PortLens Security Exposure Report"));
    assert!(html.contains("192.168.1.100"));
    assert!(html.contains("EXPOSED"));
    // Verify no external script/link tags
    assert!(!html.contains("<script src="));
    assert!(!html.contains("<link rel=\"stylesheet\" href=\"http"));
}
