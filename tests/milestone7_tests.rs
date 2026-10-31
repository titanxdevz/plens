use plens::model::{Host, Port, PortState, PortVerdict, Protocol, RiskScore, ScanSummary, Service};
use plens::profile::{evaluate_profile_compliance, load_profile};
use plens::render::export_html;

#[test]
fn test_builtin_profiles_loading() {
    let web = load_profile("web-server", None).expect("web-server profile failed to load");
    assert_eq!(web.expected_ports, vec![80, 443]);
    assert!(web.local_only_services.contains(&"mysql".to_string()));

    let node = load_profile("pterodactyl-node", None).expect("pterodactyl-node failed");
    assert!(node.expected_ports.contains(&8080));
    assert!(node.expected_ports.contains(&2022));
    assert!(node.is_port_allowed(25565));

    let min = load_profile("minimal", None).expect("minimal failed");
    assert_eq!(min.expected_ports, vec![22]);
}

#[test]
fn test_profile_compliance_evaluation() {
    let profile = load_profile("pterodactyl-panel", None).unwrap();

    let host = Host {
        id: "h1".into(),
        target: "panel.node.internal".into(),
        ip: Some("10.0.0.2".into()),
        hostname: Some("panel".into()),
        ports: vec![
            Port {
                number: 80,
                protocol: Protocol::Tcp,
                state: PortState::Open,
                service: Some(Service {
                    name: "http".into(),
                    product: None,
                    version: None,
                    extra_info: None,
                    cpe: None,
                }),
                probe_result: None,
                bind_addr: Some("0.0.0.0".into()),
                process_name: Some("nginx".into()),
                pid: Some(10),
                verdict: Some(PortVerdict::Exposed),
                confirmed: true,
            },
            // Unexpected port 9999
            Port {
                number: 9999,
                protocol: Protocol::Tcp,
                state: PortState::Open,
                service: None,
                probe_result: None,
                bind_addr: Some("0.0.0.0".into()),
                process_name: None,
                pid: None,
                verdict: Some(PortVerdict::Exposed),
                confirmed: true,
            },
            // MySQL exposed externally (violates local_only_services)
            Port {
                number: 3306,
                protocol: Protocol::Tcp,
                state: PortState::Open,
                service: Some(Service {
                    name: "mysql".into(),
                    product: None,
                    version: None,
                    extra_info: None,
                    cpe: None,
                }),
                probe_result: None,
                bind_addr: Some("0.0.0.0".into()),
                process_name: Some("mysqld".into()),
                pid: Some(20),
                verdict: Some(PortVerdict::Exposed),
                confirmed: true,
            },
        ],
        listening_sockets: Vec::new(),
        is_up: true,
    };

    let findings = evaluate_profile_compliance(&host, &profile);

    // Expected:
    // 1. unexpected-port for 9999
    // 2. mysql-must-be-local for 3306
    // 3. missing-expected for port 443 (since only 80 was found open)
    assert!(findings.iter().any(|f| f.rule_id == "unexpected-port" && f.port == Some(9999)));
    assert!(findings.iter().any(|f| f.rule_id == "mysql-must-be-local" && f.port == Some(3306)));
    assert!(findings.iter().any(|f| f.rule_id == "missing-expected" && f.port == Some(443)));
}

#[test]
fn test_html_report_documents_formula() {
    let host = Host {
        id: "h".into(),
        target: "test.local".into(),
        ip: None,
        hostname: None,
        ports: vec![],
        listening_sockets: vec![],
        is_up: true,
    };
    let summary = ScanSummary {
        scan_id: "scan-html-test".into(),
        targets: vec!["test.local".into()],
        start_time: chrono::Utc::now(),
        end_time: chrono::Utc::now(),
        duration_ms: 1200,
        preset: "quick".into(),
        profile: Some("minimal".into()),
        hosts: vec![host],
        findings: vec![],
        risk_score: RiskScore::compute(&[], Some(50)),
        partial: false,
    };

    let html = export_html(&summary).unwrap();
    assert!(html.contains("Scoring Methodology:"));
    assert!(html.contains("Weighted severity with diminishing returns"));
    assert!(html.contains("Historical Trend:"));
}
