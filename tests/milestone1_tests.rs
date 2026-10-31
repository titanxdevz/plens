use clap::Parser;
use plens::cli::args::{Cli, Commands};
use plens::config::Config;
use plens::model::{Finding, RiskScore, Severity};

#[test]
fn test_cli_parsing_scan() {
    let args = vec![
        "plens",
        "scan",
        "192.168.1.1",
        "--preset",
        "quick",
        "--speed",
        "4",
        "--explain",
    ];
    let cli = Cli::try_parse_from(args).expect("CLI parse failed");
    match cli.command {
        Some(Commands::Scan(scan)) => {
            assert_eq!(scan.targets, vec!["192.168.1.1"]);
            assert_eq!(scan.preset.as_deref(), Some("quick"));
            assert_eq!(scan.speed, Some(4));
            assert!(scan.explain);
        }
        _ => panic!("Expected Scan command"),
    }
}

#[test]
fn test_severity_ordering() {
    assert!(Severity::Info < Severity::Low);
    assert!(Severity::Low < Severity::Medium);
    assert!(Severity::Medium < Severity::High);
    assert!(Severity::High < Severity::Critical);
}

#[test]
fn test_risk_score_calculation() {
    let findings = vec![
        Finding {
            id: "1".into(),
            rule_id: "redis-noauth".into(),
            target: "10.0.0.1".into(),
            port: Some(6379),
            severity: Severity::Critical,
            message: "Redis unauthenticated".into(),
            why: "RCE".into(),
            fix: None,
            suppressed: false,
            suppress_reason: None,
            suppress_until: None,
        },
        Finding {
            id: "2".into(),
            rule_id: "telnet-exposed".into(),
            target: "10.0.0.1".into(),
            port: Some(23),
            severity: Severity::High,
            message: "Telnet exposed".into(),
            why: "Cleartext".into(),
            fix: None,
            suppressed: false,
            suppress_reason: None,
            suppress_until: None,
        },
    ];

    let score = RiskScore::compute(&findings, Some(80));
    assert!(score.score > 0);
    assert!(score.score <= 100);
    assert!(score.trend_description.is_some());
}

#[test]
fn test_config_defaults() {
    let cfg = Config::default();
    assert_eq!(cfg.default_preset, "standard");
    assert_eq!(cfg.concurrency, 1000);
    assert_eq!(cfg.timeout_ms, 800);
    assert_eq!(cfg.retention_days, 90);
}
