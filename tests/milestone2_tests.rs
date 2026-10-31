use plens::config::Config;
use plens::engine::discover::{parse_port_specs, run_discovery, DiscoveryConfig};
use plens::engine::nmap::parse_nmap_xml;
use plens::engine::{get_preset_config, DefaultScanEngine, ScanEngine, ScanRequest};
use plens::model::PortState;
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::sync::mpsc;

const SAMPLE_NMAP_XML: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<nmaprun scanner="nmap" args="nmap -sV -p 80,6379 -oX - 127.0.0.1" start="1700000000">
<host starttime="1700000000" endtime="1700000005">
<status state="up" reason="localhost-response" reason_ttl="0"/>
<address addr="127.0.0.1" addrtype="ipv4"/>
<ports>
<port protocol="tcp" portid="80">
<state state="open" reason="syn-ack" reason_ttl="64"/>
<service name="http" product="nginx" version="1.24.0" extrainfo="Ubuntu" method="probed" conf="10">
<cpe>cpe:/a:igor_sysoev:nginx:1.24.0</cpe>
</service>
</port>
<port protocol="tcp" portid="6379">
<state state="open" reason="syn-ack" reason_ttl="64"/>
<service name="redis" product="Redis key-value store" version="7.0.12" method="probed" conf="10">
<cpe>cpe:/a:redislabs:redis:7.0.12</cpe>
</service>
</port>
</ports>
</host>
<runstats><finished time="1700000005" exit="success"/></runstats>
</nmaprun>"#;

#[test]
fn test_parse_nmap_xml_fixture() {
    let parsed = parse_nmap_xml(SAMPLE_NMAP_XML).expect("Failed to parse valid nmap XML");
    assert_eq!(parsed.len(), 2);

    let port80 = parsed.get(&80).expect("Port 80 missing");
    assert_eq!(port80.state, PortState::Open);
    let s80 = port80.service.as_ref().expect("Port 80 service missing");
    assert_eq!(s80.name, "http");
    assert_eq!(s80.product.as_deref(), Some("nginx"));
    assert_eq!(s80.version.as_deref(), Some("1.24.0"));
    assert_eq!(s80.cpe.as_deref(), Some("cpe:/a:igor_sysoev:nginx:1.24.0"));

    let port6379 = parsed.get(&6379).expect("Port 6379 missing");
    assert_eq!(port6379.state, PortState::Open);
    let s6379 = port6379.service.as_ref().expect("Port 6379 service missing");
    assert_eq!(s6379.name, "redis");
    assert_eq!(s6379.version.as_deref(), Some("7.0.12"));
}

#[test]
fn test_port_specs_parsing() {
    let top100 = parse_port_specs("top100").unwrap();
    assert_eq!(top100.len(), 100);

    let custom = parse_port_specs("80,443,8000-8005").unwrap();
    assert_eq!(custom, vec![80, 443, 8000, 8001, 8002, 8003, 8004, 8005]);

    assert!(parse_port_specs("invalid-port").is_err());
    assert!(parse_port_specs("500-200").is_err());
}

#[test]
fn test_preset_configurations() {
    let quick = get_preset_config("quick", None).unwrap();
    assert_eq!(quick.ports, "top100");
    assert!(!quick.phase2_enabled);

    let standard = get_preset_config("standard", None).unwrap();
    assert_eq!(standard.ports, "top1000");
    assert!(standard.phase2_enabled);

    let full = get_preset_config("full", None).unwrap();
    assert_eq!(full.ports, "1-65535");

    let stealth = get_preset_config("stealth", None).unwrap();
    assert!(stealth.rate_limit > 0);
}

#[tokio::test]
async fn test_phase1_mock_tcp_discovery() {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("Failed to bind ephemeral TCP port");
    let local_port = listener.local_addr().unwrap().port();

    let (tx, mut rx) = mpsc::channel(10);
    let cfg = DiscoveryConfig {
        target: "127.0.0.1".into(),
        ports: vec![local_port, local_port.wrapping_add(1)],
        concurrency: 10,
        per_host_cap: 500,
        timeout: Duration::from_millis(300),
        retry: false,
        rate_limit: 0,
        aimd: false,
        aimd_settings: Default::default(),
        rtt_clamp: None,
    };

    let server_task = tokio::spawn(async move {
        // Accept one connection then shut down
        let _ = listener.accept().await;
    });

    let discovery_task = tokio::spawn(async move {
        run_discovery(cfg, tx).await
    });

    let open_port = rx.recv().await.expect("Expected open port event");
    assert_eq!(open_port.number, local_port);

    let discovered = discovery_task.await.unwrap().unwrap();
    assert!(discovered.contains(&local_port));

    server_task.abort();
}

#[test]
fn test_scan_engine_plan_explain() {
    let config = Config::default();
    let engine = DefaultScanEngine::new(config);
    let req = ScanRequest {
        targets: vec!["127.0.0.1".to_string()],
        preset: "quick".to_string(),
        profile: None,
        custom_ports: None,
        speed: Some(3),
        no_probe: false,
        raw_args: None,
    };

    let plan = engine.plan(&req).unwrap();
    assert_eq!(plan.target, "127.0.0.1");
    assert_eq!(plan.preset, "quick");
    assert_eq!(plan.phase1_ports, "top100");
    assert!(!plan.phase2_enabled);
}
