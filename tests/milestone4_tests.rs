use plens::engine::local::correlate_port_verdict;
use plens::model::{Host, ListeningSocket, Port, PortState, PortVerdict, Protocol, Severity};
use plens::probe::{probe_docker_api, probe_memcached, probe_redis};
use plens::risk::{evaluate_findings, load_rules};
use plens::safety::check_target_safety;
use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

#[tokio::test]
async fn test_redis_probe_unauthenticated() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();

    let server_task = tokio::spawn(async move {
        if let Ok((mut socket, _)) = listener.accept().await {
            let mut buf = [0u8; 64];
            let _ = socket.read(&mut buf).await;
            let _ = socket.write_all(b"+PONG\r\n").await;
        }
    });

    let probe_res = probe_redis(
        IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
        port,
        Duration::from_millis(500),
    )
    .await
    .expect("Expected Redis probe result");

    assert!(probe_res.verified_insecure);
    assert_eq!(probe_res.status, "noauth");
    assert!(probe_res.details.contains("without authentication"));

    server_task.abort();
}

#[tokio::test]
async fn test_redis_probe_authenticated() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();

    let server_task = tokio::spawn(async move {
        if let Ok((mut socket, _)) = listener.accept().await {
            let mut buf = [0u8; 64];
            let _ = socket.read(&mut buf).await;
            let _ = socket.write_all(b"-NOAUTH Authentication required.\r\n").await;
        }
    });

    let probe_res = probe_redis(
        IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
        port,
        Duration::from_millis(500),
    )
    .await
    .expect("Expected Redis probe result");

    assert!(!probe_res.verified_insecure);
    assert_eq!(probe_res.status, "auth_required");

    server_task.abort();
}

#[tokio::test]
async fn test_docker_api_probe() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();

    let server_task = tokio::spawn(async move {
        if let Ok((mut socket, _)) = listener.accept().await {
            let mut buf = [0u8; 256];
            let _ = socket.read(&mut buf).await;
            let resp = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"ApiVersion\":\"1.41\",\"DockerRootDir\":\"/var/lib/docker\"}";
            let _ = socket.write_all(resp).await;
        }
    });

    let probe_res = probe_docker_api(
        IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
        port,
        Duration::from_millis(500),
    )
    .await
    .expect("Expected Docker probe result");

    assert!(probe_res.verified_insecure);
    assert_eq!(probe_res.status, "noauth");

    server_task.abort();
}

#[tokio::test]
async fn test_memcached_probe() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();

    let server_task = tokio::spawn(async move {
        if let Ok((mut socket, _)) = listener.accept().await {
            let mut buf = [0u8; 64];
            let _ = socket.read(&mut buf).await;
            let _ = socket.write_all(b"VERSION 1.6.18\r\n").await;
        }
    });

    let probe_res = probe_memcached(
        IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
        port,
        Duration::from_millis(500),
    )
    .await
    .expect("Expected Memcached probe result");

    assert!(probe_res.verified_insecure);
    assert_eq!(probe_res.status, "open");

    server_task.abort();
}

#[test]
fn test_inside_outside_correlation() {
    let listeners = vec![
        ListeningSocket {
            protocol: Protocol::Tcp,
            bind_addr: "127.0.0.1".into(),
            port: 3306,
            pid: Some(101),
            process_name: Some("mysqld".into()),
            inode: None,
            is_docker: false,
        },
        ListeningSocket {
            protocol: Protocol::Tcp,
            bind_addr: "0.0.0.0".into(),
            port: 80,
            pid: Some(102),
            process_name: Some("nginx".into()),
            inode: None,
            is_docker: false,
        },
        ListeningSocket {
            protocol: Protocol::Tcp,
            bind_addr: "0.0.0.0".into(),
            port: 6379,
            pid: Some(103),
            process_name: Some("redis-server".into()),
            inode: None,
            is_docker: false,
        },
    ];

    // Case 1: Bound 127.0.0.1 -> LOCAL_ONLY (even if externally queried)
    let (_, _, _, verdict1) = correlate_port_verdict(3306, false, &listeners);
    assert_eq!(verdict1, PortVerdict::LocalOnly);

    // Case 2: Bound 0.0.0.0 + reachable -> EXPOSED
    let (_, _, _, verdict2) = correlate_port_verdict(80, true, &listeners);
    assert_eq!(verdict2, PortVerdict::Exposed);

    // Case 3: Bound 0.0.0.0 + not reachable -> FILTERED
    let (_, _, _, verdict3) = correlate_port_verdict(6379, false, &listeners);
    assert_eq!(verdict3, PortVerdict::Filtered);

    // Case 4: No listener + reachable -> GHOST
    let (_, _, _, verdict4) = correlate_port_verdict(8080, true, &listeners);
    assert_eq!(verdict4, PortVerdict::Ghost);
}

#[test]
fn test_safety_allowlist_and_target_validation() {
    let allowlist = vec!["192.168.1.".to_string(), "10.0.0.5".to_string()];

    // Permitted target
    assert!(check_target_safety("192.168.1.50", &allowlist, true, None).is_ok());
    assert!(check_target_safety("10.0.0.5", &allowlist, true, None).is_ok());

    // Disallowed target outside allowlist
    assert!(check_target_safety("8.8.8.8", &allowlist, true, None).is_err());

    // Injection attempt
    assert!(check_target_safety("127.0.0.1; rm -rf /", &[], true, None).is_err());
}

#[test]
fn test_risk_evaluation_and_fixes() {
    let rules = load_rules(None).expect("Failed to load default rules");
    assert!(!rules.is_empty());

    let host = Host {
        id: "test-host".into(),
        target: "10.0.0.1".into(),
        ip: Some("10.0.0.1".into()),
        hostname: Some("vps".into()),
        ports: vec![Port {
            number: 6379,
            protocol: Protocol::Tcp,
            state: PortState::Open,
            service: Some(plens::model::Service {
                name: "redis".into(),
                product: Some("Redis".into()),
                version: Some("6.2.0".into()),
                extra_info: None,
                cpe: None,
            }),
            probe_result: Some(plens::model::ProbeResult {
                service: "redis".into(),
                verified_insecure: true,
                status: "noauth".into(),
                details: "No password required".into(),
                banner: None,
            }),
            bind_addr: Some("0.0.0.0".into()),
            process_name: Some("redis-server".into()),
            pid: Some(400),
            verdict: Some(PortVerdict::Exposed),
            confirmed: true,
        }],
        listening_sockets: Vec::new(),
        is_up: true,
    };

    let findings = evaluate_findings(&host, &rules);
    assert!(!findings.is_empty());

    let redis_finding = findings
        .iter()
        .find(|f| f.rule_id == "redis-noauth")
        .expect("Redis finding missing");
    assert_eq!(redis_finding.severity, Severity::Critical);
    assert!(redis_finding.fix.is_some());

    let fix = redis_finding.fix.as_ref().unwrap();
    assert_eq!(fix.ufw.as_deref(), Some("ufw deny 6379"));
}
