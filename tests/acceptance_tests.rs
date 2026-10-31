use plens::engine::discover::{run_discovery, DiscoveryConfig};
use std::time::{Duration, Instant};
use tokio::net::TcpListener;
use tokio::sync::mpsc;

#[tokio::test]
async fn test_scan_200_mock_listeners_finds_all() {
    let mut listeners = Vec::with_capacity(200);
    let mut expected_ports = Vec::with_capacity(200);

    for _ in 0..200 {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("Failed to bind ephemeral mock listener");
        let port = listener.local_addr().unwrap().port();
        expected_ports.push(port);
        listeners.push(listener);
    }

    let (tx, mut rx) = mpsc::channel(1024);
    let config = DiscoveryConfig {
        target: "127.0.0.1".into(),
        ports: expected_ports.clone(),
        concurrency: 500,
        per_host_cap: 500,
        timeout: Duration::from_millis(300),
        retry: false,
        rate_limit: 0,
        aimd: false,
        aimd_settings: Default::default(),
        rtt_clamp: None,
    };

    let start_time = Instant::now();
    let scan_task = tokio::spawn(async move {
        run_discovery(config, tx).await
    });

    // Verify first result appears in under 1 second
    let first_port = rx.recv().await.expect("Expected first open port");
    let first_latency = start_time.elapsed();
    assert!(
        first_latency < Duration::from_secs(1),
        "First result took {:?}, exceeding 1.0s requirement",
        first_latency
    );

    let mut found_ports = vec![first_port.number];
    while let Some(port) = rx.recv().await {
        found_ports.push(port.number);
    }

    let res = scan_task.await.unwrap().unwrap();
    assert_eq!(res.len(), 200, "Discovery did not find all 200 mock listeners");
    assert_eq!(found_ports.len(), 200);

    // Keep listeners alive until scan completes
    drop(listeners);
}
