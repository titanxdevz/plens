use criterion::{criterion_group, criterion_main, Criterion};
use plens::engine::discover::{run_discovery, DiscoveryConfig};
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::sync::mpsc;

fn bench_scanner_throughput(c: &mut Criterion) {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("Failed to build tokio runtime");

    // Spawn 50 mock TCP listeners on localhost
    let (listeners, ports): (Vec<TcpListener>, Vec<u16>) = rt.block_on(async {
        let mut listeners = Vec::new();
        let mut ports = Vec::new();
        for _ in 0..50 {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let port = listener.local_addr().unwrap().port();
            ports.push(port);
            listeners.push(listener);
        }
        (listeners, ports)
    });

    c.bench_function("scanner_50_open_ports", |b| {
        b.to_async(&rt).iter(|| {
            let scan_ports = ports.clone();
            async move {
                let (tx, mut rx) = mpsc::channel(1024);
                let config = DiscoveryConfig {
                    target: "127.0.0.1".into(),
                    ports: scan_ports,
                    concurrency: 50,
                    per_host_cap: 500,
                    timeout: Duration::from_millis(150),
                    retry: false,
                    rate_limit: 10_000,
                    aimd: false,
                    aimd_settings: Default::default(),
                    rtt_clamp: None,
                };
                let scan_task = tokio::spawn(async move {
                    run_discovery(config, tx).await
                });
                let mut found = Vec::new();
                while let Some(port) = rx.recv().await {
                    found.push(port.number);
                }
                let _ = scan_task.await;
                assert_eq!(found.len(), 50);
            }
        });
    });

    drop(listeners);
}

criterion_group!(benches, bench_scanner_throughput);
criterion_main!(benches);
