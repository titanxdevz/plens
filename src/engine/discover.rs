use crate::error::{PlensError, Result};
use crate::model::{Port, PortState, Protocol};
use std::collections::{HashSet, VecDeque};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::lookup_host;
use tokio::sync::{mpsc, Mutex, Semaphore};
use tokio::time::sleep;

/// Raise soft RLIMIT_NOFILE to the hard limit (Unix only). Windows: skip.
/// Returns derived max concurrency keeping ~10% headroom.
pub fn init_system_limits() -> usize {
    #[cfg(unix)]
    {
        if let Ok((soft, hard)) = rlimit::Resource::NOFILE.get() {
            if soft < hard {
                let _ = rlimit::Resource::NOFILE.set(hard, hard);
            }
            if let Ok((effective_soft, _)) = rlimit::Resource::NOFILE.get() {
                let max_concurrency = (effective_soft as f64 * 0.90) as usize;
                return max_concurrency.clamp(64, 65535);
            }
        }
        1000
    }
    #[cfg(not(unix))]
    {
        1000
    }
}

pub const TOP_100_PORTS: &[u16] = &[
    20, 21, 22, 23, 25, 53, 69, 80, 88, 102, 110, 111, 119, 123, 135, 137, 138, 139, 143, 161,
    162, 179, 389, 443, 445, 465, 500, 514, 515, 520, 587, 631, 636, 873, 902, 990, 993, 995,
    1025, 1080, 1194, 1433, 1434, 1521, 1720, 1723, 1883, 2049, 2082, 2083, 2086, 2087, 2181,
    2222, 2375, 2376, 2379, 2380, 3000, 3128, 3306, 3389, 4369, 5000, 5060, 5432, 5672, 5900,
    5901, 5984, 6000, 6379, 6443, 7000, 7001, 8000, 8008, 8080, 8081, 8088, 8089, 8443, 8888,
    9000, 9042, 9090, 9092, 9200, 9300, 9418, 9999, 10000, 11211, 15672, 25565, 27017, 27018,
    27019, 50000, 50070,
];

/// Global port frequency table for scanning most frequent ports first
pub const PORT_FREQUENCY_ORDER: &[u16] = &[
    80, 443, 22, 21, 25, 53, 3306, 8080, 8443, 5432, 6379, 27017, 3389, 110, 143, 993, 995,
    135, 139, 445, 161, 162, 23, 111, 2049, 8000, 8888, 9000, 9200, 2375, 2376, 11211, 1433,
    1521, 5000, 5900, 5901, 25565, 3000, 8081, 8088, 8089, 9090, 9092, 6443, 8008, 9042, 9300,
    7000, 7001, 5672, 15672, 4369, 5984, 2181, 2222, 1883, 1194, 1080, 5060, 1723, 873, 990,
    902, 636, 631, 587, 465, 389, 179, 123, 119, 102, 88, 69, 20, 514, 515, 520, 500, 1434,
    1720, 2082, 2083, 2086, 2087, 2379, 2380, 3128, 6000, 9418, 9999, 10000, 27018, 27019,
    50000, 50070,
];

pub fn order_ports_by_frequency(mut ports: Vec<u16>) -> Vec<u16> {
    fn rank(port: u16) -> usize {
        if let Some(pos) = PORT_FREQUENCY_ORDER.iter().position(|&p| p == port) {
            pos
        } else {
            10_000 + (port as usize)
        }
    }
    ports.sort_by_key(|&p| rank(p));
    ports
}

/// Result cache: prioritize known open ports first, followed by remaining ports (D.1)
pub fn prioritize_cached_ports(known_open: &[u16], candidate_ports: Vec<u16>) -> Vec<u16> {
    let mut result = Vec::with_capacity(candidate_ports.len() + known_open.len());
    let mut seen = HashSet::new();
    for &p in known_open {
        if seen.insert(p) {
            result.push(p);
        }
    }
    for p in candidate_ports {
        if seen.insert(p) {
            result.push(p);
        }
    }
    result
}

pub fn get_top_1000_ports() -> Vec<u16> {
    let mut ports: HashSet<u16> = TOP_100_PORTS.iter().copied().collect();
    for p in 1..=1024 {
        ports.insert(p);
    }
    let common_high = [
        1080, 1194, 1214, 1337, 1433, 1434, 1521, 1723, 1883, 2049, 2082, 2083, 2086, 2087,
        2181, 2222, 2375, 2376, 2379, 2380, 2483, 2484, 25565, 27015, 27017, 27018, 27019,
        3000, 3128, 3268, 3269, 3306, 3389, 3690, 4369, 5000, 5060, 5432, 5672, 5900, 5901,
        5938, 5984, 6000, 6379, 6443, 6667, 7000, 7001, 7777, 8000, 8008, 8080, 8081, 8088,
        8090, 8443, 8888, 9000, 9042, 9090, 9092, 9100, 9200, 9300, 9418, 9999, 10000, 11211,
        15672, 28017, 50000, 50070,
    ];
    for p in common_high {
        ports.insert(p);
    }
    let mut sorted: Vec<u16> = ports.into_iter().collect();
    sorted = order_ports_by_frequency(sorted);
    sorted.truncate(1000);
    sorted
}

pub fn parse_port_specs(spec: &str) -> Result<Vec<u16>> {
    let spec = spec.trim().to_lowercase();
    if spec == "top100" {
        return Ok(order_ports_by_frequency(TOP_100_PORTS.to_vec()));
    }
    if spec == "top1000" {
        return Ok(get_top_1000_ports());
    }
    if spec == "all" || spec == "1-65535" {
        return Ok(order_ports_by_frequency((1..=65535).collect()));
    }
    if spec == "top50udp" {
        return Ok(order_ports_by_frequency(TOP_100_PORTS.iter().take(50).copied().collect()));
    }

    let mut result = HashSet::new();
    for part in spec.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        if let Some((start_s, end_s)) = part.split_once('-') {
            let start = start_s.trim().parse::<u16>().map_err(|_| PlensError::InvalidArgument {
                message: format!("Invalid port range start: '{start_s}'"),
            })?;
            let end = end_s.trim().parse::<u16>().map_err(|_| PlensError::InvalidArgument {
                message: format!("Invalid port range end: '{end_s}'"),
            })?;
            if start > end {
                return Err(PlensError::InvalidArgument {
                    message: format!("Invalid port range: {start} > {end}"),
                });
            }
            for p in start..=end {
                result.insert(p);
            }
        } else {
            let p = part.parse::<u16>().map_err(|_| PlensError::InvalidArgument {
                message: format!("Invalid port number: '{part}'"),
            })?;
            result.insert(p);
        }
    }

    let sorted: Vec<u16> = result.into_iter().collect();
    Ok(order_ports_by_frequency(sorted))
}

#[derive(Debug, Clone)]
pub struct AimdSettings {
    pub min_concurrency: usize,
    pub max_concurrency: usize,
    pub additive_increase: usize,
    pub multiplicative_decrease: f64,
    pub timeout_threshold: f64,
    pub window_size: usize,
}

impl Default for AimdSettings {
    fn default() -> Self {
        Self {
            min_concurrency: 10,
            max_concurrency: 1000,
            additive_increase: 25,
            multiplicative_decrease: 0.5,
            timeout_threshold: 0.20,
            window_size: 50,
        }
    }
}

#[derive(Debug, Clone)]
pub struct DiscoveryConfig {
    pub target: String,
    pub ports: Vec<u16>,
    pub concurrency: usize,
    pub per_host_cap: usize,
    pub timeout: Duration,
    pub retry: bool,
    pub rate_limit: usize,
    pub aimd: bool,
    pub aimd_settings: AimdSettings,
    pub rtt_clamp: Option<(Duration, Duration)>,
}

impl Default for DiscoveryConfig {
    fn default() -> Self {
        Self {
            target: "127.0.0.1".into(),
            ports: TOP_100_PORTS.to_vec(),
            concurrency: 1000,
            per_host_cap: 500,
            timeout: Duration::from_millis(800),
            retry: true,
            rate_limit: 0,
            aimd: true,
            aimd_settings: AimdSettings::default(),
            rtt_clamp: Some((Duration::from_millis(200), Duration::from_millis(2500))),
        }
    }
}

pub async fn resolve_target(target: &str) -> Result<SocketAddr> {
    let host_port = if target.contains(':') && !target.contains("]:") {
        target.to_string()
    } else {
        format!("{target}:80")
    };

    let mut addrs = lookup_host(&host_port).await.map_err(|e| PlensError::Network {
        message: format!("Failed to resolve target '{target}': {e}"),
    })?;

    addrs.next().ok_or_else(|| PlensError::Network {
        message: format!("No IP addresses found for target '{target}'"),
    })
}

/// Connect using socket2 with SO_LINGER=0 so closes send RST and immediately free ephemeral ports
pub async fn connect_socket2(addr: SocketAddr, timeout: Duration) -> std::result::Result<bool, bool> {
    let domain = if addr.is_ipv4() {
        socket2::Domain::IPV4
    } else {
        socket2::Domain::IPV6
    };

    let socket = match socket2::Socket::new(domain, socket2::Type::STREAM, Some(socket2::Protocol::TCP)) {
        Ok(s) => s,
        Err(_) => return Err(false),
    };

    if socket.set_nonblocking(true).is_err() {
        return Err(false);
    }
    // SO_LINGER=0 sends RST on close to immediately free port and prevent TIME_WAIT
    let _ = socket.set_linger(Some(Duration::ZERO));

    let sock_addr = socket2::SockAddr::from(addr);
    match socket.connect(&sock_addr) {
        Ok(()) => return Ok(true),
        Err(e) => {
            #[cfg(unix)]
            let would_block = e.raw_os_error() == Some(libc::EINPROGRESS) || e.kind() == std::io::ErrorKind::WouldBlock;
            #[cfg(windows)]
            let would_block = e.raw_os_error() == Some(10035) // WSAEWOULDBLOCK
                || e.raw_os_error() == Some(10036) // WSAEINPROGRESS
                || e.kind() == std::io::ErrorKind::WouldBlock;
            #[cfg(not(any(unix, windows)))]
            let would_block = e.kind() == std::io::ErrorKind::WouldBlock;

            if !would_block {
                return Ok(false);
            }
        }
    }

    let std_stream: std::net::TcpStream = socket.into();
    let tokio_stream = match tokio::net::TcpStream::from_std(std_stream) {
        Ok(s) => s,
        Err(_) => return Err(false),
    };

    match tokio::time::timeout(timeout, tokio_stream.writable()).await {
        Ok(Ok(())) => match tokio_stream.take_error() {
            Ok(None) => Ok(true),
            _ => Ok(false),
        },
        Ok(Err(_)) => Ok(false),
        Err(_) => Err(true), // timed out
    }
}

/// Measure round-trip time (RTT) to target using probe connects (C.1)
pub async fn measure_target_rtt(ip: std::net::IpAddr) -> Option<Duration> {
    let sample_ports = [80, 443, 22, 53, 39871];
    for &port in &sample_ports {
        let start = std::time::Instant::now();
        let addr = SocketAddr::new(ip, port);
        let res = connect_socket2(addr, Duration::from_millis(500)).await;
        let elapsed = start.elapsed();
        if res.is_ok() {
            return Some(elapsed);
        }
    }
    None
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PortScanOutcome {
    pub is_open: bool,
    pub timed_out: bool,
    pub confirmed: bool,
}

pub async fn scan_single_port(
    ip: std::net::IpAddr,
    port: u16,
    timeout: Duration,
    retry: bool,
) -> PortScanOutcome {
    let addr = SocketAddr::new(ip, port);
    match connect_socket2(addr, timeout).await {
        Ok(true) => PortScanOutcome {
            is_open: true,
            timed_out: false,
            confirmed: true,
        },
        Ok(false) => PortScanOutcome {
            is_open: false,
            timed_out: false,
            confirmed: true,
        },
        Err(true) => {
            if retry {
                match connect_socket2(addr, timeout).await {
                    Ok(true) => PortScanOutcome {
                        is_open: true,
                        timed_out: false,
                        confirmed: false, // passed only on retry -> uncertain
                    },
                    Ok(false) => PortScanOutcome {
                        is_open: false,
                        timed_out: false,
                        confirmed: true,
                    },
                    Err(_) => PortScanOutcome {
                        is_open: false,
                        timed_out: true,
                        confirmed: false,
                    },
                }
            } else {
                PortScanOutcome {
                    is_open: false,
                    timed_out: true,
                    confirmed: false,
                }
            }
        }
        Err(false) => PortScanOutcome {
            is_open: false,
            timed_out: false,
            confirmed: false,
        },
    }
}

/// Dual confirmation: re-check a newly appeared port after a short delay (C.4)
pub async fn dual_confirm_port(ip: std::net::IpAddr, port: u16) -> bool {
    tokio::time::sleep(Duration::from_millis(200)).await;
    let outcome = scan_single_port(ip, port, Duration::from_millis(800), false).await;
    outcome.is_open
}

pub struct AimdGovernor {
    pub current_concurrency: AtomicUsize,
    pub settings: AimdSettings,
    pub semaphore: Arc<Semaphore>,
    pub outcomes: Mutex<VecDeque<bool>>, // true if timeout
    pub rate_limit_detected: AtomicBool,
}

impl AimdGovernor {
    pub fn new(initial: usize, settings: AimdSettings) -> Self {
        let initial = initial.clamp(settings.min_concurrency, settings.max_concurrency);
        Self {
            current_concurrency: AtomicUsize::new(initial),
            settings,
            semaphore: Arc::new(Semaphore::new(initial)),
            outcomes: Mutex::new(VecDeque::new()),
            rate_limit_detected: AtomicBool::new(false),
        }
    }

    pub async fn record_outcome(&self, timed_out: bool) {
        let mut outcomes = self.outcomes.lock().await;
        outcomes.push_back(timed_out);
        if outcomes.len() >= self.settings.window_size {
            let timeouts = outcomes.iter().filter(|&&t| t).count();
            let timeout_rate = timeouts as f64 / outcomes.len() as f64;
            let current = self.current_concurrency.load(Ordering::Relaxed);

            // Detect rate-limiting or erratic drops (C.2)
            if timeout_rate >= 0.35 {
                self.rate_limit_detected.store(true, Ordering::Relaxed);
                // Aggressively reduce speed
                let new_conc = self.settings.min_concurrency;
                if new_conc < current {
                    let diff = current - new_conc;
                    self.current_concurrency.store(new_conc, Ordering::Relaxed);
                    if let Ok(permits) = self.semaphore.clone().try_acquire_many(diff as u32) {
                        permits.forget();
                    }
                }
            } else if timeout_rate > self.settings.timeout_threshold {
                // Multiplicative decrease (halve)
                let new_conc = ((current as f64 * self.settings.multiplicative_decrease) as usize)
                    .clamp(self.settings.min_concurrency, self.settings.max_concurrency);
                if new_conc < current {
                    let diff = current - new_conc;
                    self.current_concurrency.store(new_conc, Ordering::Relaxed);
                    if let Ok(permits) = self.semaphore.clone().try_acquire_many(diff as u32) {
                        permits.forget();
                    }
                }
            } else if timeout_rate <= 0.05 {
                // Additive increase
                let new_conc = (current + self.settings.additive_increase)
                    .clamp(self.settings.min_concurrency, self.settings.max_concurrency);
                if new_conc > current {
                    let diff = new_conc - current;
                    self.current_concurrency.store(new_conc, Ordering::Relaxed);
                    self.semaphore.add_permits(diff);
                }
            }
            outcomes.clear();
        }
    }
}

pub async fn run_discovery(
    cfg: DiscoveryConfig,
    tx: mpsc::Sender<Port>,
) -> Result<Vec<u16>> {
    let base_addr = resolve_target(&cfg.target).await?;
    let ip = base_addr.ip();

    // Measure RTT and clamp timeout (C.1)
    let effective_timeout = if let Some((min_t, max_t)) = cfg.rtt_clamp {
        if let Some(rtt) = measure_target_rtt(ip).await {
            (rtt * 4).clamp(min_t, max_t)
        } else {
            cfg.timeout
        }
    } else {
        cfg.timeout
    };

    // Bound concurrency by per-host cap and system limits
    let effective_concurrency = cfg.concurrency.min(cfg.per_host_cap).clamp(1, 4096);
    let mut aimd_settings = cfg.aimd_settings.clone();
    aimd_settings.max_concurrency = effective_concurrency;

    let governor = Arc::new(AimdGovernor::new(effective_concurrency, aimd_settings));
    let ports = Arc::new(cfg.ports);
    let port_index = Arc::new(AtomicUsize::new(0));

    let num_workers = effective_concurrency.clamp(1, 1024);
    let rate_delay = if cfg.rate_limit > 0 {
        1_000_000usize
            .checked_div(cfg.rate_limit)
            .map(|micros| Duration::from_micros(micros as u64))
    } else {
        None
    };

    let (found_tx, mut found_rx) = mpsc::channel::<u16>(1024);
    let mut worker_handles = Vec::with_capacity(num_workers);

    for _ in 0..num_workers {
        let ports = ports.clone();
        let port_index = port_index.clone();
        let governor = governor.clone();
        let tx = tx.clone();
        let found_tx = found_tx.clone();
        let timeout = effective_timeout;
        let retry = cfg.retry;
        let aimd = cfg.aimd;

        let handle = tokio::spawn(async move {
            loop {
                let idx = port_index.fetch_add(1, Ordering::Relaxed);
                if idx >= ports.len() {
                    break;
                }
                let port = ports[idx];

                // Acquire permit from governor (enforcing AIMD / concurrency limit)
                let permit = if aimd {
                    governor.semaphore.clone().acquire_owned().await.ok()
                } else {
                    None
                };

                if let Some(delay) = rate_delay {
                    sleep(delay).await;
                }

                let outcome = scan_single_port(ip, port, timeout, retry).await;

                if aimd {
                    governor.record_outcome(outcome.timed_out).await;
                }

                drop(permit);

                if outcome.is_open {
                    let rate_limited = governor.rate_limit_detected.load(Ordering::Relaxed);
                    let port_model = Port {
                        number: port,
                        protocol: Protocol::Tcp,
                        state: PortState::Open,
                        service: None,
                        probe_result: None,
                        bind_addr: None,
                        process_name: None,
                        pid: None,
                        verdict: None,
                        confirmed: outcome.confirmed && !rate_limited,
                    };
                    let _ = tx.send(port_model).await;
                    let _ = found_tx.send(port).await;
                }
            }
        });
        worker_handles.push(handle);
    }

    drop(found_tx);

    let mut open_ports = Vec::new();
    while let Some(port) = found_rx.recv().await {
        open_ports.push(port);
    }

    for handle in worker_handles {
        let _ = handle.await;
    }

    open_ports.sort_unstable();
    Ok(open_ports)
}
