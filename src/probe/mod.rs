use crate::model::ProbeResult;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

const DEFAULT_PROBE_TIMEOUT: Duration = Duration::from_millis(1200);

pub async fn run_probe(
    ip: IpAddr,
    port: u16,
    service_hint: Option<&str>,
    timeout: Option<Duration>,
) -> Option<ProbeResult> {
    let t = timeout.unwrap_or(DEFAULT_PROBE_TIMEOUT);
    let hint = service_hint.unwrap_or("").to_lowercase();

    if hint == "redis" || port == 6379 {
        return probe_redis(ip, port, t).await;
    }
    if hint == "mongodb" || hint == "mongo" || port == 27017 {
        return probe_mongodb(ip, port, t).await;
    }
    if hint == "elasticsearch" || port == 9200 {
        return probe_elasticsearch(ip, port, t).await;
    }
    if hint == "memcached" || port == 11211 {
        return probe_memcached(ip, port, t).await;
    }
    if hint == "docker" || port == 2375 {
        return probe_docker_api(ip, port, t).await;
    }
    if hint == "mysql" || hint == "mariadb" || port == 3306 {
        return probe_mysql(ip, port, t).await;
    }
    if hint == "postgresql" || hint == "postgres" || port == 5432 {
        return probe_postgresql(ip, port, t).await;
    }
    if hint == "ftp" || port == 21 {
        return probe_ftp(ip, port, t).await;
    }
    if hint == "ssh" || port == 22 || port == 2222 {
        return probe_ssh(ip, port, t).await;
    }
    if hint == "http" || hint == "https" || port == 80 || port == 443 || port == 8080 {
        return probe_http(ip, port, t, port == 443 || hint == "https").await;
    }
    if hint == "telnet" || port == 23 {
        return probe_telnet(ip, port, t).await;
    }
    if hint == "vnc" || (5900..=5910).contains(&port) {
        return probe_vnc(ip, port, t).await;
    }
    if hint == "rdp" || port == 3389 {
        return probe_rdp(ip, port, t).await;
    }

    None
}

pub async fn probe_redis(ip: IpAddr, port: u16, timeout: Duration) -> Option<ProbeResult> {
    let addr = SocketAddr::new(ip, port);
    let mut stream = tokio::time::timeout(timeout, TcpStream::connect(addr))
        .await
        .ok()?
        .ok()?;

    let cmd = b"*1\r\n$4\r\nPING\r\n";
    tokio::time::timeout(timeout, stream.write_all(cmd)).await.ok()?.ok()?;

    let mut buf = [0u8; 512];
    let n = tokio::time::timeout(timeout, stream.read(&mut buf)).await.ok()?.ok()?;
    let resp = String::from_utf8_lossy(&buf[..n]);

    if resp.contains("+PONG") {
        Some(ProbeResult {
            service: "redis".into(),
            verified_insecure: true,
            status: "noauth".into(),
            details: "Redis server accepted PING command without authentication".into(),
            banner: Some(resp.trim().into()),
        })
    } else if resp.contains("NOAUTH") {
        Some(ProbeResult {
            service: "redis".into(),
            verified_insecure: false,
            status: "auth_required".into(),
            details: "Redis server requires authentication (NOAUTH)".into(),
            banner: Some(resp.trim().into()),
        })
    } else {
        None
    }
}

pub async fn probe_docker_api(ip: IpAddr, port: u16, timeout: Duration) -> Option<ProbeResult> {
    let addr = SocketAddr::new(ip, port);
    let mut stream = tokio::time::timeout(timeout, TcpStream::connect(addr))
        .await
        .ok()?
        .ok()?;

    let req = b"GET /version HTTP/1.1\r\nHost: localhost\r\nUser-Agent: PortLens\r\nConnection: close\r\n\r\n";
    tokio::time::timeout(timeout, stream.write_all(req)).await.ok()?.ok()?;

    let mut buf = [0u8; 1024];
    let n = tokio::time::timeout(timeout, stream.read(&mut buf)).await.ok()?.ok()?;
    let resp = String::from_utf8_lossy(&buf[..n]);

    if resp.contains("200 OK") && (resp.contains("ApiVersion") || resp.contains("Docker")) {
        Some(ProbeResult {
            service: "docker".into(),
            verified_insecure: true,
            status: "noauth".into(),
            details: "Unauthenticated Docker daemon HTTP API exposed (allows root RCE)".into(),
            banner: Some("Docker API exposed".into()),
        })
    } else {
        None
    }
}

pub async fn probe_elasticsearch(ip: IpAddr, port: u16, timeout: Duration) -> Option<ProbeResult> {
    let addr = SocketAddr::new(ip, port);
    let mut stream = tokio::time::timeout(timeout, TcpStream::connect(addr))
        .await
        .ok()?
        .ok()?;

    let req = b"GET / HTTP/1.1\r\nHost: localhost\r\nUser-Agent: PortLens\r\nConnection: close\r\n\r\n";
    tokio::time::timeout(timeout, stream.write_all(req)).await.ok()?.ok()?;

    let mut buf = [0u8; 1024];
    let n = tokio::time::timeout(timeout, stream.read(&mut buf)).await.ok()?.ok()?;
    let resp = String::from_utf8_lossy(&buf[..n]);

    if resp.contains("200 OK") && (resp.contains("lucene") || resp.contains("tagline") || resp.contains("elasticsearch")) {
        Some(ProbeResult {
            service: "elasticsearch".into(),
            verified_insecure: true,
            status: "noauth".into(),
            details: "Elasticsearch responds without authentication credentials".into(),
            banner: Some("Elasticsearch root JSON response".into()),
        })
    } else if resp.contains("401 Unauthorized") {
        Some(ProbeResult {
            service: "elasticsearch".into(),
            verified_insecure: false,
            status: "auth_required".into(),
            details: "Elasticsearch requires xpack authentication (401)".into(),
            banner: Some("401 Unauthorized".into()),
        })
    } else {
        None
    }
}

pub async fn probe_memcached(ip: IpAddr, port: u16, timeout: Duration) -> Option<ProbeResult> {
    let addr = SocketAddr::new(ip, port);
    let mut stream = tokio::time::timeout(timeout, TcpStream::connect(addr))
        .await
        .ok()?
        .ok()?;

    tokio::time::timeout(timeout, stream.write_all(b"version\r\n")).await.ok()?.ok()?;

    let mut buf = [0u8; 256];
    let n = tokio::time::timeout(timeout, stream.read(&mut buf)).await.ok()?.ok()?;
    let resp = String::from_utf8_lossy(&buf[..n]);

    if resp.starts_with("VERSION") {
        Some(ProbeResult {
            service: "memcached".into(),
            verified_insecure: true,
            status: "open".into(),
            details: format!("Memcached service responding ({})", resp.trim()),
            banner: Some(resp.trim().into()),
        })
    } else {
        None
    }
}

pub async fn probe_mongodb(ip: IpAddr, port: u16, timeout: Duration) -> Option<ProbeResult> {
    let addr = SocketAddr::new(ip, port);
    let mut stream = tokio::time::timeout(timeout, TcpStream::connect(addr))
        .await
        .ok()?
        .ok()?;

    let msg = [
        0x3b, 0x00, 0x00, 0x00,
        0x01, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0xdd, 0x07, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00,
        0x22, 0x00, 0x00, 0x00,
        0x10, b'i', b's', b'M', b'a', b's', b't', b'e', b'r', 0x00, 0x01, 0x00, 0x00, 0x00,
        0x02, b'$', b'd', b'b', 0x00, 0x06, 0x00, 0x00, 0x00, b'a', b'd', b'm', b'i', b'n', 0x00,
        0x00,
    ];

    tokio::time::timeout(timeout, stream.write_all(&msg)).await.ok()?.ok()?;

    let mut buf = [0u8; 512];
    let n = tokio::time::timeout(timeout, stream.read(&mut buf)).await.ok()?.ok()?;
    if n > 16 {
        let resp = String::from_utf8_lossy(&buf[..n]);
        if resp.contains("ismaster") || resp.contains("isMaster") || resp.contains("maxWireVersion") {
            return Some(ProbeResult {
                service: "mongodb".into(),
                verified_insecure: true,
                status: "noauth".into(),
                details: "MongoDB responded to isMaster command without authentication".into(),
                banner: Some("MongoDB isMaster response".into()),
            });
        }
    }

    None
}

pub async fn probe_mysql(ip: IpAddr, port: u16, timeout: Duration) -> Option<ProbeResult> {
    let addr = SocketAddr::new(ip, port);
    let mut stream = tokio::time::timeout(timeout, TcpStream::connect(addr))
        .await
        .ok()?
        .ok()?;

    let mut buf = [0u8; 256];
    let n = tokio::time::timeout(timeout, stream.read(&mut buf)).await.ok()?.ok()?;
    if n > 4 {
        let text = String::from_utf8_lossy(&buf[4..n]);
        let version = text.split('\0').next().unwrap_or("unknown");
        return Some(ProbeResult {
            service: "mysql".into(),
            verified_insecure: true,
            status: "open".into(),
            details: format!("MySQL/MariaDB exposed greeting banner ({version})"),
            banner: Some(version.into()),
        });
    }

    None
}

pub async fn probe_postgresql(ip: IpAddr, port: u16, timeout: Duration) -> Option<ProbeResult> {
    let addr = SocketAddr::new(ip, port);
    let mut stream = tokio::time::timeout(timeout, TcpStream::connect(addr))
        .await
        .ok()?
        .ok()?;

    let ssl_req = [0x00, 0x00, 0x00, 0x08, 0x04, 0xd2, 0x16, 0x2f];
    tokio::time::timeout(timeout, stream.write_all(&ssl_req)).await.ok()?.ok()?;

    let mut buf = [0u8; 16];
    let n = tokio::time::timeout(timeout, stream.read(&mut buf)).await.ok()?.ok()?;
    if n > 0 && (buf[0] == b'S' || buf[0] == b'N') {
        return Some(ProbeResult {
            service: "postgresql".into(),
            verified_insecure: true,
            status: "open".into(),
            details: "PostgreSQL server acknowledged connection protocol".into(),
            banner: Some(format!("SSLRequest reply: {}", buf[0] as char)),
        });
    }

    None
}

pub async fn probe_ftp(ip: IpAddr, port: u16, timeout: Duration) -> Option<ProbeResult> {
    let addr = SocketAddr::new(ip, port);
    let mut stream = tokio::time::timeout(timeout, TcpStream::connect(addr))
        .await
        .ok()?
        .ok()?;

    let mut buf = [0u8; 256];
    let n = tokio::time::timeout(timeout, stream.read(&mut buf)).await.ok()?.ok()?;
    let banner = String::from_utf8_lossy(&buf[..n]).trim().to_string();

    tokio::time::timeout(timeout, stream.write_all(b"USER anonymous\r\n")).await.ok()?.ok()?;
    let n2 = tokio::time::timeout(timeout, stream.read(&mut buf)).await.ok()?.ok()?;
    let user_resp = String::from_utf8_lossy(&buf[..n2]);

    if user_resp.starts_with("230") || user_resp.starts_with("331") {
        Some(ProbeResult {
            service: "ftp".into(),
            verified_insecure: true,
            status: "anonymous".into(),
            details: "FTP server allows anonymous login probe".into(),
            banner: Some(banner),
        })
    } else {
        Some(ProbeResult {
            service: "ftp".into(),
            verified_insecure: false,
            status: "open".into(),
            details: "FTP server reachable".into(),
            banner: Some(banner),
        })
    }
}

pub async fn probe_ssh(ip: IpAddr, port: u16, timeout: Duration) -> Option<ProbeResult> {
    let addr = SocketAddr::new(ip, port);
    let mut stream = tokio::time::timeout(timeout, TcpStream::connect(addr))
        .await
        .ok()?
        .ok()?;

    let mut buf = [0u8; 256];
    let n = tokio::time::timeout(timeout, stream.read(&mut buf)).await.ok()?.ok()?;
    let banner = String::from_utf8_lossy(&buf[..n]);

    if banner.starts_with("SSH-") {
        Some(ProbeResult {
            service: "ssh".into(),
            verified_insecure: false,
            status: "open".into(),
            details: format!("SSH server banner: {}", banner.trim()),
            banner: Some(banner.trim().into()),
        })
    } else {
        None
    }
}

pub async fn probe_http(ip: IpAddr, port: u16, timeout: Duration, is_tls: bool) -> Option<ProbeResult> {
    if is_tls {
        return Some(ProbeResult {
            service: "https".into(),
            verified_insecure: false,
            status: "open".into(),
            details: "HTTPS TLS endpoint reachable".into(),
            banner: None,
        });
    }

    let addr = SocketAddr::new(ip, port);
    let mut stream = tokio::time::timeout(timeout, TcpStream::connect(addr))
        .await
        .ok()?
        .ok()?;

    let req = b"GET / HTTP/1.0\r\nHost: localhost\r\nUser-Agent: PortLens\r\n\r\n";
    tokio::time::timeout(timeout, stream.write_all(req)).await.ok()?.ok()?;

    let mut buf = [0u8; 1024];
    let n = tokio::time::timeout(timeout, stream.read(&mut buf)).await.ok()?.ok()?;
    let resp = String::from_utf8_lossy(&buf[..n]);

    let first_line = resp.lines().next().unwrap_or("HTTP response");
    Some(ProbeResult {
        service: "http".into(),
        verified_insecure: false,
        status: "open".into(),
        details: format!("HTTP endpoint: {}", first_line.trim()),
        banner: Some(first_line.trim().into()),
    })
}

pub async fn probe_telnet(ip: IpAddr, port: u16, timeout: Duration) -> Option<ProbeResult> {
    let addr = SocketAddr::new(ip, port);
    let mut stream = tokio::time::timeout(timeout, TcpStream::connect(addr))
        .await
        .ok()?
        .ok()?;

    let mut buf = [0u8; 128];
    let n = tokio::time::timeout(timeout, stream.read(&mut buf)).await.ok()?.ok()?;
    if n > 0 && (buf[0] == 0xff || String::from_utf8_lossy(&buf[..n]).contains("login")) {
        Some(ProbeResult {
            service: "telnet".into(),
            verified_insecure: true,
            status: "open".into(),
            details: "Cleartext Telnet service exposed".into(),
            banner: Some("Telnet IAC response".into()),
        })
    } else {
        None
    }
}

pub async fn probe_vnc(ip: IpAddr, port: u16, timeout: Duration) -> Option<ProbeResult> {
    let addr = SocketAddr::new(ip, port);
    let mut stream = tokio::time::timeout(timeout, TcpStream::connect(addr))
        .await
        .ok()?
        .ok()?;

    let mut buf = [0u8; 64];
    let n = tokio::time::timeout(timeout, stream.read(&mut buf)).await.ok()?.ok()?;
    let text = String::from_utf8_lossy(&buf[..n]);

    if text.starts_with("RFB ") {
        Some(ProbeResult {
            service: "vnc".into(),
            verified_insecure: true,
            status: "noauth".into(),
            details: format!("VNC server exposed ({})", text.trim()),
            banner: Some(text.trim().into()),
        })
    } else {
        None
    }
}

pub async fn probe_rdp(ip: IpAddr, port: u16, timeout: Duration) -> Option<ProbeResult> {
    let addr = SocketAddr::new(ip, port);
    let mut stream = tokio::time::timeout(timeout, TcpStream::connect(addr))
        .await
        .ok()?
        .ok()?;

    let cr = [
        0x03, 0x00, 0x00, 0x13,
        0x0e,
        0xe0,
        0x00, 0x00,
        0x00, 0x00,
        0x00,
        0x01, 0x00, 0x08, 0x00, 0x03, 0x00, 0x00, 0x00,
    ];

    tokio::time::timeout(timeout, stream.write_all(&cr)).await.ok()?.ok()?;

    let mut buf = [0u8; 64];
    let n = tokio::time::timeout(timeout, stream.read(&mut buf)).await.ok()?.ok()?;
    if n >= 4 && buf[0] == 0x03 {
        Some(ProbeResult {
            service: "rdp".into(),
            verified_insecure: false,
            status: "open".into(),
            details: "Remote Desktop Protocol service responsive".into(),
            banner: Some("RDP NegConfirm".into()),
        })
    } else {
        None
    }
}
