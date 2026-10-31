use crate::error::{PlensError, Result};
use crate::model::{ListeningSocket, PortVerdict, Protocol};
use std::collections::HashMap;
use std::net::IpAddr;
use std::process::Command;

pub async fn get_outbound_ip() -> Option<IpAddr> {
    let socket = std::net::UdpSocket::bind("0.0.0.0:0").ok()?;
    socket.connect("1.1.1.1:80").ok()?;
    let local_addr = socket.local_addr().ok()?;
    Some(local_addr.ip())
}

pub fn get_local_listening_sockets() -> Result<Vec<ListeningSocket>> {
    #[cfg(target_os = "linux")]
    {
        get_linux_sockets()
    }
    #[cfg(target_os = "macos")]
    {
        get_macos_sockets()
    }
    #[cfg(target_os = "windows")]
    {
        get_windows_sockets()
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        Ok(Vec::new())
    }
}

#[cfg(target_os = "windows")]
pub fn get_windows_sockets() -> Result<Vec<ListeningSocket>> {
    let output = Command::new("netstat")
        .args(["-ano", "-p", "tcp"])
        .output()
        .map_err(|e| PlensError::Other(format!("Failed to execute netstat: {e}")))?;

    let out_str = String::from_utf8_lossy(&output.stdout);
    let pid_names = get_windows_pid_process_map();
    let mut sockets = Vec::new();

    for line in out_str.lines() {
        let line = line.trim();
        if !line.starts_with("TCP") {
            continue;
        }
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 5 && parts[3].eq_ignore_ascii_case("LISTENING") {
            let local_addr = parts[1];
            let pid = parts[4].parse::<u32>().ok();

            if let Some((ip, port_str)) = local_addr.rsplit_once(':') {
                if let Ok(port) = port_str.parse::<u16>() {
                    let proc_name = pid.and_then(|p| pid_names.get(&p).cloned());
                    let is_docker = proc_name
                        .as_deref()
                        .map(|n| n.to_lowercase().contains("docker"))
                        .unwrap_or(false);

                    sockets.push(ListeningSocket {
                        protocol: Protocol::Tcp,
                        bind_addr: ip.to_string(),
                        port,
                        pid,
                        process_name: proc_name,
                        inode: None,
                        is_docker,
                    });
                }
            }
        }
    }

    Ok(sockets)
}

#[cfg(target_os = "windows")]
fn get_windows_pid_process_map() -> HashMap<u32, String> {
    let mut map = HashMap::new();
    if let Ok(output) = Command::new("tasklist").args(["/FO", "CSV", "/NH"]).output() {
        let text = String::from_utf8_lossy(&output.stdout);
        for line in text.lines() {
            let parts: Vec<&str> = line.split(',').map(|s| s.trim_matches('"')).collect();
            if parts.len() >= 2 {
                let name = parts[0].to_string();
                if let Ok(pid) = parts[1].parse::<u32>() {
                    map.insert(pid, name);
                }
            }
        }
    }
    map
}

#[cfg(target_os = "linux")]
pub fn get_linux_sockets() -> Result<Vec<ListeningSocket>> {
    if let Ok(sockets) = parse_proc_net_tcp() {
        if !sockets.is_empty() {
            return Ok(sockets);
        }
    }

    let output = Command::new("ss")
        .args(["-tulpn"])
        .output()
        .map_err(|e| PlensError::Other(format!("Failed to execute ss: {e}")))?;

    let out_str = String::from_utf8_lossy(&output.stdout);
    let mut sockets = Vec::new();

    for line in out_str.lines() {
        if line.starts_with("Netid") || line.starts_with("State") {
            continue;
        }
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 5 && parts[1].eq_ignore_ascii_case("LISTEN") {
            let proto = if parts[0].contains("udp") {
                Protocol::Udp
            } else {
                Protocol::Tcp
            };
            let local_addr = parts[4];
            if let Some((ip, port_str)) = local_addr.rsplit_once(':') {
                if let Ok(port) = port_str.parse::<u16>() {
                    let mut proc_name = None;
                    let mut pid = None;
                    if parts.len() >= 7 {
                        let proc_part = parts[6];
                        if let Some(users) = proc_part.strip_prefix("users:((") {
                            let end = users.find('"').unwrap_or(users.len());
                            proc_name = Some(users[..end].to_string());
                            if let Some(pid_idx) = users.find("pid=") {
                                let rem = &users[pid_idx + 4..];
                                let end_pid = rem.find(',').unwrap_or(rem.len());
                                pid = rem[..end_pid].parse::<u32>().ok();
                            }
                        }
                    }

                    let is_docker = proc_name
                        .as_deref()
                        .map(|n| n.contains("docker"))
                        .unwrap_or(false);

                    sockets.push(ListeningSocket {
                        protocol: proto,
                        bind_addr: ip.to_string(),
                        port,
                        pid,
                        process_name: proc_name,
                        inode: None,
                        is_docker,
                    });
                }
            }
        }
    }

    Ok(sockets)
}

#[cfg(target_os = "linux")]
fn parse_proc_net_tcp() -> Result<Vec<ListeningSocket>> {
    let mut sockets = Vec::new();
    let inode_map = get_linux_inode_process_map();

    for file in &["/proc/net/tcp", "/proc/net/tcp6"] {
        if let Ok(content) = std::fs::read_to_string(file) {
            for line in content.lines().skip(1) {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 10 && parts[3] == "0A" {
                    if let Some((hex_ip, hex_port)) = parts[1].split_once(':') {
                        if let Ok(port) = u16::from_str_radix(hex_port, 16) {
                            let ip = parse_hex_ip(hex_ip);
                            let inode = parts[9].parse::<u64>().ok();
                            let (proc_name, pid) = inode
                                .and_then(|i| inode_map.get(&i).cloned())
                                .unwrap_or((None, None));

                            let is_docker = proc_name
                                .as_deref()
                                .map(|n| n.contains("docker"))
                                .unwrap_or(false);

                            sockets.push(ListeningSocket {
                                protocol: Protocol::Tcp,
                                bind_addr: ip,
                                port,
                                pid,
                                process_name: proc_name,
                                inode,
                                is_docker,
                            });
                        }
                    }
                }
            }
        }
    }

    Ok(sockets)
}

#[cfg(target_os = "linux")]
fn parse_hex_ip(hex: &str) -> String {
    if hex.len() == 8 {
        if let Ok(num) = u32::from_str_radix(hex, 16) {
            let ip = std::net::Ipv4Addr::from(u32::from_be(num));
            return ip.to_string();
        }
    }
    hex.to_string()
}

#[cfg(target_os = "linux")]
fn get_linux_inode_process_map() -> HashMap<u64, (Option<String>, Option<u32>)> {
    let mut map = HashMap::new();
    if let Ok(entries) = std::fs::read_dir("/proc") {
        for entry in entries.flatten() {
            if let Ok(name) = entry.file_name().into_string() {
                if let Ok(pid) = name.parse::<u32>() {
                    let comm = std::fs::read_to_string(format!("/proc/{pid}/comm"))
                        .map(|s| s.trim().to_string())
                        .ok();

                    let fd_dir = format!("/proc/{pid}/fd");
                    if let Ok(fds) = std::fs::read_dir(&fd_dir) {
                        for fd in fds.flatten() {
                            if let Ok(target) = std::fs::read_link(fd.path()) {
                                let s = target.to_string_lossy();
                                if let Some(stripped) = s.strip_prefix("socket:[") {
                                    if let Some(inode_str) = stripped.strip_suffix(']') {
                                        if let Ok(inode) = inode_str.parse::<u64>() {
                                            map.insert(inode, (comm.clone(), Some(pid)));
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    map
}

#[cfg(target_os = "macos")]
pub fn get_macos_sockets() -> Result<Vec<ListeningSocket>> {
    let output = Command::new("lsof")
        .args(["-iTCP", "-sTCP:LISTEN", "-P", "-n"])
        .output()
        .map_err(|e| PlensError::Other(format!("Failed to execute lsof: {e}")))?;

    let out_str = String::from_utf8_lossy(&output.stdout);
    let mut sockets = Vec::new();

    for line in out_str.lines().skip(1) {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 9 {
            let proc_name = Some(parts[0].to_string());
            let pid = parts[1].parse::<u32>().ok();
            let name_field = parts[8];
            if let Some((ip, port_str)) = name_field.rsplit_once(':') {
                if let Ok(port) = port_str.parse::<u16>() {
                    let is_docker = proc_name
                        .as_deref()
                        .map(|n| n.contains("docker"))
                        .unwrap_or(false);

                    sockets.push(ListeningSocket {
                        protocol: Protocol::Tcp,
                        bind_addr: ip.to_string(),
                        port,
                        pid,
                        process_name: proc_name,
                        inode: None,
                        is_docker,
                    });
                }
            }
        }
    }

    Ok(sockets)
}

pub fn correlate_port_verdict(
    port: u16,
    is_externally_reachable: bool,
    listeners: &[ListeningSocket],
) -> (Option<String>, Option<u32>, Option<String>, PortVerdict) {
    let matching_listener = listeners.iter().find(|l| l.port == port);

    if let Some(listener) = matching_listener {
        let bind = &listener.bind_addr;
        let is_loopback = bind == "127.0.0.1" || bind == "::1" || bind == "localhost";

        let verdict = if is_loopback {
            PortVerdict::LocalOnly
        } else if is_externally_reachable {
            PortVerdict::Exposed
        } else {
            PortVerdict::Filtered
        };

        (
            Some(bind.clone()),
            listener.pid,
            listener.process_name.clone(),
            verdict,
        )
    } else if is_externally_reachable {
        (None, None, None, PortVerdict::Ghost)
    } else {
        (None, None, None, PortVerdict::Filtered)
    }
}
