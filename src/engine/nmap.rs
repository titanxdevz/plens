use crate::error::{PlensError, Result};
use crate::model::{Port, PortState, Protocol, Service};
use quick_xml::events::Event;
use quick_xml::reader::Reader;
use std::collections::HashMap;
use std::process::Stdio;
use tokio::process::Command;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NmapPortInfo {
    pub port: u16,
    pub protocol: Protocol,
    pub state: PortState,
    pub service: Option<Service>,
}

pub fn check_nmap_installed(nmap_binary: &str) -> bool {
    std::process::Command::new(nmap_binary)
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

pub fn build_nmap_args(
    extra_args: &[String],
    open_ports: &[u16],
    target: &str,
) -> Vec<String> {
    let mut args = Vec::new();
    for arg in extra_args {
        args.push(arg.clone());
    }
    let port_str = open_ports
        .iter()
        .map(|p| p.to_string())
        .collect::<Vec<_>>()
        .join(",");
    args.push("-p".to_string());
    args.push(port_str);
    args.push("-oX".to_string());
    args.push("-".to_string());
    args.push("--stats-every".to_string());
    args.push("1s".to_string());
    args.push(target.to_string());
    args
}

pub fn parse_nmap_xml(xml: &str) -> Result<HashMap<u16, NmapPortInfo>> {
    let mut reader = Reader::from_str(xml);
    reader.config_mut().trim_text(true);

    let mut results = HashMap::new();
    let mut current_port: Option<u16> = None;
    let mut current_proto = Protocol::Tcp;
    let mut current_state = PortState::Open;
    let mut current_service: Option<Service> = None;
    let mut in_cpe = false;

    let mut buf = Vec::new();

    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(ref e)) => match e.name().as_ref() {
                b"port" => {
                    current_port = None;
                    current_proto = Protocol::Tcp;
                    current_state = PortState::Open;
                    current_service = None;
                    for attr in e.attributes().flatten() {
                        if attr.key.as_ref() == b"portid" {
                            if let Ok(s) = std::str::from_utf8(&attr.value) {
                                current_port = s.parse::<u16>().ok();
                            }
                        } else if attr.key.as_ref() == b"protocol" {
                            if let Ok(s) = std::str::from_utf8(&attr.value) {
                                if s.eq_ignore_ascii_case("udp") {
                                    current_proto = Protocol::Udp;
                                } else {
                                    current_proto = Protocol::Tcp;
                                }
                            }
                        }
                    }
                }
                b"state" => {
                    for attr in e.attributes().flatten() {
                        if attr.key.as_ref() == b"state" {
                            if let Ok(s) = std::str::from_utf8(&attr.value) {
                                match s.to_ascii_lowercase().as_str() {
                                    "open" => current_state = PortState::Open,
                                    "closed" => current_state = PortState::Closed,
                                    _ => current_state = PortState::Filtered,
                                }
                            }
                        }
                    }
                }
                b"service" => {
                    let mut name = String::new();
                    let mut product = None;
                    let mut version = None;
                    let mut extrainfo = None;

                    for attr in e.attributes().flatten() {
                        match attr.key.as_ref() {
                            b"name" => {
                                if let Ok(s) = std::str::from_utf8(&attr.value) {
                                    name = s.to_string();
                                }
                            }
                            b"product" => {
                                if let Ok(s) = std::str::from_utf8(&attr.value) {
                                    product = Some(s.to_string());
                                }
                            }
                            b"version" => {
                                if let Ok(s) = std::str::from_utf8(&attr.value) {
                                    version = Some(s.to_string());
                                }
                            }
                            b"extrainfo" => {
                                if let Ok(s) = std::str::from_utf8(&attr.value) {
                                    extrainfo = Some(s.to_string());
                                }
                            }
                            _ => {}
                        }
                    }

                    current_service = Some(Service {
                        name,
                        product,
                        version,
                        extra_info: extrainfo,
                        cpe: None,
                    });
                }
                b"cpe" => {
                    in_cpe = true;
                }
                _ => {}
            },
            Ok(Event::Empty(ref e)) => match e.name().as_ref() {
                b"port" => {
                    // Handled similarly if self-closing
                }
                b"state" => {
                    for attr in e.attributes().flatten() {
                        if attr.key.as_ref() == b"state" {
                            if let Ok(s) = std::str::from_utf8(&attr.value) {
                                match s.to_ascii_lowercase().as_str() {
                                    "open" => current_state = PortState::Open,
                                    "closed" => current_state = PortState::Closed,
                                    _ => current_state = PortState::Filtered,
                                }
                            }
                        }
                    }
                }
                b"service" => {
                    let mut name = String::new();
                    let mut product = None;
                    let mut version = None;
                    let mut extrainfo = None;

                    for attr in e.attributes().flatten() {
                        match attr.key.as_ref() {
                            b"name" => {
                                if let Ok(s) = std::str::from_utf8(&attr.value) {
                                    name = s.to_string();
                                }
                            }
                            b"product" => {
                                if let Ok(s) = std::str::from_utf8(&attr.value) {
                                    product = Some(s.to_string());
                                }
                            }
                            b"version" => {
                                if let Ok(s) = std::str::from_utf8(&attr.value) {
                                    version = Some(s.to_string());
                                }
                            }
                            b"extrainfo" => {
                                if let Ok(s) = std::str::from_utf8(&attr.value) {
                                    extrainfo = Some(s.to_string());
                                }
                            }
                            _ => {}
                        }
                    }

                    current_service = Some(Service {
                        name,
                        product,
                        version,
                        extra_info: extrainfo,
                        cpe: None,
                    });
                }
                _ => {}
            },
            Ok(Event::Text(ref e)) => {
                if in_cpe {
                    if let Ok(s) = e.unescape() {
                        if let Some(ref mut srv) = current_service {
                            srv.cpe = Some(s.to_string());
                        }
                    }
                }
            }
            Ok(Event::End(ref e)) => match e.name().as_ref() {
                b"cpe" => in_cpe = false,
                b"port" => {
                    if let Some(port) = current_port {
                        results.insert(
                            port,
                            NmapPortInfo {
                                port,
                                protocol: current_proto,
                                state: current_state,
                                service: current_service.take(),
                            },
                        );
                    }
                }
                _ => {}
            },
            Ok(Event::Eof) => break,
            Err(e) => {
                return Err(PlensError::Other(format!(
                    "XML error during nmap parse: {e}"
                )));
            }
            _ => {}
        }
        buf.clear();
    }

    Ok(results)
}

pub async fn run_nmap_phase2(
    nmap_binary: &str,
    extra_args: &[String],
    open_ports: &[u16],
    target: &str,
) -> Result<Option<HashMap<u16, NmapPortInfo>>> {
    if open_ports.is_empty() {
        return Ok(Some(HashMap::new()));
    }

    if !check_nmap_installed(nmap_binary) {
        return Ok(None);
    }

    let args = build_nmap_args(extra_args, open_ports, target);

    let mut cmd = Command::new(nmap_binary);
    cmd.args(&args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);

    let child = cmd.spawn().map_err(|e| PlensError::Network {
        message: format!("Failed to spawn nmap process: {e}"),
    })?;

    // Subprocess execution timeout (B.1, B.4)
    let timeout = std::time::Duration::from_secs(120);
    let output = match tokio::time::timeout(timeout, child.wait_with_output()).await {
        Ok(Ok(out)) => out,
        Ok(Err(e)) => {
            return Err(PlensError::Network {
                message: format!("nmap process failed: {e}"),
            });
        }
        Err(_) => {
            return Err(PlensError::Other("nmap process execution timed out after 120s".into()));
        }
    };

    let stdout_str = String::from_utf8_lossy(&output.stdout);
    let parsed = parse_nmap_xml(&stdout_str)?;
    Ok(Some(parsed))
}

pub fn enrich_ports_with_nmap(
    ports: &mut [Port],
    nmap_results: &HashMap<u16, NmapPortInfo>,
) {
    for port in ports.iter_mut() {
        if let Some(info) = nmap_results.get(&port.number) {
            port.state = info.state;
            if info.service.is_some() {
                port.service = info.service.clone();
            }
        }
    }
}
