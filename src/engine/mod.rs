pub mod discover;
pub mod local;
pub mod nmap;

use crate::config::Config;
use crate::engine::discover::{parse_port_specs, run_discovery, DiscoveryConfig};
use crate::engine::local::{correlate_port_verdict, get_local_listening_sockets};
use crate::engine::nmap::{build_nmap_args, check_nmap_installed, enrich_ports_with_nmap, run_nmap_phase2};
use crate::error::{PlensError, Result};
use crate::model::{Host, Port, ProbeResult, RiskScore, ScanPlan, ScanSummary};
use crate::probe::run_probe;
use crate::risk::{evaluate_findings, load_rules};
use async_stream::stream;
use chrono::Utc;
use futures::Stream;
use std::time::{Duration, Instant};
use tokio::sync::mpsc;
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct ScanRequest {
    pub targets: Vec<String>,
    pub preset: String,
    pub profile: Option<String>,
    pub custom_ports: Option<String>,
    pub speed: Option<u8>,
    pub no_probe: bool,
    pub raw_args: Option<String>,
}

#[derive(Debug, Clone)]
pub enum ScanEvent {
    HostUp(Host),
    PortFound {
        host: String,
        port: u16,
    },
    Progress {
        pct: f32,
        eta: Option<String>,
    },
    ProbeResult {
        host: String,
        port: u16,
        result: ProbeResult,
    },
    HostDone(String),
    Warning(String),
    Finished(Box<ScanSummary>),
}

pub trait ScanEngine: Send + Sync {
    fn plan(&self, req: &ScanRequest) -> Result<ScanPlan>;
    fn run(&self, plan: ScanPlan) -> impl Stream<Item = ScanEvent> + Send;
}

#[derive(Debug, Clone)]
pub struct PresetConfig {
    pub name: String,
    pub ports: String,
    pub concurrency: usize,
    pub timeout_ms: u64,
    pub rate_limit: usize,
    pub phase2_enabled: bool,
    pub phase2_args: Vec<String>,
}

pub fn get_preset_config(preset: &str, speed: Option<u8>) -> Result<PresetConfig> {
    let mut cfg = match preset.to_lowercase().as_str() {
        "quick" => PresetConfig {
            name: "quick".to_string(),
            ports: "top100".to_string(),
            concurrency: 1000,
            timeout_ms: 600,
            rate_limit: 0,
            phase2_enabled: false,
            phase2_args: Vec::new(),
        },
        "standard" => PresetConfig {
            name: "standard".to_string(),
            ports: "top1000".to_string(),
            concurrency: 1000,
            timeout_ms: 800,
            rate_limit: 0,
            phase2_enabled: true,
            phase2_args: vec![
                "-n".to_string(),
                "-Pn".to_string(),
                "-sV".to_string(),
                "--version-intensity".to_string(),
                "2".to_string(),
            ],
        },
        "full" => PresetConfig {
            name: "full".to_string(),
            ports: "1-65535".to_string(),
            concurrency: 1000,
            timeout_ms: 800,
            rate_limit: 0,
            phase2_enabled: true,
            phase2_args: vec![
                "-n".to_string(),
                "-Pn".to_string(),
                "-sV".to_string(),
                "-sC".to_string(),
                "--version-intensity".to_string(),
                "7".to_string(),
            ],
        },
        "stealth" => PresetConfig {
            name: "stealth".to_string(),
            ports: "top1000".to_string(),
            concurrency: 50,
            timeout_ms: 1500,
            rate_limit: 50,
            phase2_enabled: true,
            phase2_args: vec!["-sS".to_string(), "-T2".to_string(), "-f".to_string()],
        },
        "web" => PresetConfig {
            name: "web".to_string(),
            ports: "80,443,8000-9000".to_string(),
            concurrency: 500,
            timeout_ms: 1000,
            rate_limit: 0,
            phase2_enabled: true,
            phase2_args: vec![
                "-sV".to_string(),
                "--script".to_string(),
                "http-title,http-headers,ssl-cert".to_string(),
            ],
        },
        "udp" => PresetConfig {
            name: "udp".to_string(),
            ports: "top50udp".to_string(),
            concurrency: 100,
            timeout_ms: 1500,
            rate_limit: 100,
            phase2_enabled: true,
            phase2_args: vec!["-sU".to_string(), "-sV".to_string()],
        },
        other => {
            return Err(PlensError::PresetNotFound {
                name: other.to_string(),
            });
        }
    };

    if let Some(spd) = speed {
        match spd {
            1 => {
                cfg.concurrency = 50;
                cfg.timeout_ms = 1500;
                cfg.rate_limit = 20;
            }
            2 => {
                cfg.concurrency = 200;
                cfg.timeout_ms = 1200;
                cfg.rate_limit = 100;
            }
            3 => {
                cfg.concurrency = 500;
                cfg.timeout_ms = 900;
                cfg.rate_limit = 500;
            }
            4 => {
                cfg.concurrency = 1000;
                cfg.timeout_ms = 700;
                cfg.rate_limit = 0;
            }
            5 => {
                cfg.concurrency = 2000;
                cfg.timeout_ms = 500;
                cfg.rate_limit = 0;
            }
            _ => {}
        }
    }

    Ok(cfg)
}

#[derive(Debug, Clone)]
pub struct DefaultScanEngine {
    pub config: Config,
}

impl DefaultScanEngine {
    pub fn new(config: Config) -> Self {
        Self { config }
    }
}

impl ScanEngine for DefaultScanEngine {
    fn plan(&self, req: &ScanRequest) -> Result<ScanPlan> {
        let preset_cfg = get_preset_config(&req.preset, req.speed)?;
        let ports_spec = req
            .custom_ports
            .as_deref()
            .unwrap_or(&preset_cfg.ports)
            .to_string();

        let target_str = req.targets.first().cloned().unwrap_or_default();
        let phase2_cmd = if preset_cfg.phase2_enabled {
            let parsed_ports = parse_port_specs(&ports_spec).unwrap_or_default();
            let mut sample_ports: Vec<u16> = parsed_ports.into_iter().take(5).collect();
            if sample_ports.is_empty() {
                sample_ports = vec![80, 443];
            }
            let args = build_nmap_args(&preset_cfg.phase2_args, &sample_ports, &target_str);
            Some(format!("nmap {}", args.join(" ")))
        } else {
            None
        };

        Ok(ScanPlan {
            target: target_str,
            preset: req.preset.clone(),
            profile: req.profile.clone(),
            phase1_ports: ports_spec,
            phase1_concurrency: preset_cfg.concurrency,
            phase1_timeout_ms: preset_cfg.timeout_ms,
            phase2_enabled: preset_cfg.phase2_enabled,
            phase2_command: phase2_cmd,
            probes_enabled: !req.no_probe,
        })
    }

    fn run(&self, plan: ScanPlan) -> impl Stream<Item = ScanEvent> + Send {
        let nmap_binary = self.config.nmap_path.clone();
        stream! {
            let start_instant = Instant::now();
            let start_time = Utc::now();
            let scan_id = Uuid::new_v4().to_string();

            let target = plan.target.clone();
            let host_initial = Host {
                id: Uuid::new_v4().to_string(),
                target: target.clone(),
                ip: None,
                hostname: Some(target.clone()),
                ports: Vec::new(),
                listening_sockets: Vec::new(),
                is_up: true,
            };

            yield ScanEvent::HostUp(host_initial);
            yield ScanEvent::Progress { pct: 0.05, eta: Some("Discovering open ports...".to_string()) };

            let preset_cfg = match get_preset_config(&plan.preset, None) {
                Ok(c) => c,
                Err(e) => {
                    yield ScanEvent::Warning(e.to_string());
                    return;
                }
            };

            let port_list = match parse_port_specs(&plan.phase1_ports) {
                Ok(p) => p,
                Err(e) => {
                    yield ScanEvent::Warning(e.to_string());
                    return;
                }
            };

            let (tx, mut rx) = mpsc::channel::<Port>(1024);
            let disc_cfg = DiscoveryConfig {
                target: target.clone(),
                ports: port_list.clone(),
                concurrency: plan.phase1_concurrency,
                per_host_cap: 500,
                timeout: Duration::from_millis(plan.phase1_timeout_ms),
                retry: true,
                rate_limit: preset_cfg.rate_limit,
                aimd: true,
                aimd_settings: crate::engine::discover::AimdSettings::default(),
                rtt_clamp: None,
            };

            let disc_handle = tokio::spawn(async move {
                run_discovery(disc_cfg, tx).await
            });

            let resolved_target = discover::resolve_target(&target).await.ok();
            let target_ip = resolved_target.map(|a| a.ip());

            let (probe_tx, mut probe_rx) = mpsc::channel::<(u16, ProbeResult)>(1024);
            let mut active_probes = tokio::task::JoinSet::new();

            let mut discovered_ports: Vec<Port> = Vec::new();
            while let Some(port) = rx.recv().await {
                yield ScanEvent::PortFound { host: target.clone(), port: port.number };

                // Spawn probes the moment a port is confirmed open (A.7, B.5)
                if plan.probes_enabled {
                    if let Some(ip) = target_ip {
                        let ptx = probe_tx.clone();
                        let pnum = port.number;
                        active_probes.spawn(async move {
                            // Isolate probe in task and catch panics so one probe cannot kill a scan
                            let probe_task = std::panic::AssertUnwindSafe(async {
                                run_probe(ip, pnum, None, None).await
                            });
                            if let Ok(Some(res)) = futures::FutureExt::catch_unwind(probe_task).await {
                                let _ = ptx.send((pnum, res)).await;
                            }
                        });
                    }
                }

                // Drain any probe results available immediately
                while let Ok((p_num, probe_res)) = probe_rx.try_recv() {
                    yield ScanEvent::ProbeResult {
                        host: target.clone(),
                        port: p_num,
                        result: probe_res.clone(),
                    };
                    if let Some(p) = discovered_ports.iter_mut().find(|p| p.number == p_num) {
                        p.probe_result = Some(probe_res);
                    }
                }

                discovered_ports.push(port);
            }

            let _ = disc_handle.await;
            yield ScanEvent::Progress { pct: 0.50, eta: Some("Phase 1 complete. Inspecting open services...".to_string()) };

            // Wait for remaining probes launched during phase 1
            while let Some(join_res) = active_probes.join_next().await {
                let _ = join_res;
            }
            while let Ok((p_num, probe_res)) = probe_rx.try_recv() {
                yield ScanEvent::ProbeResult {
                    host: target.clone(),
                    port: p_num,
                    result: probe_res.clone(),
                };
                if let Some(p) = discovered_ports.iter_mut().find(|p| p.number == p_num) {
                    p.probe_result = Some(probe_res);
                }
            }

            // Phase 2: nmap deep inspection
            let open_port_nums: Vec<u16> = discovered_ports.iter().map(|p| p.number).collect();
            if preset_cfg.phase2_enabled && !open_port_nums.is_empty() {
                if check_nmap_installed(&nmap_binary) {
                    match run_nmap_phase2(&nmap_binary, &preset_cfg.phase2_args, &open_port_nums, &target).await {
                        Ok(Some(nmap_map)) => {
                            enrich_ports_with_nmap(&mut discovered_ports, &nmap_map);
                        }
                        Ok(None) => {
                            yield ScanEvent::Warning("nmap not found; skipping phase 2 deep inspection and falling back to banner probes".to_string());
                        }
                        Err(e) => {
                            yield ScanEvent::Warning(format!("nmap phase 2 execution error: {e}"));
                        }
                    }
                } else {
                    yield ScanEvent::Warning("nmap not found on PATH. Phase 2 deep service inspection skipped. Install nmap or use '--preset quick'.".to_string());
                }
            }

            // Phase 3: Additional targeted probes for ports that gained service hints from nmap
            if plan.probes_enabled && !discovered_ports.is_empty() {
                if let Some(ip) = target_ip {
                    for port in &mut discovered_ports {
                        if port.probe_result.is_none() {
                            let hint = port.service.as_ref().map(|s| s.name.as_str());
                            if let Some(probe_res) = run_probe(ip, port.number, hint, None).await {
                                yield ScanEvent::ProbeResult {
                                    host: target.clone(),
                                    port: port.number,
                                    result: probe_res.clone(),
                                };
                                port.probe_result = Some(probe_res);
                            }
                        }
                    }
                }
            }

            // Local correlation if scanning localhost
            let is_local = target == "127.0.0.1" || target == "localhost" || target == "::1";
            let mut listening_sockets = Vec::new();
            if is_local {
                if let Ok(sockets) = get_local_listening_sockets() {
                    listening_sockets = sockets.clone();
                    for port in &mut discovered_ports {
                        let (bind, pid, proc_name, verdict) = correlate_port_verdict(port.number, true, &sockets);
                        port.bind_addr = bind;
                        port.pid = pid;
                        port.process_name = proc_name;
                        port.verdict = Some(verdict);
                    }
                }
            } else {
                for port in &mut discovered_ports {
                    if port.verdict.is_none() {
                        port.verdict = Some(crate::model::PortVerdict::Exposed);
                    }
                }
            }

            yield ScanEvent::Progress { pct: 0.90, eta: Some("Evaluating risk rules and security posture...".to_string()) };

            let final_host = Host {
                id: Uuid::new_v4().to_string(),
                target: target.clone(),
                ip: None,
                hostname: Some(target.clone()),
                ports: discovered_ports,
                listening_sockets,
                is_up: true,
            };

            let rules = load_rules(None).unwrap_or_default();
            let mut findings = evaluate_findings(&final_host, &rules);

            if let Some(ref prof_name) = plan.profile {
                if let Ok(prof) = crate::profile::load_profile(prof_name, None) {
                    let prof_findings = crate::profile::evaluate_profile_compliance(&final_host, &prof);
                    findings.extend(prof_findings);
                }
            }

            let risk_score = RiskScore::compute(&findings, None);

            yield ScanEvent::HostDone(target.clone());

            let end_time = Utc::now();
            let duration_ms = start_instant.elapsed().as_millis() as u64;

            let summary = ScanSummary {
                scan_id,
                targets: vec![target],
                start_time,
                end_time,
                duration_ms,
                preset: plan.preset,
                profile: plan.profile,
                hosts: vec![final_host],
                findings,
                risk_score,
                partial: false,
            };

            yield ScanEvent::Finished(Box::new(summary));
        }
    }
}
