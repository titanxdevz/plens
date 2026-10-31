use crate::engine::ScanEvent;
use crate::error::Result;
use crate::model::{Port, ScanPlan, ScanSummary};
use crate::render::table::{format_severity_badge, render_summary_card};
use crossterm::event::{self, Event, KeyCode};
use futures::{Stream, StreamExt};
use is_terminal::IsTerminal;
use std::io::{stdout, Write};
use std::time::Duration;

pub struct LiveRunner {
    pub no_color: bool,
}

impl LiveRunner {
    pub fn new(no_color: bool) -> Self {
        Self { no_color }
    }

    pub async fn run_live_stream<S>(
        &self,
        plan: &ScanPlan,
        mut stream: S,
    ) -> Result<Option<Box<ScanSummary>>>
    where
        S: Stream<Item = ScanEvent> + Unpin,
    {
        let is_tty = stdout().is_terminal() && !self.no_color;

        if !is_tty {
            return self.run_plain_stream(plan, stream).await;
        }

        println!("PortLens live exposure audit");
        println!(
            "Target: {} | Preset: {} | Profile: {}",
            plan.target,
            plan.preset,
            plan.profile.as_deref().unwrap_or("none")
        );
        println!("Controls: [p] pause  [c] cancel  [d] details  [q] quit");
        println!("{:-<60}", "");

        let mut discovered_ports: Vec<Port> = Vec::new();
        let mut final_summary: Option<Box<ScanSummary>> = None;
        let mut paused = false;

        loop {
            // Check for keyboard interaction
            if event::poll(Duration::from_millis(20)).unwrap_or(false) {
                if let Ok(Event::Key(key)) = event::read() {
                    match key.code {
                        KeyCode::Char('q') => {
                            println!("\nScan aborted by user.");
                            return Ok(final_summary);
                        }
                        KeyCode::Char('c') => {
                            println!("\nCancelling scan... Saving partial results.");
                            if let Some(ref mut s) = final_summary {
                                s.partial = true;
                            }
                            return Ok(final_summary);
                        }
                        KeyCode::Char('p') => {
                            paused = !paused;
                            if paused {
                                println!("\n[Scan PAUSED - press 'p' to resume]");
                            } else {
                                println!("\n[Scan RESUMED]");
                            }
                        }
                        KeyCode::Char('d') => {
                            println!(
                                "\nDiscovered {} ports so far on target {}",
                                discovered_ports.len(),
                                plan.target
                            );
                        }
                        _ => {}
                    }
                }
            }

            if paused {
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            }

            tokio::select! {
                _ = tokio::signal::ctrl_c() => {
                    println!("\n[!] Ctrl+C received: Gracefully stopping scan and saving partial results...");
                    let partial = ScanSummary {
                        scan_id: uuid::Uuid::new_v4().to_string(),
                        targets: vec![plan.target.clone()],
                        start_time: chrono::Utc::now(),
                        end_time: chrono::Utc::now(),
                        duration_ms: 0,
                        preset: plan.preset.clone(),
                        profile: plan.profile.clone(),
                        hosts: vec![crate::model::Host {
                            id: uuid::Uuid::new_v4().to_string(),
                            target: plan.target.clone(),
                            ip: None,
                            hostname: Some(plan.target.clone()),
                            ports: discovered_ports,
                            listening_sockets: Vec::new(),
                            is_up: true,
                        }],
                        findings: Vec::new(),
                        risk_score: crate::model::RiskScore {
                            score: 0,
                            grade: "N/A".into(),
                            previous_score: None,
                            trend_description: None,
                            formula: String::new(),
                        },
                        partial: true,
                    };
                    final_summary = Some(Box::new(partial));
                    break;
                }
                next_event = stream.next() => {
                    match next_event {
                        Some(ScanEvent::HostUp(h)) => {
                            println!("Target {} is UP", h.target);
                        }
                        Some(ScanEvent::PortFound { host: _, port }) => {
                            print!("\rFound open port: {}   \n", port);
                            let _ = stdout().flush();
                            discovered_ports.push(Port {
                                number: port,
                                protocol: crate::model::Protocol::Tcp,
                                state: crate::model::PortState::Open,
                                service: None,
                                probe_result: None,
                                bind_addr: None,
                                process_name: None,
                                pid: None,
                                verdict: None,
                                confirmed: true,
                            });
                        }
                        Some(ScanEvent::Progress { pct, eta }) => {
                            let eta_str = eta.unwrap_or_default();
                            print!("\rProgress: [{:>3.0}%] {} ", pct * 100.0, eta_str);
                            let _ = stdout().flush();
                        }
                        Some(ScanEvent::ProbeResult { host: _, port, result }) => {
                            let status_badge = if result.verified_insecure {
                                format_severity_badge(crate::model::Severity::Critical, self.no_color)
                            } else {
                                format_severity_badge(crate::model::Severity::Info, self.no_color)
                            };
                            println!("\n{} Port {}: {} - {}", status_badge, port, result.service, result.details);
                        }
                        Some(ScanEvent::Warning(w)) => {
                            println!("\n[!] Warning: {}", w);
                        }
                        Some(ScanEvent::HostDone(h)) => {
                            println!("\nHost {} scan completed.", h);
                        }
                        Some(ScanEvent::Finished(summary)) => {
                            final_summary = Some(summary);
                            break;
                        }
                        None => break,
                    }
                }
            }
        }

        if let Some(ref summary) = final_summary {
            println!("{}", render_summary_card(summary, self.no_color));
        }

        Ok(final_summary)
    }

    async fn run_plain_stream<S>(
        &self,
        plan: &ScanPlan,
        mut stream: S,
    ) -> Result<Option<Box<ScanSummary>>>
    where
        S: Stream<Item = ScanEvent> + Unpin,
    {
        println!("PortLens Exposure Audit: Target {}", plan.target);
        let mut final_summary: Option<Box<ScanSummary>> = None;
        let mut discovered_ports: Vec<Port> = Vec::new();

        loop {
            tokio::select! {
                _ = tokio::signal::ctrl_c() => {
                    println!("\n[!] Ctrl+C received: Gracefully stopping scan and saving partial results...");
                    let partial = ScanSummary {
                        scan_id: uuid::Uuid::new_v4().to_string(),
                        targets: vec![plan.target.clone()],
                        start_time: chrono::Utc::now(),
                        end_time: chrono::Utc::now(),
                        duration_ms: 0,
                        preset: plan.preset.clone(),
                        profile: plan.profile.clone(),
                        hosts: vec![crate::model::Host {
                            id: uuid::Uuid::new_v4().to_string(),
                            target: plan.target.clone(),
                            ip: None,
                            hostname: Some(plan.target.clone()),
                            ports: discovered_ports,
                            listening_sockets: Vec::new(),
                            is_up: true,
                        }],
                        findings: Vec::new(),
                        risk_score: crate::model::RiskScore {
                            score: 0,
                            grade: "N/A".into(),
                            previous_score: None,
                            trend_description: None,
                            formula: String::new(),
                        },
                        partial: true,
                    };
                    final_summary = Some(Box::new(partial));
                    break;
                }
                event = stream.next() => {
                    match event {
                        Some(ScanEvent::HostUp(h)) => {
                            println!("[+] Host {} is up", h.target);
                        }
                        Some(ScanEvent::PortFound { port, .. }) => {
                            println!("[+] Port {} is open", port);
                            discovered_ports.push(Port {
                                number: port,
                                protocol: crate::model::Protocol::Tcp,
                                state: crate::model::PortState::Open,
                                service: None,
                                probe_result: None,
                                bind_addr: None,
                                process_name: None,
                                pid: None,
                                verdict: None,
                                confirmed: true,
                            });
                        }
                        Some(ScanEvent::Progress { pct, eta }) => {
                            if let Some(e) = eta {
                                println!("[*] {:.0}% - {}", pct * 100.0, e);
                            }
                        }
                        Some(ScanEvent::ProbeResult { port, result, .. }) => {
                            println!(
                                "[*] Probe port {}: {} ({})",
                                port, result.service, result.status
                            );
                        }
                        Some(ScanEvent::Warning(w)) => {
                            eprintln!("[!] Warning: {}", w);
                        }
                        Some(ScanEvent::HostDone(h)) => {
                            println!("[+] Completed host {}", h);
                        }
                        Some(ScanEvent::Finished(summary)) => {
                            final_summary = Some(summary);
                            break;
                        }
                        None => break,
                    }
                }
            }
        }

        if let Some(ref summary) = final_summary {
            println!("{}", render_summary_card(summary, true));
        }

        Ok(final_summary)
    }
}
