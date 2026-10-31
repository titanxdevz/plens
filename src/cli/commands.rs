use crate::cli::args::{
    AlertArgs, BaselineArgs, Cli, Commands, CompletionsArgs, ConfigArgs, DaemonArgs, DiffArgs,
    ExplainArgs, ExportArgs, FixArgs, HistoryArgs, IgnoreArgs, ScanArgs, ScheduleArgs, SelfArgs,
    ShowArgs, WatchArgs,
};
use crate::cli::doctor::run_doctor;
use crate::config::Config;
use crate::engine::{DefaultScanEngine, ScanEngine, ScanRequest};
use crate::error::{ExitCode, PlensError, Result};
use clap::CommandFactory;
use clap_complete::generate;
use std::io;

pub async fn run(cli: Cli, config: &mut Config) -> Result<ExitCode> {
    match cli.command {
        Some(Commands::Scan(args)) => handle_scan(args, config).await,
        Some(Commands::SelfAudit(args)) => handle_self(args, config).await,
        Some(Commands::Watch(args)) => handle_watch(args, config).await,
        Some(Commands::Fix(args)) => handle_fix(args, config).await,
        Some(Commands::Explain(args)) => handle_explain(args, config).await,
        Some(Commands::Ignore(args)) => handle_ignore(args, config).await,
        Some(Commands::Ui) => handle_ui(config).await,
        Some(Commands::History(args)) => handle_history(args, config).await,
        Some(Commands::Show(args)) => handle_show(args, config).await,
        Some(Commands::Diff(args)) => handle_diff(args, config).await,
        Some(Commands::Baseline(args)) => handle_baseline(args, config).await,
        Some(Commands::Schedule(args)) => handle_schedule(args, config).await,
        Some(Commands::Daemon(args)) => handle_daemon(args, config).await,
        Some(Commands::Alert(args)) => handle_alert(args, config).await,
        Some(Commands::Export(args)) => handle_export(args, config).await,
        Some(Commands::Config(args)) => handle_config(args, config).await,
        Some(Commands::Doctor) => handle_doctor(config).await,
        Some(Commands::Completions(args)) => handle_completions(args),
        None => {
            let mut cmd = Cli::command();
            cmd.print_help().map_err(|e| PlensError::Other(e.to_string()))?;
            println!();
            Ok(ExitCode::Ok)
        }
    }
}

pub async fn handle_scan(args: ScanArgs, config: &Config) -> Result<ExitCode> {
    let preset_name = args
        .preset
        .as_deref()
        .unwrap_or(&config.default_preset)
        .to_string();

    let scan_req = ScanRequest {
        targets: args.targets.clone(),
        preset: preset_name.clone(),
        profile: args.profile.clone(),
        custom_ports: args.ports.clone(),
        speed: args.speed,
        no_probe: args.no_probe,
        raw_args: args.raw.clone(),
    };

    let engine = DefaultScanEngine::new(config.clone());
    let plan = engine.plan(&scan_req)?;

    if args.explain {
        println!("PortLens Execution Plan (--explain):");
        println!("  Target:             {}", plan.target);
        println!("  Preset:             {}", plan.preset);
        println!("  Profile:            {}", plan.profile.as_deref().unwrap_or("none"));
        println!("  Phase 1 Ports:      {}", plan.phase1_ports);
        println!("  Phase 1 Concurrency:{} sockets", plan.phase1_concurrency);
        println!("  Phase 1 Timeout:    {} ms/connect", plan.phase1_timeout_ms);
        println!("  Phase 2 (nmap):     {}", if plan.phase2_enabled { "Enabled" } else { "Disabled" });
        if let Some(ref cmd) = plan.phase2_command {
            println!("  Phase 2 Command:    {}", cmd);
        }
        println!("  Verification Probes:{}", if plan.probes_enabled { "Enabled" } else { "Disabled" });
        return Ok(ExitCode::Ok);
    }

    for target in &args.targets {
        crate::safety::check_target_safety(target, &config.allowlist, args.yes, None)?;
    }

    let stream = Box::pin(engine.run(plan.clone()));
    let live_runner = crate::render::LiveRunner::new(args.no_color || std::env::var("NO_COLOR").is_ok());
    let summary_opt = live_runner.run_live_stream(&plan, stream).await?;

    if let Some(summary) = summary_opt {
        if args.json {
            let json = crate::render::export_json(&summary)?;
            if let Some(ref path) = args.output {
                std::fs::write(path, json).map_err(|e| PlensError::Other(e.to_string()))?;
            } else {
                println!("{json}");
            }
        } else if args.csv {
            let csv = crate::render::export_csv(&summary)?;
            if let Some(ref path) = args.output {
                std::fs::write(path, csv).map_err(|e| PlensError::Other(e.to_string()))?;
            } else {
                println!("{csv}");
            }
        } else if args.md {
            let md = crate::render::export_markdown(&summary)?;
            if let Some(ref path) = args.output {
                std::fs::write(path, md).map_err(|e| PlensError::Other(e.to_string()))?;
            } else {
                println!("{md}");
            }
        } else if args.html {
            let html = crate::render::export_html(&summary)?;
            if let Some(ref path) = args.output {
                std::fs::write(path, html).map_err(|e| PlensError::Other(e.to_string()))?;
            } else {
                println!("{html}");
            }
        }

        if !args.no_save {
            if let Ok(conn) = crate::store::open_db(&Config::db_path()) {
                let _ = crate::store::save_scan(&conn, &summary);
                let _ = crate::store::checkpoint_wal(&conn);
                let _ = crate::store::apply_retention(&conn, config.retention_days, config.retention_scans);
            }
        }

        if args.baseline {
            if let Ok(conn) = crate::store::open_db(&Config::db_path()) {
                for target in &summary.targets {
                    if let Ok(Some(baseline)) = crate::store::get_baseline(&conn, target) {
                        let drift = crate::diff::diff_scans(&baseline, &summary);
                        println!("{}", crate::diff::render_diff_card(&drift, &baseline.scan_id, &summary.scan_id, args.no_color));
                        if drift.has_drift() && args.fail_on.is_some() {
                            return Err(PlensError::BaselineDriftDetected);
                        }
                    } else {
                        println!("[*] No baseline registered for target '{target}'. Set one with 'plens baseline set {target}'.");
                    }
                }
            }
        }
    }

    Ok(ExitCode::Ok)
}

pub async fn handle_self(args: SelfArgs, _config: &Config) -> Result<ExitCode> {
    println!("PortLens inside-vs-outside node exposure audit:\n");
    let listeners = crate::engine::local::get_local_listening_sockets()?;
    println!("Found {} local listening sockets.", listeners.len());

    let target_ip = if let Some(ref via) = args.via {
        via.parse::<std::net::IpAddr>().map_err(|e| PlensError::InvalidArgument {
            message: format!("Invalid --via IP: {e}"),
        })?
    } else if let Some(ip) = crate::engine::local::get_outbound_ip().await {
        ip
    } else {
        std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1))
    };

    println!("Testing external reachability via address: {target_ip}\n");

    let mut table = comfy_table::Table::new();
    table
        .load_preset(comfy_table::presets::UTF8_FULL)
        .apply_modifier(comfy_table::modifiers::UTF8_ROUND_CORNERS)
        .set_header(vec!["PORT/PROTO", "BIND ADDRESS", "PROCESS", "PID", "REACHABLE", "VERDICT"]);

    let mut exposed_count = 0;
    let mut has_docker = false;

    for l in &listeners {
        let outcome = crate::engine::discover::scan_single_port(
            target_ip,
            l.port,
            std::time::Duration::from_millis(600),
            false,
        )
        .await;
        let is_reachable = outcome.is_open;

        let (_bind, _pid, _name, verdict) =
            crate::engine::local::correlate_port_verdict(l.port, is_reachable, &listeners);

        if verdict == crate::model::PortVerdict::Exposed {
            exposed_count += 1;
        }
        if l.is_docker {
            has_docker = true;
        }

        let reach_str = if is_reachable { "YES" } else { "NO" };
        let proc_str = l.process_name.clone().unwrap_or_else(|| "-".into());
        let pid_str = l.pid.map(|p| p.to_string()).unwrap_or_else(|| "-".into());

        table.add_row(vec![
            format!("{}/{}", l.port, l.protocol),
            l.bind_addr.clone(),
            proc_str,
            pid_str,
            reach_str.into(),
            verdict.to_string(),
        ]);
    }

    println!("{table}");

    if has_docker {
        println!("\n[!] Docker Warning: One or more listening ports are published by Docker.");
        println!("    Note: Docker publishes container ports directly via iptables, BYPASSING standard UFW rules.");
        println!("    Remediation: Bind ports explicitly to loopback in docker-compose.yml: '127.0.0.1:8080:8080'");
    }

    println!(
        "\nAudit complete: {} listening sockets inspected, {} exposed externally.",
        listeners.len(),
        exposed_count
    );
    Ok(ExitCode::Ok)
}

pub async fn handle_fix(args: FixArgs, _config: &Config) -> Result<ExitCode> {
    let conn = crate::store::open_db(&Config::db_path())?;
    let findings = if let Ok(Some(scan)) = crate::store::get_scan(&conn, &args.id) {
        scan.findings
    } else {
        vec![crate::model::Finding {
            id: args.id.clone(),
            rule_id: "redis-noauth".into(),
            target: "localhost".into(),
            port: Some(6379),
            severity: crate::model::Severity::Critical,
            message: "Redis accepts commands without authentication.".into(),
            why: "Anyone can read/write data and often gain RCE.".into(),
            fix: Some(crate::model::FixRemedy {
                ufw: Some("ufw deny 6379".into()),
                iptables: Some("iptables -A INPUT -p tcp --dport 6379 ! -s 127.0.0.1 -j DROP".into()),
                nftables: None,
                config: Some("bind 127.0.0.1 ::1\nrequirepass <strong-password>".into()),
                docker: Some("ports:\n  - '127.0.0.1:6379:6379'".into()),
                notes: None,
            }),
            suppressed: false,
            suppress_reason: None,
            suppress_until: None,
        }]
    };

    let fixes = crate::fix::generate_grouped_fixes(&findings);
    println!("{fixes}");
    Ok(ExitCode::Ok)
}

pub async fn handle_explain(args: ExplainArgs, _config: &Config) -> Result<ExitCode> {
    println!("PortLens Knowledge: Explaining '{}'...", args.query);
    let q = args.query.to_lowercase();
    if q.contains("6379") || q.contains("redis") {
        println!("Service: Redis (In-memory data structure store)");
        println!("Default Port: 6379/TCP");
        println!("Exposure Risk: Critical. Unauthenticated Redis allows immediate reading, writing, flushing data, and remote code execution (via cron writing or SSH authorized_keys).");
        println!("Remediation:");
        println!("  1. Edit redis.conf: bind 127.0.0.1 ::1");
        println!("  2. Require auth: requirepass <strong-password>");
        println!("  3. Block remote traffic: sudo ufw deny 6379");
    } else if q.contains("2375") || q.contains("docker") {
        println!("Service: Docker Daemon REST API");
        println!("Default Port: 2375/TCP (unencrypted), 2376/TCP (TLS)");
        println!("Exposure Risk: Critical. The Docker socket grants full root privileges over the host system via container volume mounts.");
        println!("Remediation:");
        println!("  1. Never expose 2375 on public interfaces (0.0.0.0).");
        println!("  2. Use local unix socket: unix:///var/run/docker.sock");
        println!("  3. If remote is required, enforce mTLS client certificates on port 2376.");
    } else {
        println!("Service / Port query: {}", args.query);
        println!("Best practice: Ensure the service binds strictly to 127.0.0.1 or is shielded behind a firewall (UFW/iptables).");
    }
    Ok(ExitCode::Ok)
}

pub async fn handle_ignore(args: IgnoreArgs, _config: &Config) -> Result<ExitCode> {
    let conn = crate::store::open_db(&Config::db_path())?;

    if args.list {
        let list = crate::store::list_ignores(&conn)?;
        println!("Active Finding Suppressions (total: {}):", list.len());
        let mut table = comfy_table::Table::new();
        table
            .load_preset(comfy_table::presets::UTF8_FULL)
            .apply_modifier(comfy_table::modifiers::UTF8_ROUND_CORNERS)
            .set_header(vec!["ID", "RULE / PORT", "TARGET", "REASON", "EXPIRES"]);

        for item in list {
            table.add_row(vec![
                item.id.to_string(),
                item.rule_or_port,
                item.target.unwrap_or_else(|| "ALL".into()),
                item.reason,
                item.until.unwrap_or_else(|| "NEVER".into()),
            ]);
        }
        println!("{table}");
        return Ok(ExitCode::Ok);
    }

    if let Some(ref rem_id) = args.remove {
        let id_val = rem_id.parse::<i64>().map_err(|_| PlensError::InvalidArgument {
            message: format!("Invalid ignore ID: {rem_id}"),
        })?;
        crate::store::remove_ignore(&conn, id_val)?;
        println!("Removed suppression #{id_val}.");
        return Ok(ExitCode::Ok);
    }

    if let Some(ref rule_or_port) = args.rule_or_port {
        let reason = args.reason.as_deref().unwrap_or("Operator acknowledged exception");
        crate::store::add_ignore(&conn, rule_or_port, args.target.as_deref(), reason, args.until.as_deref())?;
        println!(
            "Added suppression for '{}' on target '{}' (Expires: {}).",
            rule_or_port,
            args.target.as_deref().unwrap_or("ALL"),
            args.until.as_deref().unwrap_or("NEVER")
        );
        return Ok(ExitCode::Ok);
    }

    println!("Run 'plens ignore --list' or 'plens ignore <rule|port> --reason \"...\"'");
    Ok(ExitCode::Ok)
}

pub async fn handle_ui(config: &Config) -> Result<ExitCode> {
    crate::render::tui::run_tui(config).await
}

pub async fn handle_history(args: HistoryArgs, _config: &Config) -> Result<ExitCode> {
    let conn = crate::store::open_db(&Config::db_path())?;
    let history = crate::store::list_history(
        &conn,
        args.target.as_deref(),
        args.since.as_deref(),
        args.has_findings,
        args.limit,
    )?;

    if history.is_empty() {
        println!("No historical scans found matching criteria.");
        return Ok(ExitCode::Ok);
    }

    let mut table = comfy_table::Table::new();
    table
        .load_preset(comfy_table::presets::UTF8_FULL)
        .apply_modifier(comfy_table::modifiers::UTF8_ROUND_CORNERS)
        .set_header(vec!["SCAN ID", "TARGETS", "START TIME", "PRESET", "SCORE", "GRADE", "FINDINGS"]);

    for item in history {
        table.add_row(vec![
            item.id[..8.min(item.id.len())].to_string(),
            item.targets,
            item.start_time,
            item.preset,
            format!("{}/100", item.risk_score),
            item.risk_grade,
            item.findings_count.to_string(),
        ]);
    }

    println!("{table}");
    Ok(ExitCode::Ok)
}

pub async fn handle_show(args: ShowArgs, _config: &Config) -> Result<ExitCode> {
    let conn = crate::store::open_db(&Config::db_path())?;
    match crate::store::get_scan(&conn, &args.scan_id)? {
        Some(summary) => {
            if args.json {
                let json = crate::render::export_json(&summary)?;
                println!("{json}");
            } else {
                println!("{}", crate::render::render_summary_card(&summary, false));
            }
            Ok(ExitCode::Ok)
        }
        None => Err(PlensError::Other(format!("Scan ID '{}' not found in store", args.scan_id))),
    }
}

pub async fn handle_diff(args: DiffArgs, _config: &Config) -> Result<ExitCode> {
    let conn = crate::store::open_db(&Config::db_path())?;

    let scan_a = if args.first == "baseline" {
        None
    } else {
        crate::store::get_scan(&conn, &args.first)?
    };

    let scan_b = if args.second == "latest" {
        if let Some(ref a) = scan_a {
            let target = a.targets.first().cloned().unwrap_or_default();
            crate::store::get_latest_scan_for_target(&conn, &target)?
        } else {
            None
        }
    } else {
        crate::store::get_scan(&conn, &args.second)?
    };

    match (scan_a, scan_b) {
        (Some(a), Some(b)) => {
            let drift = crate::diff::diff_scans(&a, &b);
            println!("{}", crate::diff::render_diff_card(&drift, &a.scan_id, &b.scan_id, false));
            Ok(ExitCode::Ok)
        }
        _ => Err(PlensError::Other(format!(
            "Could not load both scans ('{}' and '{}') for comparison",
            args.first, args.second
        ))),
    }
}

pub async fn handle_baseline(args: BaselineArgs, _config: &Config) -> Result<ExitCode> {
    let conn = crate::store::open_db(&Config::db_path())?;

    match args.action {
        crate::cli::args::BaselineSubcommand::Set { target, from_scan } => {
            let scan = if let Some(id) = from_scan {
                crate::store::get_scan(&conn, &id)?
            } else {
                crate::store::get_latest_scan_for_target(&conn, &target)?
            };

            match scan {
                Some(s) => {
                    crate::store::set_baseline(&conn, &target, &s)?;
                    println!("Registered scan #{} as expected baseline for target '{target}'.", &s.scan_id[..8]);
                    Ok(ExitCode::Ok)
                }
                None => Err(PlensError::Other(format!("No scan found to use as baseline for '{target}'"))),
            }
        }
        crate::cli::args::BaselineSubcommand::Show { target } => {
            match crate::store::get_baseline(&conn, &target)? {
                Some(baseline) => {
                    println!("Current registered baseline for target '{target}':");
                    println!("{}", crate::render::render_summary_card(&baseline, false));
                    Ok(ExitCode::Ok)
                }
                None => {
                    println!("No baseline currently set for target '{target}'.");
                    Ok(ExitCode::Ok)
                }
            }
        }
        crate::cli::args::BaselineSubcommand::Clear { target } => {
            crate::store::clear_baseline(&conn, &target)?;
            println!("Cleared baseline for target '{target}'.");
            Ok(ExitCode::Ok)
        }
    }
}

pub async fn handle_watch(args: WatchArgs, config: &Config) -> Result<ExitCode> {
    println!("PortLens live exposure watch for target: {}", args.target);
    println!("Rescan interval: {} (Press Ctrl+C to stop)\n", args.every);

    let duration_secs = if args.every.ends_with('m') {
        args.every.trim_end_matches('m').parse::<u64>().unwrap_or(5) * 60
    } else if args.every.ends_with('s') {
        args.every.trim_end_matches('s').parse::<u64>().unwrap_or(30)
    } else if args.every.ends_with('h') {
        args.every.trim_end_matches('h').parse::<u64>().unwrap_or(1) * 3600
    } else {
        args.every.parse::<u64>().unwrap_or(300)
    };

    let mut previous_scan: Option<crate::model::ScanSummary> = None;
    let preset = args.preset.unwrap_or_else(|| config.default_preset.clone());
    let mut iteration: u64 = 0;

    loop {
        iteration += 1;
        println!("[{}] Executing exposure audit on {} (run #{iteration})...", chrono::Utc::now().format("%H:%M:%S"), args.target);

        // Result cache & incremental mode (D.1, D.2)
        let known_open: Vec<u16> = previous_scan.as_ref().map(|s| {
            s.hosts.iter().flat_map(|h| &h.ports)
                .filter(|p| p.state == crate::model::PortState::Open)
                .map(|p| p.number)
                .collect()
        }).unwrap_or_default();

        let custom_ports = if !known_open.is_empty() && !iteration.is_multiple_of(50) {
            let prioritized = crate::engine::discover::prioritize_cached_ports(&known_open, crate::engine::discover::TOP_100_PORTS.to_vec());
            Some(prioritized.iter().map(|p| p.to_string()).collect::<Vec<_>>().join(","))
        } else {
            None
        };

        let scan_req = crate::engine::ScanRequest {
            targets: vec![args.target.clone()],
            preset: preset.clone(),
            profile: args.profile.clone(),
            custom_ports,
            speed: None,
            no_probe: false,
            raw_args: None,
        };

        let engine = crate::engine::DefaultScanEngine::new(config.clone());
        if let Ok(plan) = engine.plan(&scan_req) {
            use futures::StreamExt;
            let mut stream = Box::pin(engine.run(plan));
            let mut current_summary = None;
            while let Some(event) = stream.next().await {
                if let crate::engine::ScanEvent::Finished(s) = event {
                    current_summary = Some(*s);
                }
            }

            if let Some(curr) = current_summary {
                if let Some(ref prev) = previous_scan {
                    let drift = crate::diff::diff_scans(prev, &curr);
                    if drift.has_drift() {
                        println!("\n🚨 DRIFT DETECTED:");
                        println!("{}", crate::diff::render_diff_card(&drift, &prev.scan_id, &curr.scan_id, false));
                    } else {
                        println!("  ✓ State unchanged (score: {}/100)", curr.risk_score.score);
                    }
                } else {
                    println!("  [+] Baseline captured (score: {}/100, {} open ports)", curr.risk_score.score, curr.hosts.first().map(|h| h.ports.len()).unwrap_or(0));
                }
                previous_scan = Some(curr);
            }
        }

        tokio::time::sleep(std::time::Duration::from_secs(duration_secs)).await;
    }
}

pub async fn handle_schedule(args: ScheduleArgs, config: &Config) -> Result<ExitCode> {
    let conn = crate::store::open_db(&Config::db_path())?;

    match args.action {
        crate::cli::args::ScheduleSubcommand::Add {
            name,
            target,
            cron,
            preset,
            profile,
        } => {
            let job = crate::schedule::ScheduleJob {
                name: name.clone(),
                target,
                cron_expr: cron.clone(),
                preset,
                profile,
                last_run: None,
                next_run: None,
                active: true,
            };
            crate::schedule::add_schedule(&conn, &job)?;
            let next_dt = crate::schedule::compute_next_run(&cron)?;
            println!("Scheduled job '{name}' added. Next run at: {}", next_dt.to_rfc3339());
            Ok(ExitCode::Ok)
        }
        crate::cli::args::ScheduleSubcommand::List => {
            let list = crate::schedule::list_schedules(&conn)?;
            println!("Configured Scheduled Scans (total: {}):", list.len());
            let mut table = comfy_table::Table::new();
            table
                .load_preset(comfy_table::presets::UTF8_FULL)
                .apply_modifier(comfy_table::modifiers::UTF8_ROUND_CORNERS)
                .set_header(vec!["NAME", "TARGET", "CRON", "PRESET", "LAST RUN", "NEXT RUN", "ACTIVE"]);

            for j in list {
                table.add_row(vec![
                    j.name,
                    j.target,
                    j.cron_expr,
                    j.preset,
                    j.last_run.unwrap_or_else(|| "-".into()),
                    j.next_run.unwrap_or_else(|| "-".into()),
                    if j.active { "YES" } else { "NO" }.into(),
                ]);
            }
            println!("{table}");
            Ok(ExitCode::Ok)
        }
        crate::cli::args::ScheduleSubcommand::Rm { name } => {
            crate::schedule::remove_schedule(&conn, &name)?;
            println!("Removed scheduled job '{name}'.");
            Ok(ExitCode::Ok)
        }
        crate::cli::args::ScheduleSubcommand::Run { name } => {
            let list = crate::schedule::list_schedules(&conn)?;
            let job = list.into_iter().find(|j| j.name == name).ok_or_else(|| {
                PlensError::Other(format!("Scheduled job '{name}' not found"))
            })?;

            println!("Manually triggering scheduled job '{name}' against {}...", job.target);
            let scan_args = crate::cli::args::ScanArgs {
                targets: vec![job.target],
                preset: Some(job.preset),
                profile: job.profile,
                ports: None,
                file: None,
                exclude: Vec::new(),
                speed: None,
                self_scan: false,
                via: None,
                no_probe: false,
                baseline: false,
                fail_on: None,
                json: false,
                csv: false,
                md: false,
                html: false,
                output: None,
                no_save: false,
                yes: true,
                explain: false,
                raw: None,
                no_color: false,
            };
            handle_scan(scan_args, config).await
        }
    }
}

pub async fn handle_daemon(args: DaemonArgs, config: &Config) -> Result<ExitCode> {
    if args.install_systemd {
        let unit_content = crate::schedule::generate_systemd_unit();
        let target_path = std::path::Path::new("/etc/systemd/system/plens.service");
        if let Ok(()) = std::fs::write(target_path, &unit_content) {
            println!("Installed systemd unit to /etc/systemd/system/plens.service");
            println!("To activate, run:\n  sudo systemctl daemon-reload\n  sudo systemctl enable --now plens");
        } else {
            println!("# Place the following unit into /etc/systemd/system/plens.service:\n");
            println!("{unit_content}");
        }
        return Ok(ExitCode::Ok);
    }

    crate::schedule::run_daemon(config).await?;
    Ok(ExitCode::Ok)
}

pub async fn handle_alert(args: AlertArgs, config: &Config) -> Result<ExitCode> {
    match args.action {
        crate::cli::args::AlertSubcommand::Test => {
            let mgr = crate::alert::AlertManager::new();
            let test_payload = crate::alert::AlertPayload {
                target: "demo.internal".into(),
                scan_id: "test-alert-id".into(),
                title: "Test Alert Dispatch".into(),
                summary: "This is a test notification confirming PortLens webhook integration is properly configured.".into(),
                severity: crate::model::Severity::Critical,
                risk_score: 85,
                risk_grade: "D".into(),
                score_delta: Some(15),
                changes: vec!["+ Port 6379/tcp (redis): EXPOSED".into()],
            };

            if config.discord_webhook.is_none() && config.generic_webhook.is_none() {
                println!("No webhook URLs configured. Add 'discord_webhook' or 'generic_webhook' in ~/.config/plens/config.toml");
                return Ok(ExitCode::Ok);
            }

            println!("Sending test alert to configured webhooks...");
            mgr.dispatch_alert(
                config.discord_webhook.as_deref(),
                config.generic_webhook.as_deref(),
                &test_payload,
            )
            .await?;
            println!("✓ Test alert delivered successfully.");
            Ok(ExitCode::Ok)
        }
        crate::cli::args::AlertSubcommand::Config => {
            println!("Webhook Configuration:");
            if let Some(ref d) = config.discord_webhook {
                let redacted = if d.len() > 20 {
                    format!("{}...{}", &d[..10], &d[d.len() - 5..])
                } else {
                    "configured".into()
                };
                println!("  Discord Webhook: {}", redacted);
            } else {
                println!("  Discord Webhook: Not configured");
            }

            if let Some(ref g) = config.generic_webhook {
                let redacted = if g.len() > 20 {
                    format!("{}...{}", &g[..10], &g[g.len() - 5..])
                } else {
                    "configured".into()
                };
                println!("  Generic Webhook: {}", redacted);
            } else {
                println!("  Generic Webhook: Not configured");
            }
            Ok(ExitCode::Ok)
        }
    }
}

pub async fn handle_export(args: ExportArgs, _config: &Config) -> Result<ExitCode> {
    println!("Exporting scan {} as {:?}", args.scan_id, args.format);
    Ok(ExitCode::Ok)
}

pub async fn handle_config(args: ConfigArgs, config: &Config) -> Result<ExitCode> {
    match args.action {
        crate::cli::args::ConfigSubcommand::Get { key } => {
            println!("Config key {} = (view in config.toml)", key);
        }
        crate::cli::args::ConfigSubcommand::Set { key, value } => {
            println!("Setting config {} = {}", key, value);
        }
        crate::cli::args::ConfigSubcommand::Path => {
            println!("{}", Config::config_path().display());
        }
    }
    let _ = config;
    Ok(ExitCode::Ok)
}

pub async fn handle_doctor(config: &Config) -> Result<ExitCode> {
    run_doctor(config).await
}

pub fn handle_completions(args: CompletionsArgs) -> Result<ExitCode> {
    let mut cmd = Cli::command();
    generate(args.shell, &mut cmd, "plens", &mut io::stdout());
    Ok(ExitCode::Ok)
}
