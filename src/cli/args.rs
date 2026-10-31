use clap::{Args, Parser, Subcommand, ValueEnum};
use clap_complete::Shell;
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(
    name = "plens",
    about = "Server-exposure auditor for operators who run their own VPS/nodes",
    long_about = "PortLens audits server exposure, compares inside vs outside socket visibility, runs safe verification probes, detects baseline drift, scores risk (0-100), and provides actionable copy-paste remediation commands.",
    version
)]
pub struct Cli {
    #[arg(short = 'q', long = "quiet", global = true, help = "Suppress non-essential output")]
    pub quiet: bool,

    #[arg(short = 'v', long = "verbose", global = true, help = "Show verbose debug details")]
    pub verbose: bool,

    #[arg(long = "no-color", global = true, help = "Disable ANSI colored output")]
    pub no_color: bool,

    #[command(subcommand)]
    pub command: Option<Commands>,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    #[command(about = "Scan one or more targets for exposed services and security risks")]
    Scan(ScanArgs),

    #[command(name = "self", about = "Inside-vs-outside exposure audit of the local machine/host")]
    SelfAudit(SelfArgs),

    #[command(about = "Live terminal monitor that continuously re-scans on an interval")]
    Watch(WatchArgs),

    #[command(about = "Display copy-paste remediation commands for a scan or finding")]
    Fix(FixArgs),

    #[command(about = "Plain-language offline knowledge page for a port or service")]
    Explain(ExplainArgs),

    #[command(about = "Suppress or manage finding suppressions with reason and expiry")]
    Ignore(IgnoreArgs),

    #[command(about = "Interactive terminal user interface (Ratatui TUI)")]
    Ui,

    #[command(about = "List scan history with filters for target and findings")]
    History(HistoryArgs),

    #[command(about = "Show detailed scan results by scan ID")]
    Show(ShowArgs),

    #[command(about = "Compare two scans or scan against latest/baseline with colored diff")]
    Diff(DiffArgs),

    #[command(about = "Manage host baseline expected states")]
    Baseline(BaselineArgs),

    #[command(about = "Manage recurring scheduled scan jobs")]
    Schedule(ScheduleArgs),

    #[command(about = "Run the background scheduler daemon")]
    Daemon(DaemonArgs),

    #[command(about = "Configure or test alert integrations (Discord / Webhooks)")]
    Alert(AlertArgs),

    #[command(about = "Export scan results to JSON, CSV, Markdown, or HTML")]
    Export(ExportArgs),

    #[command(about = "View or modify PortLens configuration settings")]
    Config(ConfigArgs),

    #[command(about = "Verify environment health: nmap presence, permissions, socket limits, DB")]
    Doctor,

    #[command(about = "Generate shell completions script")]
    Completions(CompletionsArgs),
}

#[derive(Args, Debug, Clone)]
pub struct ScanArgs {
    #[arg(help = "Target IP addresses or hostnames to scan")]
    pub targets: Vec<String>,

    #[arg(long = "preset", help = "Scan preset: quick, standard, full, stealth, web, udp")]
    pub preset: Option<String>,

    #[arg(long = "profile", help = "Hosting profile: web-server, database-server, pterodactyl-panel, pterodactyl-node, minimal")]
    pub profile: Option<String>,

    #[arg(short = 'p', long = "ports", help = "Custom port list or ranges (e.g. '80,443', '1-1024')")]
    pub ports: Option<String>,

    #[arg(short = 'f', long = "file", help = "Read targets from a file (one per line)")]
    pub file: Option<PathBuf>,

    #[arg(long = "exclude", help = "Target to exclude from scanning")]
    pub exclude: Vec<String>,

    #[arg(long = "speed", help = "Scan speed level (1=slowest/stealthiest to 5=fastest)")]
    pub speed: Option<u8>,

    #[arg(long = "self", help = "Perform an inside-vs-outside comparison for the local host")]
    pub self_scan: bool,

    #[arg(long = "via", help = "Explicit external IP or interface to test against")]
    pub via: Option<String>,

    #[arg(long = "no-probe", help = "Disable active protocol verification probes")]
    pub no_probe: bool,

    #[arg(long = "baseline", help = "Compare scan against stored baseline and report drift")]
    pub baseline: bool,

    #[arg(long = "fail-on", help = "Exit with code 2 if findings meet or exceed this level (info, low, medium, high, critical)")]
    pub fail_on: Option<String>,

    #[arg(long = "json", help = "Output scan results as JSON")]
    pub json: bool,

    #[arg(long = "csv", help = "Output open ports as CSV")]
    pub csv: bool,

    #[arg(long = "md", help = "Output report as Markdown")]
    pub md: bool,

    #[arg(long = "html", help = "Output self-contained HTML report")]
    pub html: bool,

    #[arg(short = 'o', long = "output", help = "Write output to file instead of stdout")]
    pub output: Option<PathBuf>,

    #[arg(long = "no-save", help = "Do not persist scan results into the local SQLite database")]
    pub no_save: bool,

    #[arg(short = 'y', long = "yes", help = "Acknowledge authorization to scan target without prompt (CI mode)")]
    pub yes: bool,

    #[arg(long = "explain", help = "Print the exact execution plan and parameters without scanning")]
    pub explain: bool,

    #[arg(long = "raw", help = "Additional raw nmap arguments for phase 2")]
    pub raw: Option<String>,

    #[arg(long = "no-color", help = "Disable ANSI colored output")]
    pub no_color: bool,
}

#[derive(Args, Debug, Clone)]
pub struct SelfArgs {
    #[arg(long = "via", help = "Explicit external IP or interface to test against")]
    pub via: Option<String>,

    #[arg(long = "json", help = "Output inside-vs-outside audit as JSON")]
    pub json: bool,
}

#[derive(Args, Debug, Clone)]
pub struct WatchArgs {
    #[arg(help = "Target to continuously monitor")]
    pub target: String,

    #[arg(long = "every", default_value = "5m", help = "Interval between scans (e.g. 30s, 5m, 1h)")]
    pub every: String,

    #[arg(long = "preset", help = "Scan preset to use during watch")]
    pub preset: Option<String>,

    #[arg(long = "profile", help = "Hosting profile to evaluate against")]
    pub profile: Option<String>,
}

#[derive(Args, Debug, Clone)]
pub struct FixArgs {
    #[arg(help = "Scan ID or Finding ID to generate fixes for")]
    pub id: String,
}

#[derive(Args, Debug, Clone)]
pub struct ExplainArgs {
    #[arg(help = "Port number (e.g. 6379) or service name (e.g. redis, mongodb)")]
    pub query: String,
}

#[derive(Args, Debug, Clone)]
pub struct IgnoreArgs {
    #[arg(help = "Rule ID or port to ignore (e.g. 'redis-noauth' or '6379')")]
    pub rule_or_port: Option<String>,

    #[arg(long = "target", help = "Target to apply ignore rule to")]
    pub target: Option<String>,

    #[arg(long = "reason", help = "Reason for ignoring this finding")]
    pub reason: Option<String>,

    #[arg(long = "until", help = "Expiry date in YYYY-MM-DD format")]
    pub until: Option<String>,

    #[arg(long = "list", help = "List all active suppressions")]
    pub list: bool,

    #[arg(long = "remove", help = "Remove suppression by ID")]
    pub remove: Option<String>,
}

#[derive(Args, Debug, Clone)]
pub struct HistoryArgs {
    #[arg(long = "target", help = "Filter history by target")]
    pub target: Option<String>,

    #[arg(long = "since", help = "Filter scans since date (YYYY-MM-DD)")]
    pub since: Option<String>,

    #[arg(long = "has-findings", help = "Only show scans with security findings")]
    pub has_findings: bool,

    #[arg(long = "limit", default_value = "20", help = "Maximum number of records to return")]
    pub limit: usize,
}

#[derive(Args, Debug, Clone)]
pub struct ShowArgs {
    #[arg(help = "Scan ID to display")]
    pub scan_id: String,

    #[arg(long = "json", help = "Output raw scan record as JSON")]
    pub json: bool,
}

#[derive(Args, Debug, Clone)]
pub struct DiffArgs {
    #[arg(help = "First scan ID (or 'baseline')")]
    pub first: String,

    #[arg(help = "Second scan ID (or 'latest')")]
    pub second: String,
}

#[derive(Args, Debug, Clone)]
pub struct BaselineArgs {
    #[command(subcommand)]
    pub action: BaselineSubcommand,
}

#[derive(Subcommand, Debug, Clone)]
pub enum BaselineSubcommand {
    #[command(about = "Set baseline from latest scan or specific scan ID for target")]
    Set {
        #[arg(help = "Target hostname or IP")]
        target: String,
        #[arg(long = "from-scan", help = "Scan ID to use as baseline (defaults to latest)")]
        from_scan: Option<String>,
    },
    #[command(about = "Display stored baseline for a target")]
    Show {
        #[arg(help = "Target hostname or IP")]
        target: String,
    },
    #[command(about = "Edit or clear baseline for a target")]
    Clear {
        #[arg(help = "Target hostname or IP")]
        target: String,
    },
}

#[derive(Args, Debug, Clone)]
pub struct ScheduleArgs {
    #[command(subcommand)]
    pub action: ScheduleSubcommand,
}

#[derive(Subcommand, Debug, Clone)]
pub enum ScheduleSubcommand {
    #[command(about = "Add a new scheduled scan")]
    Add {
        #[arg(help = "Schedule job name")]
        name: String,
        #[arg(long = "target", required = true, help = "Target to scan")]
        target: String,
        #[arg(long = "cron", required = true, help = "Cron expression (e.g. '0 0 * * *')")]
        cron: String,
        #[arg(long = "preset", default_value = "standard", help = "Scan preset")]
        preset: String,
        #[arg(long = "profile", help = "Hosting profile")]
        profile: Option<String>,
    },
    #[command(about = "List configured scheduled scans")]
    List,
    #[command(about = "Remove a scheduled scan")]
    Rm {
        #[arg(help = "Schedule job name")]
        name: String,
    },
    #[command(about = "Manually trigger a scheduled job by name")]
    Run {
        #[arg(help = "Schedule job name")]
        name: String,
    },
}

#[derive(Args, Debug, Clone)]
pub struct DaemonArgs {
    #[arg(long = "install-systemd", help = "Print or write systemd service unit file")]
    pub install_systemd: bool,
}

#[derive(Args, Debug, Clone)]
pub struct AlertArgs {
    #[command(subcommand)]
    pub action: AlertSubcommand,
}

#[derive(Subcommand, Debug, Clone)]
pub enum AlertSubcommand {
    #[command(about = "Send a test alert to configured Discord or generic webhooks")]
    Test,
    #[command(about = "Show current webhook configuration and alert status")]
    Config,
}

#[derive(ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExportFormat {
    Json,
    Csv,
    Md,
    Html,
}

#[derive(Args, Debug, Clone)]
pub struct ExportArgs {
    #[arg(help = "Scan ID to export")]
    pub scan_id: String,

    #[arg(long = "format", value_enum, default_value = "json", help = "Export format")]
    pub format: ExportFormat,

    #[arg(short = 'o', long = "output", help = "File path to write export to")]
    pub output: Option<PathBuf>,
}

#[derive(Args, Debug, Clone)]
pub struct ConfigArgs {
    #[command(subcommand)]
    pub action: ConfigSubcommand,
}

#[derive(Subcommand, Debug, Clone)]
pub enum ConfigSubcommand {
    #[command(about = "Get configuration value by key")]
    Get { key: String },
    #[command(about = "Set configuration value by key")]
    Set { key: String, value: String },
    #[command(about = "Print configuration file location or path")]
    Path,
}

#[derive(Args, Debug, Clone)]
pub struct CompletionsArgs {
    #[arg(value_enum, help = "Shell to generate completions for")]
    pub shell: Shell,
}
