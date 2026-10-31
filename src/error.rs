use miette::Diagnostic;
use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExitCode {
    Ok = 0,
    GeneralError = 1,
    FailOnThresholdOrDrift = 2,
    NmapMissing = 3,
    AuthDeclined = 4,
    Interrupted = 130,
}

impl ExitCode {
    pub fn as_i32(self) -> i32 {
        self as i32
    }
}

#[derive(Error, Diagnostic, Debug)]
pub enum PlensError {
    #[error("Configuration error: {message}")]
    #[diagnostic(
        code(plens::config::error),
        help("Verify your configuration file at ~/.config/plens/config.toml or environment variables (PLENS_*). Cause: {message}")
    )]
    Config { message: String },

    #[error("Target authorization declined for: {target}")]
    #[diagnostic(
        code(plens::safety::unauthorized),
        help("PortLens requires explicit authorization to scan targets. Run with --yes if authorized in CI or respond 'yes' to the prompt.")
    )]
    AuthorizationDeclined { target: String },

    #[error("Target {target} violates safety allowlist")]
    #[diagnostic(
        code(plens::safety::allowlist_violation),
        help("The configured allowlist restricts scans to specific IP/CIDR ranges. Update 'allowlist' in config.toml to include {target}.")
    )]
    AllowlistViolation { target: String },

    #[error("Required dependency 'nmap' was not found on PATH")]
    #[diagnostic(
        code(plens::engine::nmap_missing),
        help("Phase 2 deep inspection requires nmap. Install nmap via your package manager (e.g., 'apt install nmap' or 'brew install nmap') or run with '--preset quick' to use phase-1 connect scan only.")
    )]
    NmapMissing,

    #[error("Scan threshold failure: findings detected at or above '{level}'")]
    #[diagnostic(
        code(plens::scan::fail_on_threshold),
        help("Remediate the critical/high exposure findings reported above, or adjust --fail-on if this level is acceptable.")
    )]
    ThresholdExceeded { level: String },

    #[error("Baseline drift detected: target deviates from registered baseline")]
    #[diagnostic(
        code(plens::baseline::drift_detected),
        help("Inspect changes with 'plens diff' or update the baseline with 'plens baseline set <target>'.")
    )]
    BaselineDriftDetected,

    #[error("Database error: {message}")]
    #[diagnostic(
        code(plens::store::sqlite_error),
        help("Ensure the SQLite database directory is writable. You can reset with 'plens doctor' to check DB health. Cause: {message}")
    )]
    Database { message: String },

    #[error("Network I/O error: {message}")]
    #[diagnostic(
        code(plens::network::io_error),
        help("Check local network connectivity, DNS resolution, and firewall rules.")
    )]
    Network { message: String },

    #[error("Profile '{name}' not found")]
    #[diagnostic(
        code(plens::profile::not_found),
        help("Available built-in profiles: web-server, database-server, pterodactyl-panel, pterodactyl-node, minimal. Custom profiles can be added to ~/.config/plens/profiles/<name>.toml.")
    )]
    ProfileNotFound { name: String },

    #[error("Preset '{name}' not found")]
    #[diagnostic(
        code(plens::preset::not_found),
        help("Available built-in presets: quick, standard, full, stealth, web, udp.")
    )]
    PresetNotFound { name: String },

    #[error("Scan interrupted by user")]
    #[diagnostic(
        code(plens::scan::interrupted),
        help("The scan was cancelled before completion. Partial results have been saved.")
    )]
    Interrupted,

    #[error("Invalid argument or flag: {message}")]
    #[diagnostic(
        code(plens::cli::invalid_argument),
        help("Run 'plens --help' or 'plens <subcommand> --help' for correct command syntax.")
    )]
    InvalidArgument { message: String },

    #[error("{0}")]
    #[diagnostic(code(plens::generic))]
    Other(String),
}

pub type Result<T> = std::result::Result<T, PlensError>;
