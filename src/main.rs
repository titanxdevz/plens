use clap::Parser;
use miette::Result;
use plens::cli::{commands, Cli};
use plens::config::Config;
use plens::engine::discover::init_system_limits;
use plens::error::PlensError;
use std::process::ExitCode as StdExitCode;

#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

#[tokio::main]
async fn main() -> Result<StdExitCode> {
    // Raise soft RLIMIT_NOFILE to hard limit on Unix, derive concurrency headroom
    let _max_system_concurrency = init_system_limits();

    let cli = Cli::parse();

    // Respect --no-color or NO_COLOR environment variable
    if cli.no_color || std::env::var("NO_COLOR").is_ok() {
        // owo-colors respects NO_COLOR automatically
    }

    let mut config = Config::load().unwrap_or_else(|_| Config::default());

    let exit_code = match commands::run(cli, &mut config).await {
        Ok(code) => code.as_i32(),
        Err(err) => {
            let code = match &err {
                PlensError::ThresholdExceeded { .. } | PlensError::BaselineDriftDetected => 2,
                PlensError::NmapMissing => 3,
                PlensError::AuthorizationDeclined { .. } | PlensError::AllowlistViolation { .. } => {
                    4
                }
                PlensError::Interrupted => 130,
                _ => 1,
            };
            eprintln!("{:?}", miette::Report::new(err));
            code
        }
    };

    Ok(StdExitCode::from(exit_code as u8))
}
