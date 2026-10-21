//! `sentinel-fim` command-line entry point.

mod cli;
mod commands;

use std::io::IsTerminal as _;
use std::process::ExitCode;

use clap::Parser as _;
use tracing_subscriber::EnvFilter;

use crate::cli::Cli;

/// Exit code for errors (including an incomplete scan).
const EXIT_ERROR: u8 = 3;
/// Exit code for a rejected baseline.
const EXIT_BASELINE_REJECTED: u8 = 4;

fn main() -> ExitCode {
    // clap exits with code 2 on usage errors and 0 for --help/--version.
    let cli = Cli::parse();
    init_logging(cli.verbose, cli.quiet);

    match commands::run(cli) {
        Ok(outcome) => ExitCode::from(outcome.exit_code()),
        Err(error) => {
            let mut message = String::new();
            let _ = sentinel_fim::path::write_escaped(&mut message, &format!("{error:#}"));
            eprintln!("sentinel-fim: error: {message}");
            ExitCode::from(if commands::is_baseline_rejection(&error) {
                EXIT_BASELINE_REJECTED
            } else {
                EXIT_ERROR
            })
        }
    }
}

/// Logs go to stderr so stdout stays machine-readable. `SENTINEL_FIM_LOG`
/// (e.g. `debug`, `sentinel_fim=trace`) overrides the -v/-q flags.
fn init_logging(verbose: u8, quiet: bool) {
    let level = match (quiet, verbose) {
        (true, _) => "error",
        (false, 0) => "warn",
        (false, 1) => "info",
        (false, 2) => "debug",
        (false, _) => "trace",
    };
    let filter =
        EnvFilter::try_from_env("SENTINEL_FIM_LOG").unwrap_or_else(|_| EnvFilter::new(level));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .with_ansi(std::io::stderr().is_terminal())
        .with_target(false)
        .without_time()
        .init();
}
