//! Command-line interface definition.

use std::path::PathBuf;

use clap::{ArgAction, Args, Parser, Subcommand, ValueEnum};

const AFTER_HELP: &str = "\
Exit codes:
  0  success: no changes (scan, report), baseline valid (verify)
  1  changes detected
  2  usage error
  3  runtime error, or the scan was incomplete (some entries could not be checked)
  4  the baseline was rejected (corrupted, edited, malformed, or signature invalid)

Examples:
  sentinel-fim init /srv/data -b baseline.json --exclude '*.log'
  sentinel-fim scan -b baseline.json
  sentinel-fim scan -b baseline.json --format json --report scan.json
  sentinel-fim watch -b baseline.json --rescan-interval 600
  sentinel-fim keygen --secret-key fim.secret --public-key fim.pub
  sentinel-fim sign -b baseline.json --secret-key fim.secret
  sentinel-fim verify -b baseline.json --public-key fim.pub --require-signature";

/// File integrity monitor: record a trusted baseline of a directory tree and
/// detect added, removed and modified files.
#[derive(Debug, Parser)]
#[command(name = "sentinel-fim", version, after_help = AFTER_HELP)]
pub struct Cli {
    /// More log output on stderr (-v info, -vv debug, -vvv trace).
    #[arg(short, long, global = true, action = ArgAction::Count)]
    pub verbose: u8,

    /// Only log errors.
    #[arg(short, long, global = true, conflicts_with = "verbose")]
    pub quiet: bool,

    /// TOML configuration file. Command-line options take precedence.
    #[arg(short, long, global = true, value_name = "FILE")]
    pub config: Option<PathBuf>,

    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Scan a directory and record its state as a new baseline.
    Init(InitArgs),
    /// Scan the baseline's directory again and report differences.
    Scan(ScanArgs),
    /// Check a baseline file's checksum and signature (no file system scan).
    Verify(VerifyArgs),
    /// Render a JSON report saved by `scan --report`.
    Report(ReportArgs),
    /// Watch the directory in real time, with periodic full re-scans.
    Watch(WatchArgs),
    /// Generate an Ed25519 key pair for signing baselines.
    Keygen(KeygenArgs),
    /// Sign an existing baseline file in place.
    Sign(SignArgs),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum Format {
    Human,
    Json,
}

#[derive(Debug, Args)]
pub struct BaselineArg {
    /// Baseline file.
    #[arg(short, long, value_name = "FILE")]
    pub baseline: Option<PathBuf>,
}

#[derive(Debug, Args)]
pub struct TrustArgs {
    /// Verify the baseline signature with this public key (required to pass).
    #[arg(long, value_name = "FILE")]
    pub public_key: Option<PathBuf>,

    /// Refuse baselines without a valid signature.
    #[arg(long)]
    pub require_signature: bool,
}

#[derive(Debug, Args)]
pub struct InitArgs {
    /// Directory to monitor.
    pub root: Option<PathBuf>,

    #[command(flatten)]
    pub baseline: BaselineArg,

    /// Exclude entries matching a glob (repeatable). Without '/' a pattern
    /// matches names at any depth ("*.log"); with '/' it matches the path
    /// from the root ("cache/**", "/tmp").
    #[arg(short, long, value_name = "GLOB")]
    pub exclude: Vec<String>,

    /// Follow symbolic links instead of recording them (not recommended).
    #[arg(long)]
    pub follow_symlinks: bool,

    /// Do not cross into other file systems.
    #[arg(long)]
    pub one_file_system: bool,

    /// Report files larger than this many bytes instead of hashing them.
    #[arg(long, value_name = "BYTES")]
    pub max_file_size: Option<u64>,

    /// Replace an existing baseline file.
    #[arg(long)]
    pub force: bool,

    /// Write the baseline even if some entries could not be read.
    #[arg(long)]
    pub allow_incomplete: bool,

    /// Sign the new baseline with this secret key.
    #[arg(long, value_name = "FILE")]
    pub sign_key: Option<PathBuf>,
}

#[derive(Debug, Args)]
pub struct ScanArgs {
    #[command(flatten)]
    pub baseline: BaselineArg,

    #[command(flatten)]
    pub trust: TrustArgs,

    /// Scan this directory instead of the one recorded in the baseline.
    #[arg(long, value_name = "DIR")]
    pub root: Option<PathBuf>,

    /// Output format on stdout.
    #[arg(short, long, value_enum, default_value_t = Format::Human)]
    pub format: Format,

    /// Also write the JSON report to this file.
    #[arg(long, value_name = "FILE")]
    pub report: Option<PathBuf>,
}

#[derive(Debug, Args)]
pub struct VerifyArgs {
    #[command(flatten)]
    pub baseline: BaselineArg,

    #[command(flatten)]
    pub trust: TrustArgs,

    #[arg(short, long, value_enum, default_value_t = Format::Human)]
    pub format: Format,
}

#[derive(Debug, Args)]
pub struct ReportArgs {
    /// JSON report file.
    pub file: PathBuf,

    #[arg(short, long, value_enum, default_value_t = Format::Human)]
    pub format: Format,
}

#[derive(Debug, Args)]
pub struct WatchArgs {
    #[command(flatten)]
    pub baseline: BaselineArg,

    #[command(flatten)]
    pub trust: TrustArgs,

    /// Watch this directory instead of the one recorded in the baseline.
    #[arg(long, value_name = "DIR")]
    pub root: Option<PathBuf>,

    /// Output format: human-readable lines or one JSON object per line.
    #[arg(short, long, value_enum, default_value_t = Format::Human)]
    pub format: Format,

    /// Quiet period before changed paths are re-checked [default: 500].
    #[arg(long, value_name = "MS")]
    pub debounce: Option<u64>,

    /// Seconds between full re-scans; 0 disables them [default: 3600].
    #[arg(long, value_name = "SECS")]
    pub rescan_interval: Option<u64>,

    /// Stop after this many seconds (default: run until interrupted).
    #[arg(long, value_name = "SECS")]
    pub duration: Option<u64>,
}

#[derive(Debug, Args)]
pub struct KeygenArgs {
    /// Where to write the secret key (must not exist). Keep it off the
    /// monitored machine.
    #[arg(long, value_name = "FILE")]
    pub secret_key: PathBuf,

    /// Where to write the public key (must not exist).
    #[arg(long, value_name = "FILE")]
    pub public_key: PathBuf,
}

#[derive(Debug, Args)]
pub struct SignArgs {
    #[command(flatten)]
    pub baseline: BaselineArg,

    /// Secret key file.
    #[arg(long, value_name = "FILE")]
    pub secret_key: PathBuf,
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn cli_definition_is_valid() {
        Cli::command().debug_assert();
    }
}
