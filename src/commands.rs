//! Implementation of the subcommands.

use std::cell::Cell;
use std::fs;
use std::io::{self, Write as _};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use anyhow::{Context as _, Result, bail};
use ed25519_dalek::VerifyingKey;
use serde::Serialize;
use tracing::{info, warn};

use sentinel_fim::baseline::{Baseline, BaselineError, Loaded, SignatureStatus, Trust};
use sentinel_fim::config::Config;
use sentinel_fim::diff;
use sentinel_fim::fsutil;
use sentinel_fim::path::{PathRepr, RelPath, display_os_path};
use sentinel_fim::report::{self, ScanReport, Status, describe_change, format_time};
use sentinel_fim::scan::{Record, ScanPolicy, Scanner, SymlinkPolicy};
use sentinel_fim::sign;
use sentinel_fim::watch::{self, RescanReason, Source, WatchEvent, WatchOptions};

use crate::cli::{
    BaselineArg, Cli, Command, Format, InitArgs, KeygenArgs, ReportArgs, ScanArgs, SignArgs,
    TrustArgs, VerifyArgs, WatchArgs,
};

/// Result of a successful command, mapped to the exit code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    Success,
    Changes,
    Incomplete,
}

impl Outcome {
    pub fn exit_code(self) -> u8 {
        match self {
            Outcome::Success => 0,
            Outcome::Changes => 1,
            Outcome::Incomplete => 3,
        }
    }

    fn from_status(status: Status) -> Self {
        match status {
            Status::Clean => Outcome::Success,
            Status::Changed => Outcome::Changes,
            Status::Incomplete => Outcome::Incomplete,
        }
    }
}

/// `true` if the error means the baseline must not be trusted (exit code 4).
pub fn is_baseline_rejection(error: &anyhow::Error) -> bool {
    error.chain().any(|cause| {
        matches!(
            cause.downcast_ref::<BaselineError>(),
            Some(BaselineError::Integrity(_) | BaselineError::Malformed(_))
        )
    })
}

pub fn run(cli: Cli) -> Result<Outcome> {
    let config = match &cli.config {
        Some(path) => Config::load(path)?,
        None => Config::default(),
    };
    match cli.command {
        Command::Init(args) => init(&config, args),
        Command::Scan(args) => scan(&config, args),
        Command::Verify(args) => verify(&config, args),
        Command::Report(args) => show_report(args),
        Command::Watch(args) => run_watch(&config, args),
        Command::Keygen(args) => keygen(args),
        Command::Sign(args) => sign_baseline(&config, args),
    }
}

fn baseline_path(arg: &BaselineArg, config: &Config) -> Result<PathBuf> {
    match arg.baseline.as_ref().or(config.baseline.as_ref()) {
        Some(path) => Ok(path.clone()),
        None => {
            bail!("no baseline file given: use --baseline or set `baseline` in the configuration")
        }
    }
}

/// Loads the baseline with the trust settings from the CLI and config.
fn load_baseline(path: &Path, trust: &TrustArgs, config: &Config) -> Result<Loaded> {
    let key_path = trust.public_key.as_ref().or(config.public_key.as_ref());
    let key: Option<VerifyingKey> = key_path.map(|p| sign::read_public_key(p)).transpose()?;
    let require_signature = trust.require_signature || config.require_signature == Some(true);

    let loaded = Baseline::load(
        path,
        Trust {
            public_key: key.as_ref(),
            require_signature,
        },
    )?;
    match &loaded.signature {
        SignatureStatus::Unsigned => info!("baseline is not signed"),
        SignatureStatus::NotChecked { signer } => warn!(
            "baseline is signed by {signer}, but no public key was given; the signature was not checked"
        ),
        SignatureStatus::Verified { signer } => info!("baseline signature verified ({signer})"),
    }
    Ok(loaded)
}

fn print(text: &str) -> Result<()> {
    let mut stdout = io::stdout().lock();
    stdout.write_all(text.as_bytes())?;
    stdout.flush()?;
    Ok(())
}

fn init(config: &Config, args: InitArgs) -> Result<Outcome> {
    let Some(root) = args.root.as_ref().or(config.root.as_ref()) else {
        bail!("no directory given: pass it as an argument or set `root` in the configuration");
    };
    let path = baseline_path(&args.baseline, config)?;
    if path.exists() && !args.force {
        bail!(
            "baseline {} already exists (use --force to replace it)",
            path.display()
        );
    }

    let mut exclude = config.exclude.clone();
    exclude.extend(args.exclude.iter().cloned());
    let mut policy = ScanPolicy {
        symlinks: if args.follow_symlinks || config.follow_symlinks == Some(true) {
            SymlinkPolicy::Follow
        } else {
            SymlinkPolicy::Record
        },
        exclude,
        one_file_system: args.one_file_system || config.one_file_system == Some(true),
        max_file_size: args.max_file_size.or(config.max_file_size),
        ..ScanPolicy::default()
    };

    let canonical_root =
        fs::canonicalize(root).with_context(|| format!("cannot access {}", root.display()))?;
    if let Some(rel) = inside(&canonical_root, &path) {
        // Otherwise the baseline would report itself as changed on every scan.
        match rel.to_repr() {
            PathRepr::Utf8(text) => {
                warn!("the baseline file is inside the scanned directory; excluding /{text}");
                policy.exclude.push(format!("/{}", globset::escape(&text)));
            }
            _ => warn!(
                "the baseline file is inside the scanned directory and will show up as changed"
            ),
        }
    }
    if let Some(key_path) = &args.sign_key
        && inside(&canonical_root, key_path).is_some()
    {
        warn!("the secret key is inside the monitored directory; keep it off this machine");
    }

    let scanner = Scanner::new(&canonical_root, policy)?;
    let snapshot = scanner.scan();
    for issue in &snapshot.issues {
        warn!("{issue}");
    }
    if !snapshot.is_complete() && !args.allow_incomplete {
        bail!(
            "{} entries could not be read; baseline not written (fix the problems or use --allow-incomplete)",
            snapshot.issues.len()
        );
    }

    let signer = args
        .sign_key
        .as_ref()
        .map(|p| sign::read_secret_key(p))
        .transpose()?;
    let files = snapshot
        .entries
        .values()
        .filter(|r| matches!(r, Record::File { .. }))
        .count();
    let baseline = Baseline::new(
        scanner.root().to_path_buf(),
        scanner.policy().clone(),
        snapshot.entries,
    );
    baseline.save(&path, signer.as_ref(), args.force)?;

    let signed = signer
        .map(|k| format!(", signed by {}", sign::key_id(&k.verifying_key())))
        .unwrap_or_default();
    print(&format!(
        "Baseline written to {}: {} entries ({files} files) under {}{signed}\n",
        path.display(),
        baseline.entries.len(),
        display_os_path(scanner.root()),
    ))?;
    if snapshot.issues.is_empty() {
        Ok(Outcome::Success)
    } else {
        Ok(Outcome::Incomplete)
    }
}

/// `path` relative to `root` if it lies inside it (`path` need not exist).
fn inside(root: &Path, path: &Path) -> Option<RelPath> {
    let absolute = match fs::canonicalize(path) {
        Ok(p) => p,
        Err(_) => {
            let parent = match path.parent() {
                Some(p) if !p.as_os_str().is_empty() => p,
                _ => Path::new("."),
            };
            fs::canonicalize(parent).ok()?.join(path.file_name()?)
        }
    };
    RelPath::from_root(root, &absolute).ok()
}

fn scanner_for(loaded: &Loaded, root: Option<&PathBuf>, config: &Config) -> Result<Scanner> {
    if !config.exclude.is_empty() && config.exclude != loaded.baseline.policy.exclude {
        warn!(
            "the configuration's exclude rules differ from the baseline's; the baseline's rules are used"
        );
    }
    let root = root.unwrap_or(&loaded.baseline.root);
    Ok(Scanner::new(root, loaded.baseline.policy.clone())?)
}

fn scan(config: &Config, args: ScanArgs) -> Result<Outcome> {
    let path = baseline_path(&args.baseline, config)?;
    let loaded = load_baseline(&path, &args.trust, config)?;
    let scanner = scanner_for(&loaded, args.root.as_ref(), config)?;

    let snapshot = scanner.scan();
    let diff = diff::compare(&loaded.baseline.entries, &snapshot);
    let report = ScanReport::new(&path, &loaded, scanner.root(), &snapshot, &diff);

    if let Some(report_path) = &args.report {
        fsutil::write_atomic(report_path, report.to_json().as_bytes(), true)
            .with_context(|| format!("cannot write report {}", report_path.display()))?;
    }
    match args.format {
        Format::Human => print(&report.to_human())?,
        Format::Json => print(&report.to_json())?,
    }
    Ok(Outcome::from_status(report.status))
}

#[derive(Serialize)]
struct VerifyOutput<'a> {
    valid: bool,
    #[serde(serialize_with = "serialize_path")]
    baseline: &'a Path,
    #[serde(serialize_with = "serialize_path")]
    root: &'a Path,
    created_at: u64,
    tool_version: &'a str,
    entries: usize,
    signature: &'static str,
    signer: Option<&'a str>,
}

fn serialize_path<S: serde::Serializer>(path: &&Path, s: S) -> Result<S::Ok, S::Error> {
    PathRepr::from_os_str(path.as_os_str()).serialize(s)
}

fn verify(config: &Config, args: VerifyArgs) -> Result<Outcome> {
    let path = baseline_path(&args.baseline, config)?;
    let loaded = load_baseline(&path, &args.trust, config)?;
    let b = &loaded.baseline;
    let signer = match &loaded.signature {
        SignatureStatus::Unsigned => None,
        SignatureStatus::NotChecked { signer } | SignatureStatus::Verified { signer } => {
            Some(signer.as_str())
        }
    };
    match args.format {
        Format::Json => {
            let output = VerifyOutput {
                valid: true,
                baseline: &path,
                root: &b.root,
                created_at: b.created_at,
                tool_version: &b.tool_version,
                entries: b.entries.len(),
                signature: loaded.signature.label(),
                signer,
            };
            print(&(serde_json::to_string_pretty(&output)? + "\n"))?;
        }
        Format::Human => {
            let signature = match &loaded.signature {
                SignatureStatus::Unsigned => "unsigned".to_owned(),
                SignatureStatus::NotChecked { signer } => {
                    format!("signed by {signer}, NOT checked (no --public-key)")
                }
                SignatureStatus::Verified { signer } => format!("verified, signed by {signer}"),
            };
            print(&format!(
                "Baseline OK: {}\n  root:       {}\n  created:    {} (sentinel-fim {})\n  entries:    {}\n  signature:  {signature}\n",
                path.display(),
                display_os_path(&b.root),
                format_time(b.created_at),
                b.tool_version,
                b.entries.len(),
            ))?;
        }
    }
    Ok(Outcome::Success)
}

fn show_report(args: ReportArgs) -> Result<Outcome> {
    let text = fs::read_to_string(&args.file)
        .with_context(|| format!("cannot read report {}", args.file.display()))?;
    let report = ScanReport::from_json(&text)
        .map_err(|e| anyhow::anyhow!("invalid report {}: {e}", args.file.display()))?;
    match args.format {
        Format::Human => print(&report.to_human())?,
        Format::Json => print(&report.to_json())?,
    }
    Ok(Outcome::from_status(report.status))
}

fn run_watch(config: &Config, args: WatchArgs) -> Result<Outcome> {
    let path = baseline_path(&args.baseline, config)?;
    let loaded = load_baseline(&path, &args.trust, config)?;
    let scanner = scanner_for(&loaded, args.root.as_ref(), config)?;

    let debounce = Duration::from_millis(args.debounce.or(config.watch.debounce_ms).unwrap_or(500));
    let rescan_secs = args
        .rescan_interval
        .or(config.watch.rescan_interval_secs)
        .unwrap_or(3600);
    let options = WatchOptions {
        debounce,
        max_latency: (debounce * 10).max(Duration::from_secs(5)),
        rescan_interval: (rescan_secs > 0).then(|| Duration::from_secs(rescan_secs)),
        ..WatchOptions::default()
    };

    let deadline = args
        .duration
        .map(|secs| Instant::now() + Duration::from_secs(secs));
    // Set when stdout is gone (e.g. a closed pipe): nobody would see alerts.
    let output_failed = Cell::new(false);
    let should_stop = || output_failed.get() || deadline.is_some_and(|d| Instant::now() >= d);

    let mut deviations = 0;
    let mut output_error: Option<anyhow::Error> = None;
    let format = args.format;
    let mut sink = |event: WatchEvent| {
        if let WatchEvent::Stopped { deviations: d } = event {
            deviations = d;
        }
        if output_error.is_some() {
            return;
        }
        let line = match format {
            Format::Human => format!(
                "[{}] {}\n",
                format_time(report::unix_now()),
                render_event(&event)
            ),
            Format::Json => {
                let timed = Timed {
                    time: report::unix_now(),
                    event: &event,
                };
                serde_json::to_string(&timed).expect("event is serializable") + "\n"
            }
        };
        if let Err(e) = print(&line) {
            output_error = Some(e);
            output_failed.set(true);
        }
    };
    watch::run(
        &scanner,
        &loaded.baseline.entries,
        &options,
        &should_stop,
        &mut sink,
    )?;
    if let Some(e) = output_error {
        return Err(e).context("cannot write watch output");
    }
    Ok(if deviations > 0 {
        Outcome::Changes
    } else {
        Outcome::Success
    })
}

#[derive(Serialize)]
struct Timed<'a> {
    time: u64,
    #[serde(flatten)]
    event: &'a WatchEvent,
}

fn source_name(source: Source) -> &'static str {
    match source {
        Source::InitialScan => "initial scan",
        Source::Event => "event",
        Source::Reconciliation => "reconciliation scan",
        Source::PeriodicRescan => "periodic scan",
    }
}

fn reason_name(reason: RescanReason) -> &'static str {
    match reason {
        RescanReason::Startup => "startup",
        RescanReason::EventsLost => "events were lost",
        RescanReason::QueueOverflow => "event queue overflow",
        RescanReason::WatcherError => "watcher error",
        RescanReason::RootChanged => "root changed",
        RescanReason::Periodic => "periodic",
    }
}

fn render_event(event: &WatchEvent) -> String {
    match event {
        WatchEvent::Started {
            root,
            baseline_entries,
        } => format!(
            "watching {} ({baseline_entries} baseline entries)",
            display_os_path(root)
        ),
        WatchEvent::Change { source, change } => {
            format!("{} [{}]", describe_change(change), source_name(*source))
        }
        WatchEvent::Reverted { source, path } => format!(
            "= {:<12} {path} (matches the baseline again) [{}]",
            "reverted",
            source_name(*source)
        ),
        WatchEvent::Unverified { source, path } => format!(
            "? {:<12} {path} (state unknown) [{}]",
            "unverified",
            source_name(*source)
        ),
        WatchEvent::Issue { source, issue } => {
            let location = issue
                .path
                .as_ref()
                .map_or_else(|| "<scan root>".to_owned(), ToString::to_string);
            let mut message = String::new();
            let _ = sentinel_fim::path::write_escaped(&mut message, &issue.message);
            format!(
                "! {:<12} {location}: {message} [{}]",
                "issue",
                source_name(*source)
            )
        }
        WatchEvent::Rescan {
            reason,
            entries_scanned,
            deviations,
        } => format!(
            "full scan ({}): {entries_scanned} entries, {deviations} deviations from the baseline",
            reason_name(*reason)
        ),
        WatchEvent::WatcherError { message } => {
            let mut escaped = String::new();
            let _ = sentinel_fim::path::write_escaped(&mut escaped, message);
            format!("watcher error: {escaped}")
        }
        WatchEvent::Stopped { deviations } => {
            format!("stopped; {deviations} deviations from the baseline")
        }
    }
}

fn keygen(args: KeygenArgs) -> Result<Outcome> {
    for path in [&args.secret_key, &args.public_key] {
        if path.exists() {
            bail!(
                "{} already exists; refusing to overwrite a key",
                path.display()
            );
        }
    }
    let key = sign::generate()?;
    sign::write_secret_key(&args.secret_key, &key)?;
    sign::write_public_key(&args.public_key, &key.verifying_key())?;
    print(&format!(
        "Secret key: {}\nPublic key: {} ({})\n\nKeep the secret key off the monitored machine; give it only the public key.\n",
        args.secret_key.display(),
        args.public_key.display(),
        sign::key_id(&key.verifying_key()),
    ))?;
    Ok(Outcome::Success)
}

fn sign_baseline(config: &Config, args: SignArgs) -> Result<Outcome> {
    let path = baseline_path(&args.baseline, config)?;
    let key = sign::read_secret_key(&args.secret_key)?;
    sentinel_fim::baseline::sign_file(&path, &key)?;
    print(&format!(
        "Signed {} with key {}\n",
        path.display(),
        sign::key_id(&key.verifying_key())
    ))?;
    Ok(Outcome::Success)
}
