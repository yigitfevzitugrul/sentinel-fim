//! Real-time monitoring with reconciliation.
//!
//! File system notifications are a *hint*, not a guarantee: they can be lost
//! (queue overflow), coalesced, or arrive for paths that changed again since.
//! Therefore an event never carries a verdict by itself. It only marks a path
//! as dirty; the path is then re-scanned and compared with the baseline.
//! Full reconciliation scans run at startup, whenever the platform reports
//! lost events or our own queue overflows, after watcher errors, and
//! periodically.
//!
//! Startup order matters: the watcher is registered *before* the initial
//! full scan, so a change racing with the scan is either seen by the scan or
//! delivered as an event afterwards.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, RecvTimeoutError, SyncSender, TrySendError};
use std::time::{Duration, Instant};

use notify::{RecommendedWatcher, RecursiveMode, Watcher};
use serde::Serialize;

use crate::diff::{self, Change};
use crate::path::RelPath;
use crate::report::IssueRecord;
use crate::scan::{self, Record, Scanner, Snapshot, SymlinkPolicy};

#[derive(Debug, Clone)]
pub struct WatchOptions {
    /// Quiet period after the last event before dirty paths are re-checked.
    pub debounce: Duration,
    /// Re-check at the latest after this long, even under a constant stream
    /// of events.
    pub max_latency: Duration,
    /// Interval of full reconciliation scans (`None`: only when needed).
    pub rescan_interval: Option<Duration>,
    /// Capacity of the event queue; on overflow a full rescan is scheduled.
    pub queue_capacity: usize,
}

impl Default for WatchOptions {
    fn default() -> Self {
        WatchOptions {
            debounce: Duration::from_millis(500),
            max_latency: Duration::from_secs(5),
            rescan_interval: Some(Duration::from_secs(3600)),
            queue_capacity: 65_536,
        }
    }
}

/// What led to a finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Source {
    /// Full scan at startup.
    InitialScan,
    /// Re-check of a path after a notification.
    Event,
    /// Full scan because events may have been lost.
    Reconciliation,
    /// Scheduled full scan.
    PeriodicRescan,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RescanReason {
    Startup,
    /// The OS reported dropped events (e.g. inotify queue overflow).
    EventsLost,
    /// Our own event queue was full.
    QueueOverflow,
    /// The watcher reported an error.
    WatcherError,
    /// An event concerned the root itself.
    RootChanged,
    Periodic,
}

/// Everything the watcher reports.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum WatchEvent {
    Started {
        #[serde(with = "scan::os_path")]
        root: PathBuf,
        baseline_entries: usize,
    },
    /// A path deviates from the baseline (newly, or differently than before).
    Change {
        source: Source,
        #[serde(flatten)]
        change: Change,
    },
    /// A previously reported path matches the baseline again.
    Reverted {
        source: Source,
        path: RelPath,
    },
    /// The state of a baseline entry could not be determined.
    Unverified {
        source: Source,
        path: RelPath,
    },
    Issue {
        source: Source,
        #[serde(flatten)]
        issue: IssueRecord,
    },
    /// A full scan finished.
    Rescan {
        reason: RescanReason,
        entries_scanned: usize,
        deviations: usize,
    },
    WatcherError {
        message: String,
    },
    Stopped {
        deviations: usize,
    },
}

#[derive(Debug, thiserror::Error)]
pub enum WatchError {
    #[error("cannot start watching {}: {message}", .root.display())]
    Start { root: PathBuf, message: String },
}

/// Watches `scanner`'s root against `baseline` until `should_stop` returns
/// true, reporting through `sink`.
///
/// # Errors
///
/// Only if the watcher cannot be started (for example the inotify watch limit
/// is too low); runtime problems are reported as events.
pub fn run(
    scanner: &Scanner,
    baseline: &BTreeMap<RelPath, Record>,
    options: &WatchOptions,
    should_stop: &dyn Fn() -> bool,
    sink: &mut dyn FnMut(WatchEvent),
) -> Result<(), WatchError> {
    let (tx, rx) = mpsc::sync_channel(options.queue_capacity.max(1));
    let overflow = Arc::new(AtomicBool::new(false));
    let _watcher = start_watcher(scanner, tx, Arc::clone(&overflow))?;

    let mut state = State {
        scanner,
        baseline,
        reported: BTreeMap::new(),
        unverified: BTreeSet::new(),
        issues: BTreeMap::new(),
    };
    sink(WatchEvent::Started {
        root: scanner.root().to_path_buf(),
        baseline_entries: baseline.len(),
    });
    state.full_scan(RescanReason::Startup, Source::InitialScan, sink);

    let tick = Duration::from_millis(100).min(options.debounce.max(Duration::from_millis(1)));
    let mut dirty: BTreeSet<RelPath> = BTreeSet::new();
    let mut rescan: Option<RescanReason> = None;
    let mut last_event = Instant::now();
    let mut first_pending: Option<Instant> = None;
    let mut last_full_scan = Instant::now();

    while !should_stop() {
        match rx.recv_timeout(tick) {
            Ok(Ok(event)) if is_read_access(&event) => {}
            Ok(Ok(event)) => {
                last_event = Instant::now();
                first_pending.get_or_insert(last_event);
                if event.need_rescan() {
                    rescan.get_or_insert(RescanReason::EventsLost);
                }
                for path in &event.paths {
                    match relative(scanner.root(), path) {
                        Some(rel) if !scanner.is_excluded(&rel) => {
                            dirty.insert(rel);
                        }
                        Some(_) => {}
                        None if path == scanner.root() => {
                            rescan.get_or_insert(RescanReason::RootChanged);
                        }
                        None => {}
                    }
                }
            }
            Ok(Err(error)) => {
                last_event = Instant::now();
                first_pending.get_or_insert(last_event);
                sink(WatchEvent::WatcherError {
                    message: error.to_string(),
                });
                rescan.get_or_insert(RescanReason::WatcherError);
            }
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => {
                sink(WatchEvent::WatcherError {
                    message: "file system watcher stopped unexpectedly".into(),
                });
                break;
            }
        }
        if overflow.swap(false, Ordering::AcqRel) {
            first_pending.get_or_insert_with(Instant::now);
            rescan.get_or_insert(RescanReason::QueueOverflow);
        }

        let quiet = last_event.elapsed() >= options.debounce;
        let overdue = first_pending.is_some_and(|t| t.elapsed() >= options.max_latency);
        if first_pending.is_some() && (quiet || overdue) {
            if let Some(reason) = rescan.take() {
                // A full scan supersedes all pending path checks.
                dirty.clear();
                state.full_scan(reason, Source::Reconciliation, sink);
                last_full_scan = Instant::now();
            } else {
                for path in outermost(&dirty) {
                    state.check_subtree(path, sink);
                }
                dirty.clear();
            }
            first_pending = None;
        }

        if options
            .rescan_interval
            .is_some_and(|interval| last_full_scan.elapsed() >= interval)
        {
            state.full_scan(RescanReason::Periodic, Source::PeriodicRescan, sink);
            last_full_scan = Instant::now();
        }
    }

    sink(WatchEvent::Stopped {
        deviations: state.reported.len(),
    });
    Ok(())
}

fn start_watcher(
    scanner: &Scanner,
    tx: SyncSender<notify::Result<notify::Event>>,
    overflow: Arc<AtomicBool>,
) -> Result<RecommendedWatcher, WatchError> {
    let start_error = |e: notify::Error| {
        let mut message = e.to_string();
        if matches!(e.kind, notify::ErrorKind::MaxFilesWatch) {
            message.push_str(
                " (raise the limit with `sysctl fs.inotify.max_user_watches=<n>` on Linux)",
            );
        }
        WatchError::Start {
            root: scanner.root().to_path_buf(),
            message,
        }
    };
    let handler = move |result: notify::Result<notify::Event>| {
        // Never block the notification thread: drop and remember instead.
        if let Err(TrySendError::Full(_)) = tx.try_send(result) {
            overflow.store(true, Ordering::Release);
        }
    };
    let config = notify::Config::default()
        .with_follow_symlinks(scanner.policy().symlinks == SymlinkPolicy::Follow);
    let mut watcher = RecommendedWatcher::new(handler, config).map_err(start_error)?;
    watcher
        .watch(scanner.root(), RecursiveMode::Recursive)
        .map_err(start_error)?;
    Ok(watcher)
}

/// Opening or reading a file does not change it. Ignoring these events is
/// also essential because the scanner's own reads produce them (inotify
/// reports opens), which would otherwise trigger endless re-checks. Closing a
/// file that was open for writing is kept: it signals a completed write.
fn is_read_access(event: &notify::Event) -> bool {
    use notify::EventKind;
    use notify::event::{AccessKind, AccessMode};
    matches!(event.kind, EventKind::Access(kind)
        if kind != AccessKind::Close(AccessMode::Write))
        && !event.need_rescan()
}

fn relative(root: &Path, path: &Path) -> Option<RelPath> {
    RelPath::from_root(root, path).ok()
}

/// Drops paths whose ancestor is also in the set: scanning the ancestor's
/// subtree covers them.
fn outermost(paths: &BTreeSet<RelPath>) -> Vec<&RelPath> {
    let mut result: Vec<&RelPath> = Vec::new();
    for path in paths {
        // Sorted component-wise, so an ancestor always comes first.
        if result.last().is_none_or(|last| !path.starts_with(last)) {
            result.push(path);
        }
    }
    result
}

/// Deviations reported so far, to report only transitions.
struct State<'a> {
    scanner: &'a Scanner,
    baseline: &'a BTreeMap<RelPath, Record>,
    reported: BTreeMap<RelPath, Change>,
    unverified: BTreeSet<RelPath>,
    issues: BTreeMap<(Option<RelPath>, String), IssueRecord>,
}

impl State<'_> {
    fn full_scan(
        &mut self,
        reason: RescanReason,
        source: Source,
        sink: &mut dyn FnMut(WatchEvent),
    ) {
        let snapshot = self.scanner.scan();
        self.apply(None, &snapshot, source, sink);
        sink(WatchEvent::Rescan {
            reason,
            entries_scanned: snapshot.entries.len(),
            deviations: self.reported.len(),
        });
    }

    fn check_subtree(&mut self, path: &RelPath, sink: &mut dyn FnMut(WatchEvent)) {
        let snapshot = self.scanner.scan_subtree(path);
        self.apply(Some(path), &snapshot, Source::Event, sink);
    }

    /// Replaces everything known about `scope` with what `snapshot` shows.
    fn apply(
        &mut self,
        scope: Option<&RelPath>,
        snapshot: &Snapshot,
        source: Source,
        sink: &mut dyn FnMut(WatchEvent),
    ) {
        let in_scope = |p: &RelPath| scope.is_none_or(|s| p.starts_with(s));
        let diff = diff::compare_within(self.baseline, scope, snapshot);

        // Changes: report new or different deviations, then reversions.
        let mut current: BTreeMap<RelPath, Change> = diff
            .changes
            .into_iter()
            .map(|c| (c.path.clone(), c))
            .collect();
        for (path, change) in &current {
            if self.reported.get(path) != Some(change) {
                sink(WatchEvent::Change {
                    source,
                    change: change.clone(),
                });
            }
        }
        let gone: Vec<RelPath> = self
            .reported
            .keys()
            .filter(|p| in_scope(p) && !current.contains_key(*p))
            .cloned()
            .collect();
        for path in gone {
            self.reported.remove(&path);
            // An entry that cannot be checked now is not "reverted".
            if !diff.unverified.contains(&path) {
                sink(WatchEvent::Reverted { source, path });
            }
        }
        self.reported.retain(|p, _| !in_scope(p));
        self.reported.append(&mut current);

        // Unverified entries.
        self.unverified
            .retain(|p| !in_scope(p) || diff.unverified.contains(p));
        for path in diff.unverified {
            if self.unverified.insert(path.clone()) {
                sink(WatchEvent::Unverified { source, path });
            }
        }

        // Issues, deduplicated by location and code.
        let fresh: BTreeMap<_, _> = snapshot
            .issues
            .iter()
            .map(IssueRecord::from)
            .map(|r| ((r.path.clone(), r.code.clone()), r))
            .collect();
        self.issues.retain(|(p, _), _| match (scope, p) {
            // A full scan replaces everything.
            (None, _) => false,
            // Root-level issues outlive subtree checks.
            (Some(_), None) => true,
            (Some(s), Some(p)) => !p.starts_with(s),
        });
        for (key, issue) in fresh {
            if !self.issues.contains_key(&key) {
                sink(WatchEvent::Issue {
                    source,
                    issue: issue.clone(),
                });
            }
            self.issues.insert(key, issue);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::diff::ChangeKind;
    use crate::scan::ScanPolicy;
    use std::fs;
    use std::sync::mpsc::Receiver;
    use std::thread;
    use tempfile::TempDir;

    fn rel(s: &str) -> RelPath {
        RelPath::new(Path::new(s)).unwrap()
    }

    #[test]
    fn outermost_drops_descendants() {
        let set: BTreeSet<RelPath> = ["a", "a/b", "a/b/c", "a-b", "c/d", "c/e"]
            .into_iter()
            .map(rel)
            .collect();
        let result: Vec<String> = outermost(&set).iter().map(ToString::to_string).collect();
        assert_eq!(result, ["a", "a-b", "c/d", "c/e"]);
    }

    /// Runs the watcher on a thread and forwards its events.
    struct Harness {
        events: Receiver<WatchEvent>,
        stop: Arc<AtomicBool>,
        handle: Option<thread::JoinHandle<()>>,
    }

    impl Harness {
        fn start(dir: &Path, options: WatchOptions) -> Self {
            let harness = Self::spawn(dir, options, None);
            // Wait until the initial scan is done.
            harness.wait_for(|e| matches!(e, WatchEvent::Rescan { .. }));
            harness
        }

        /// Like `start`, but the watcher pauses right after registering
        /// (before the initial scan) until `gate` receives a message, so the
        /// event queue is guaranteed not to be drained meanwhile.
        fn spawn(dir: &Path, options: WatchOptions, gate: Option<Receiver<()>>) -> Self {
            let scanner = Scanner::new(dir, ScanPolicy::default()).unwrap();
            let baseline = scanner.scan().entries;
            let (tx, events) = mpsc::channel();
            let stop = Arc::new(AtomicBool::new(false));
            let flag = Arc::clone(&stop);
            let handle = thread::spawn(move || {
                let should_stop = || flag.load(Ordering::Acquire);
                let mut sink = |e: WatchEvent| {
                    let started = matches!(e, WatchEvent::Started { .. });
                    let _ = tx.send(e);
                    if let (true, Some(gate)) = (started, &gate) {
                        let _ = gate.recv();
                    }
                };
                run(&scanner, &baseline, &options, &should_stop, &mut sink).unwrap();
            });
            Harness {
                events,
                stop,
                handle: Some(handle),
            }
        }

        fn wait_for(&self, pred: impl Fn(&WatchEvent) -> bool) -> WatchEvent {
            let deadline = Instant::now() + Duration::from_secs(20);
            loop {
                let left = deadline.saturating_duration_since(Instant::now());
                match self.events.recv_timeout(left) {
                    Ok(e) if pred(&e) => return e,
                    Ok(_) => {}
                    Err(_) => panic!("timed out waiting for watch event"),
                }
            }
        }
    }

    impl Drop for Harness {
        fn drop(&mut self) {
            self.stop.store(true, Ordering::Release);
            if let Some(h) = self.handle.take() {
                let _ = h.join();
            }
        }
    }

    fn fast() -> WatchOptions {
        WatchOptions {
            debounce: Duration::from_millis(100),
            max_latency: Duration::from_secs(1),
            rescan_interval: None,
            ..WatchOptions::default()
        }
    }

    fn change_for<'a>(event: &'a WatchEvent, path: &str) -> Option<&'a Change> {
        match event {
            WatchEvent::Change { change, .. } if change.path == rel(path) => Some(change),
            _ => None,
        }
    }

    #[test]
    fn reports_modification_addition_removal_and_reversion() {
        let dir = TempDir::new().unwrap();
        fs::write(dir.path().join("f"), "abc").unwrap();
        fs::write(dir.path().join("gone"), "x").unwrap();
        let h = Harness::start(dir.path(), fast());

        fs::write(dir.path().join("f"), "changed").unwrap();
        let e = h.wait_for(|e| change_for(e, "f").is_some());
        assert_eq!(change_for(&e, "f").unwrap().kind, ChangeKind::Modified);
        assert!(matches!(
            e,
            WatchEvent::Change {
                source: Source::Event,
                ..
            }
        ));

        fs::write(dir.path().join("new"), "").unwrap();
        let e = h.wait_for(|e| change_for(e, "new").is_some());
        assert_eq!(change_for(&e, "new").unwrap().kind, ChangeKind::Added);

        fs::remove_file(dir.path().join("gone")).unwrap();
        let e = h.wait_for(|e| change_for(e, "gone").is_some());
        assert_eq!(change_for(&e, "gone").unwrap().kind, ChangeKind::Removed);

        // Restoring the original content is reported as a reversion.
        fs::write(dir.path().join("f"), "abc").unwrap();
        h.wait_for(|e| matches!(e, WatchEvent::Reverted { path, .. } if *path == rel("f")));
    }

    #[test]
    fn removing_a_directory_reports_its_contents() {
        let dir = TempDir::new().unwrap();
        fs::create_dir_all(dir.path().join("d/sub")).unwrap();
        fs::write(dir.path().join("d/sub/f"), "x").unwrap();
        let h = Harness::start(dir.path(), fast());

        fs::remove_dir_all(dir.path().join("d")).unwrap();
        h.wait_for(|e| change_for(e, "d/sub/f").is_some_and(|c| c.kind == ChangeKind::Removed));
    }

    #[test]
    fn changes_before_start_are_found_by_initial_scan() {
        let dir = TempDir::new().unwrap();
        fs::write(dir.path().join("f"), "abc").unwrap();
        let scanner = Scanner::new(dir.path(), ScanPolicy::default()).unwrap();
        let baseline = scanner.scan().entries;
        fs::write(dir.path().join("f"), "tampered while not watching").unwrap();

        let mut events = Vec::new();
        let mut sink = |e: WatchEvent| events.push(e);
        // Stop right after startup.
        run(&scanner, &baseline, &fast(), &|| true, &mut sink).unwrap();

        assert!(events.iter().any(|e| matches!(
            e,
            WatchEvent::Change { source: Source::InitialScan, change } if change.path == rel("f")
        )));
        assert!(matches!(
            events.last(),
            Some(WatchEvent::Stopped { deviations: 1 })
        ));
    }

    #[test]
    fn queue_overflow_triggers_reconciliation() {
        let dir = TempDir::new().unwrap();
        let options = WatchOptions {
            queue_capacity: 1,
            ..fast()
        };
        let (gate_tx, gate_rx) = mpsc::channel();
        let h = Harness::spawn(dir.path(), options, Some(gate_rx));
        h.wait_for(|e| matches!(e, WatchEvent::Started { .. }));

        // The watcher is registered but nothing drains its queue now.
        for i in 0..50 {
            fs::write(dir.path().join(format!("f{i}")), "x").unwrap();
        }
        thread::sleep(Duration::from_millis(500));
        gate_tx.send(()).unwrap();

        h.wait_for(|e| {
            matches!(
                e,
                WatchEvent::Rescan {
                    reason: RescanReason::QueueOverflow,
                    ..
                }
            )
        });
    }

    #[test]
    fn periodic_rescan_runs() {
        let dir = TempDir::new().unwrap();
        let options = WatchOptions {
            rescan_interval: Some(Duration::from_millis(200)),
            ..fast()
        };
        let h = Harness::start(dir.path(), options);
        h.wait_for(|e| {
            matches!(
                e,
                WatchEvent::Rescan {
                    reason: RescanReason::Periodic,
                    ..
                }
            )
        });
    }

    #[test]
    fn excluded_paths_are_ignored() {
        let dir = TempDir::new().unwrap();
        let policy = ScanPolicy {
            exclude: vec!["*.tmp".into()],
            ..ScanPolicy::default()
        };
        let scanner = Scanner::new(dir.path(), policy).unwrap();
        let mut state = State {
            scanner: &scanner,
            baseline: &BTreeMap::new(),
            reported: BTreeMap::new(),
            unverified: BTreeSet::new(),
            issues: BTreeMap::new(),
        };
        fs::write(dir.path().join("x.tmp"), "").unwrap();
        let mut events = Vec::new();
        state.check_subtree(&rel("x.tmp"), &mut |e| events.push(e));
        assert!(events.is_empty(), "{events:?}");
    }

    #[test]
    fn read_access_events_are_ignored() {
        use notify::event::{AccessKind, AccessMode, EventKind, ModifyKind};
        let event = |kind| notify::Event::new(kind);
        assert!(is_read_access(&event(EventKind::Access(AccessKind::Open(
            AccessMode::Read
        )))));
        assert!(is_read_access(&event(EventKind::Access(
            AccessKind::Close(AccessMode::Read)
        ))));
        assert!(!is_read_access(&event(EventKind::Access(
            AccessKind::Close(AccessMode::Write)
        ))));
        assert!(!is_read_access(&event(EventKind::Modify(ModifyKind::Any))));
        let lost = event(EventKind::Access(AccessKind::Any)).set_flag(notify::event::Flag::Rescan);
        assert!(!is_read_access(&lost));
    }

    #[test]
    fn event_json_shape() {
        let event = WatchEvent::Reverted {
            source: Source::Event,
            path: rel("a/b"),
        };
        assert_eq!(
            serde_json::to_string(&event).unwrap(),
            r#"{"event":"reverted","source":"event","path":"a/b"}"#
        );
        let change = WatchEvent::Change {
            source: Source::PeriodicRescan,
            change: Change {
                path: rel("x"),
                kind: ChangeKind::Removed,
                before: Some(Record::Directory {}),
                after: None,
            },
        };
        assert_eq!(
            serde_json::to_string(&change).unwrap(),
            r#"{"event":"change","source":"periodic_rescan","path":"x","kind":"removed","before":{"type":"directory"},"after":null}"#
        );
    }
}
