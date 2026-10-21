//! Scan reports: a stable JSON document and a human-readable rendering.

use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::baseline::{Loaded, SignatureStatus};
use crate::diff::{Change, ChangeKind, Diff};
use crate::path::{RelPath, display_os_path};
use crate::scan::{self, IssueKind, Record, ScanIssue, Snapshot};

const FORMAT: &str = "sentinel-fim-report";
const VERSION: u32 = 1;

/// Overall outcome of a scan.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    /// Complete scan, no differences.
    Clean,
    /// At least one difference was detected (the scan may also be incomplete).
    Changed,
    /// No difference detected, but some entries could not be checked.
    Incomplete,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScanReport {
    pub format: String,
    pub version: u32,
    pub tool_version: String,
    /// Seconds since the Unix epoch.
    pub generated_at: u64,
    #[serde(with = "scan::os_path")]
    pub root: PathBuf,
    pub baseline: BaselineInfo,
    pub status: Status,
    /// `false` if any entry could not be checked.
    pub complete: bool,
    pub summary: Summary,
    pub changes: Vec<Change>,
    pub unverified: Vec<RelPath>,
    pub issues: Vec<IssueRecord>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BaselineInfo {
    #[serde(with = "scan::os_path")]
    pub path: PathBuf,
    pub created_at: u64,
    pub entries: usize,
    /// `unsigned`, `not checked` or `verified`.
    pub signature: String,
    /// Public key (hex) of the signer, if signed.
    pub signer: Option<String>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Summary {
    pub entries_scanned: usize,
    pub added: usize,
    pub removed: usize,
    pub modified: usize,
    pub type_changed: usize,
    pub unverified: usize,
    pub issues: usize,
}

/// A scan issue in serializable form.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IssueRecord {
    /// `None` means the scan root itself.
    pub path: Option<RelPath>,
    /// Stable machine-readable code.
    pub code: String,
    pub message: String,
}

impl From<&ScanIssue> for IssueRecord {
    fn from(issue: &ScanIssue) -> Self {
        let code = match &issue.kind {
            IssueKind::Io(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
                "permission_denied"
            }
            IssueKind::Io(_) => "io_error",
            IssueKind::ChangedDuringScan => "changed_during_scan",
            IssueKind::TypeChangedDuringScan => "type_changed_during_scan",
            IssueKind::TooLarge { .. } => "too_large",
            IssueKind::InvalidPath { .. } => "invalid_path",
        };
        IssueRecord {
            path: issue.path.clone(),
            code: code.to_owned(),
            message: issue.kind.to_string(),
        }
    }
}

impl ScanReport {
    /// Assembles the report of a scan against `loaded`.
    pub fn new(
        baseline_path: &Path,
        loaded: &Loaded,
        root: &Path,
        snapshot: &Snapshot,
        diff: &Diff,
    ) -> Self {
        let signer = match &loaded.signature {
            SignatureStatus::Unsigned => None,
            SignatureStatus::NotChecked { signer } | SignatureStatus::Verified { signer } => {
                Some(signer.clone())
            }
        };
        let complete = snapshot.is_complete() && diff.unverified.is_empty();
        let status = if !diff.changes.is_empty() {
            Status::Changed
        } else if !complete {
            Status::Incomplete
        } else {
            Status::Clean
        };
        ScanReport {
            format: FORMAT.to_owned(),
            version: VERSION,
            tool_version: env!("CARGO_PKG_VERSION").to_owned(),
            generated_at: unix_now(),
            root: root.to_path_buf(),
            baseline: BaselineInfo {
                path: baseline_path.to_path_buf(),
                created_at: loaded.baseline.created_at,
                entries: loaded.baseline.entries.len(),
                signature: loaded.signature.label().to_owned(),
                signer,
            },
            status,
            complete,
            summary: Summary {
                entries_scanned: snapshot.entries.len(),
                added: diff.count(ChangeKind::Added),
                removed: diff.count(ChangeKind::Removed),
                modified: diff.count(ChangeKind::Modified),
                type_changed: diff.count(ChangeKind::TypeChanged),
                unverified: diff.unverified.len(),
                issues: snapshot.issues.len(),
            },
            changes: diff.changes.clone(),
            unverified: diff.unverified.clone(),
            issues: snapshot.issues.iter().map(IssueRecord::from).collect(),
        }
    }

    /// Parses a saved JSON report.
    ///
    /// # Errors
    ///
    /// If the text is not a report of a supported version.
    pub fn from_json(text: &str) -> Result<Self, String> {
        let report: ScanReport = serde_json::from_str(text).map_err(|e| e.to_string())?;
        if report.format != FORMAT {
            return Err(format!(
                "not a sentinel-fim report (format {:?})",
                report.format
            ));
        }
        if report.version != VERSION {
            return Err(format!("unsupported report version {}", report.version));
        }
        Ok(report)
    }

    pub fn to_json(&self) -> String {
        let mut text = serde_json::to_string_pretty(self).expect("report is serializable");
        text.push('\n');
        text
    }

    /// Human-readable rendering.
    pub fn to_human(&self) -> String {
        let mut out = String::new();
        // Writing to a String cannot fail; results are ignored below.
        let _ = writeln!(out, "Sentinel FIM scan report");
        let _ = writeln!(out, "  root:      {}", display_os_path(&self.root));
        let _ = writeln!(
            out,
            "  baseline:  {} (created {}, {} entries, signature: {})",
            display_os_path(&self.baseline.path),
            format_time(self.baseline.created_at),
            self.baseline.entries,
            self.baseline.signature,
        );
        let _ = writeln!(out, "  scanned:   {}", format_time(self.generated_at));

        if !self.changes.is_empty() {
            let _ = writeln!(out, "\nChanges:");
            for change in &self.changes {
                let _ = writeln!(out, "  {}", describe_change(change));
            }
        }
        if !self.unverified.is_empty() {
            let _ = writeln!(out, "\nUnverified (state unknown because of scan issues):");
            for path in &self.unverified {
                let _ = writeln!(out, "  ? {path}");
            }
        }
        if !self.issues.is_empty() {
            let _ = writeln!(out, "\nIssues:");
            for issue in &self.issues {
                let location = issue
                    .path
                    .as_ref()
                    .map_or_else(|| "<scan root>".to_owned(), ToString::to_string);
                let mut message = String::new();
                let _ = crate::path::write_escaped(&mut message, &issue.message);
                let _ = writeln!(out, "  ! {location}: {message}");
            }
        }

        let s = &self.summary;
        let verdict = match self.status {
            Status::Clean => "CLEAN",
            Status::Changed => "CHANGED",
            Status::Incomplete => "INCOMPLETE",
        };
        let _ = writeln!(
            out,
            "\nResult: {verdict}{} ({} entries scanned; {} added, {} removed, {} modified, \
             {} type changed, {} unverified, {} issues)",
            if self.complete || self.status == Status::Incomplete {
                ""
            } else {
                ", scan incomplete"
            },
            s.entries_scanned,
            s.added,
            s.removed,
            s.modified,
            s.type_changed,
            s.unverified,
            s.issues,
        );
        out
    }
}

/// One line describing a change, e.g. `~ modified     a.txt (content, 3 -> 4 bytes)`.
pub fn describe_change(change: &Change) -> String {
    let (symbol, label) = match change.kind {
        ChangeKind::Added => ('+', "added"),
        ChangeKind::Removed => ('-', "removed"),
        ChangeKind::Modified => ('~', "modified"),
        ChangeKind::TypeChanged => ('!', "type changed"),
    };
    let detail = match (&change.before, &change.after) {
        (None, Some(after)) => describe_record(after),
        (Some(before), None) => describe_record(before),
        (Some(Record::File { size: old, .. }), Some(Record::File { size: new, .. })) => {
            if old == new {
                format!("content changed, {new} bytes")
            } else {
                format!("content changed, {old} -> {new} bytes")
            }
        }
        (Some(Record::Symlink { target: old }), Some(Record::Symlink { target: new })) => format!(
            "link target {} -> {}",
            display_os_path(old),
            display_os_path(new)
        ),
        (Some(before), Some(after)) => {
            format!("{} -> {}", before.type_name(), after.type_name())
        }
        (None, None) => String::new(),
    };
    format!("{symbol} {label:<12} {} ({detail})", change.path)
}

fn describe_record(record: &Record) -> String {
    match record {
        Record::File { size, .. } => format!("file, {size} bytes"),
        Record::Symlink { target } => format!("symlink -> {}", display_os_path(target)),
        other => other.type_name().to_owned(),
    }
}

pub(crate) fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// Formats Unix seconds as `YYYY-MM-DD HH:MM:SS UTC`.
pub fn format_time(secs: u64) -> String {
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    let (y, m, d) = civil_from_days(days);
    format!(
        "{y:04}-{m:02}-{d:02} {:02}:{:02}:{:02} UTC",
        rem / 3600,
        rem % 3600 / 60,
        rem % 60
    )
}

/// Gregorian date from days since 1970-01-01 (H. Hinnant's algorithm).
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let y = yoe + era * 400 + i64::from(m <= 2);
    (y, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::baseline::Baseline;
    use crate::hash::Algorithm;
    use crate::scan::ScanPolicy;
    use std::collections::BTreeMap;

    fn rel(s: &str) -> RelPath {
        RelPath::new(Path::new(s)).unwrap()
    }

    fn file(data: &[u8]) -> Record {
        Record::File {
            size: data.len() as u64,
            digest: Algorithm::Sha256
                .hash_reader(&mut &data[..])
                .unwrap()
                .digest,
        }
    }

    fn report(baseline: &[(&str, Record)], current: Snapshot) -> ScanReport {
        let entries: BTreeMap<_, _> = baseline.iter().map(|(p, r)| (rel(p), r.clone())).collect();
        let loaded = Loaded {
            baseline: Baseline::new(PathBuf::from("/data"), ScanPolicy::default(), entries),
            signature: SignatureStatus::Unsigned,
        };
        let diff = crate::diff::compare(&loaded.baseline.entries, &current);
        ScanReport::new(
            Path::new("baseline.json"),
            &loaded,
            Path::new("/data"),
            &current,
            &diff,
        )
    }

    fn snapshot(items: &[(&str, Record)], issues: Vec<ScanIssue>) -> Snapshot {
        Snapshot {
            entries: items.iter().map(|(p, r)| (rel(p), r.clone())).collect(),
            issues,
        }
    }

    #[test]
    fn clean_report() {
        let items = [("a", file(b"x"))];
        let r = report(&items, snapshot(&items, vec![]));
        assert_eq!(r.status, Status::Clean);
        assert!(r.complete);
        assert!(r.to_human().contains("Result: CLEAN"));
    }

    #[test]
    fn changed_and_incomplete_report() {
        let r = report(
            &[("a", file(b"x")), ("b", file(b"y")), ("locked", file(b"z"))],
            snapshot(
                &[("a", file(b"xx")), ("c", Record::Directory {})],
                vec![ScanIssue {
                    path: Some(rel("locked")),
                    kind: IssueKind::Io(std::io::Error::from(std::io::ErrorKind::PermissionDenied)),
                }],
            ),
        );
        assert_eq!(r.status, Status::Changed);
        assert!(!r.complete);
        assert_eq!(
            r.summary,
            Summary {
                entries_scanned: 2,
                added: 1,
                removed: 1,
                modified: 1,
                type_changed: 0,
                unverified: 1,
                issues: 1
            }
        );
        assert_eq!(r.issues[0].code, "permission_denied");

        let human = r.to_human();
        assert!(
            human.contains("~ modified     a (content changed, 1 -> 2 bytes)"),
            "{human}"
        );
        assert!(
            human.contains("- removed      b (file, 1 bytes)"),
            "{human}"
        );
        assert!(human.contains("+ added        c (directory)"), "{human}");
        assert!(human.contains("? locked"), "{human}");
        assert!(
            human.contains("Result: CHANGED, scan incomplete"),
            "{human}"
        );
    }

    #[test]
    fn incomplete_without_changes() {
        let r = report(
            &[("a", file(b"x"))],
            snapshot(
                &[],
                vec![ScanIssue {
                    path: Some(rel("a")),
                    kind: IssueKind::ChangedDuringScan,
                }],
            ),
        );
        assert_eq!(r.status, Status::Incomplete);
        assert!(r.to_human().contains("Result: INCOMPLETE ("));
    }

    #[test]
    fn json_round_trip() {
        let r = report(&[("a", file(b"x"))], snapshot(&[("b", file(b""))], vec![]));
        let parsed = ScanReport::from_json(&r.to_json()).unwrap();
        assert_eq!(parsed, r);
        assert!(ScanReport::from_json("{}").is_err());
        let other = r.to_json().replacen(FORMAT, "x", 1);
        assert!(ScanReport::from_json(&other).is_err());
    }

    #[test]
    fn hostile_names_are_escaped_in_human_output() {
        let r = report(
            &[],
            snapshot(&[("evil\u{1b}[31mname", Record::Directory {})], vec![]),
        );
        let human = r.to_human();
        assert!(!human.contains('\u{1b}'));
        assert!(human.contains(r"evil\u{1b}[31mname"));
    }

    #[test]
    fn time_formatting() {
        assert_eq!(format_time(0), "1970-01-01 00:00:00 UTC");
        assert_eq!(format_time(951_782_400), "2000-02-29 00:00:00 UTC");
        assert_eq!(format_time(1_792_540_800 + 3661), "2026-10-21 01:01:01 UTC");
    }
}
