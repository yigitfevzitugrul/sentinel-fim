//! Comparing a scan with a baseline.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::path::RelPath;
use crate::scan::{Record, Snapshot};

/// What happened to one path.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChangeKind {
    Added,
    Removed,
    /// Same type, different content (file contents, link target).
    Modified,
    /// The entry is now of a different type (e.g. a file became a symlink).
    TypeChanged,
}

impl ChangeKind {
    pub fn name(self) -> &'static str {
        match self {
            ChangeKind::Added => "added",
            ChangeKind::Removed => "removed",
            ChangeKind::Modified => "modified",
            ChangeKind::TypeChanged => "type_changed",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Change {
    pub path: RelPath,
    pub kind: ChangeKind,
    /// State in the baseline (`None` for added entries).
    pub before: Option<Record>,
    /// Current state (`None` for removed entries).
    pub after: Option<Record>,
}

/// Differences between a baseline and a scan.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Diff {
    /// Sorted by path.
    pub changes: Vec<Change>,
    /// Baseline entries whose current state is unknown because of scan
    /// issues (e.g. inside an unreadable directory). They are deliberately
    /// *not* reported as removed.
    pub unverified: Vec<RelPath>,
}

impl Diff {
    pub fn is_empty(&self) -> bool {
        self.changes.is_empty() && self.unverified.is_empty()
    }

    pub fn count(&self, kind: ChangeKind) -> usize {
        self.changes.iter().filter(|c| c.kind == kind).count()
    }
}

/// Compares a full scan with the baseline entries.
pub fn compare(baseline: &BTreeMap<RelPath, Record>, snapshot: &Snapshot) -> Diff {
    compare_within(baseline, None, snapshot)
}

/// Like [`compare`], but only for `scope` and the paths below it (`None` for
/// everything). Used for incremental re-checks of a subtree.
pub fn compare_within(
    baseline: &BTreeMap<RelPath, Record>,
    scope: Option<&RelPath>,
    snapshot: &Snapshot,
) -> Diff {
    let in_scope = |path: &RelPath| scope.is_none_or(|s| path.starts_with(s));
    let mut diff = Diff::default();

    for (path, before) in baseline.iter().filter(|(p, _)| in_scope(p)) {
        match snapshot.entries.get(path) {
            Some(after) => {
                if let Some(kind) = classify(before, after) {
                    diff.changes.push(Change {
                        path: path.clone(),
                        kind,
                        before: Some(before.clone()),
                        after: Some(after.clone()),
                    });
                }
            }
            None if snapshot.issues.iter().any(|i| i.covers(path)) => {
                diff.unverified.push(path.clone());
            }
            None => diff.changes.push(Change {
                path: path.clone(),
                kind: ChangeKind::Removed,
                before: Some(before.clone()),
                after: None,
            }),
        }
    }

    for (path, after) in snapshot.entries.iter().filter(|(p, _)| in_scope(p)) {
        if !baseline.contains_key(path) {
            diff.changes.push(Change {
                path: path.clone(),
                kind: ChangeKind::Added,
                before: None,
                after: Some(after.clone()),
            });
        }
    }

    diff.changes
        .sort_by(|a, b| a.path.cmp(&b.path).then(a.kind.cmp(&b.kind)));
    diff
}

fn classify(before: &Record, after: &Record) -> Option<ChangeKind> {
    if before == after {
        return None;
    }
    let same_type = matches!(
        (before, after),
        (Record::File { .. }, Record::File { .. })
            | (Record::Symlink { .. }, Record::Symlink { .. })
    );
    Some(if same_type {
        ChangeKind::Modified
    } else {
        ChangeKind::TypeChanged
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::{Algorithm, Digest};
    use crate::scan::{IssueKind, ScanIssue, SpecialKind};
    use std::path::{Path, PathBuf};

    fn rel(s: &str) -> RelPath {
        RelPath::new(Path::new(s)).unwrap()
    }

    fn digest(data: &[u8]) -> Digest {
        Algorithm::Sha256
            .hash_reader(&mut &data[..])
            .unwrap()
            .digest
    }

    fn file(data: &[u8]) -> Record {
        Record::File {
            size: data.len() as u64,
            digest: digest(data),
        }
    }

    fn map(items: &[(&str, Record)]) -> BTreeMap<RelPath, Record> {
        items.iter().map(|(p, r)| (rel(p), r.clone())).collect()
    }

    fn snapshot(items: &[(&str, Record)], issues: Vec<ScanIssue>) -> Snapshot {
        Snapshot {
            entries: map(items),
            issues,
        }
    }

    fn kinds(diff: &Diff) -> Vec<(String, ChangeKind)> {
        diff.changes
            .iter()
            .map(|c| (c.path.to_string(), c.kind))
            .collect()
    }

    #[test]
    fn identical_is_empty() {
        let items = [("a", file(b"x")), ("d", Record::Directory {})];
        let diff = compare(&map(&items), &snapshot(&items, vec![]));
        assert!(diff.is_empty());
    }

    #[test]
    fn detects_every_kind_of_change() {
        let baseline = map(&[
            ("content", file(b"old")),
            ("gone", file(b"x")),
            (
                "link",
                Record::Symlink {
                    target: PathBuf::from("a"),
                },
            ),
            ("swapped", file(b"x")),
            ("dir", Record::Directory {}),
        ]);
        let current = snapshot(
            &[
                ("content", file(b"new")),
                (
                    "link",
                    Record::Symlink {
                        target: PathBuf::from("b"),
                    },
                ),
                (
                    "swapped",
                    Record::Symlink {
                        target: PathBuf::from("x"),
                    },
                ),
                (
                    "dir",
                    Record::Special {
                        kind: SpecialKind::Fifo,
                    },
                ),
                ("new", file(b"")),
            ],
            vec![],
        );

        let diff = compare(&baseline, &current);
        assert_eq!(
            kinds(&diff),
            [
                ("content".into(), ChangeKind::Modified),
                ("dir".into(), ChangeKind::TypeChanged),
                ("gone".into(), ChangeKind::Removed),
                ("link".into(), ChangeKind::Modified),
                ("new".into(), ChangeKind::Added),
                ("swapped".into(), ChangeKind::TypeChanged),
            ]
        );
        let gone = &diff.changes[2];
        assert_eq!(gone.before, Some(file(b"x")));
        assert_eq!(gone.after, None);
        assert_eq!(diff.count(ChangeKind::TypeChanged), 2);
    }

    #[test]
    fn same_content_different_size_is_modified() {
        let baseline = map(&[("f", file(b"abc"))]);
        let current = snapshot(&[("f", file(b"abcd"))], vec![]);
        assert_eq!(compare(&baseline, &current).count(ChangeKind::Modified), 1);
    }

    #[test]
    fn unreadable_entries_are_unverified_not_removed() {
        let baseline = map(&[
            ("locked", Record::Directory {}),
            ("locked/secret", file(b"x")),
            ("unreadable", file(b"x")),
            ("locked-sibling", file(b"x")),
        ]);
        let current = snapshot(
            &[("locked", Record::Directory {})],
            vec![
                ScanIssue {
                    path: Some(rel("locked")),
                    kind: IssueKind::ChangedDuringScan,
                },
                ScanIssue {
                    path: Some(rel("unreadable")),
                    kind: IssueKind::ChangedDuringScan,
                },
            ],
        );

        let diff = compare(&baseline, &current);
        assert_eq!(diff.unverified, [rel("locked/secret"), rel("unreadable")]);
        // Not covered by any issue: really removed.
        assert_eq!(
            kinds(&diff),
            [("locked-sibling".into(), ChangeKind::Removed)]
        );
    }

    #[test]
    fn root_issue_makes_everything_missing_unverified() {
        let baseline = map(&[("a", file(b"x")), ("b", file(b"y"))]);
        let current = snapshot(
            &[("a", file(b"x"))],
            vec![ScanIssue {
                path: None,
                kind: IssueKind::ChangedDuringScan,
            }],
        );
        let diff = compare(&baseline, &current);
        assert!(diff.changes.is_empty());
        assert_eq!(diff.unverified, [rel("b")]);
    }

    #[test]
    fn scoped_comparison_ignores_other_paths() {
        let baseline = map(&[
            ("a", Record::Directory {}),
            ("a/f", file(b"x")),
            ("b", file(b"y")),
        ]);
        // Subtree scan of "a" after "a/f" was deleted: "b" is not in it.
        let current = snapshot(&[("a", Record::Directory {})], vec![]);
        let diff = compare_within(&baseline, Some(&rel("a")), &current);
        assert_eq!(kinds(&diff), [("a/f".into(), ChangeKind::Removed)]);
    }

    #[test]
    fn change_json_shape() {
        let change = Change {
            path: rel("f"),
            kind: ChangeKind::Removed,
            before: Some(Record::Directory {}),
            after: None,
        };
        let json = serde_json::to_string(&change).unwrap();
        assert_eq!(
            json,
            r#"{"path":"f","kind":"removed","before":{"type":"directory"},"after":null}"#
        );
        assert_eq!(serde_json::from_str::<Change>(&json).unwrap(), change);
    }
}
