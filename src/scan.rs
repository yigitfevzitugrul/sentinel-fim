//! Walking a directory tree and recording the state of every entry.
//!
//! Policy (see `docs/THREAT_MODEL.md`):
//!
//! * By default symbolic links are **not followed**; the link itself is
//!   recorded with its target. On Windows this includes junctions and other
//!   name-surrogate reparse points. Following is an explicit opt-in
//!   ([`SymlinkPolicy::Follow`]).
//! * Special files (FIFOs, sockets, devices) are recorded by type and never
//!   opened: opening a FIFO can block forever.
//! * Regular files are opened without following links (and, on Unix, without
//!   blocking), then the *opened handle* is checked to still be a regular file.
//!   This closes the window in which an entry is swapped for a link or FIFO
//!   after the directory was listed.
//! * A file whose metadata changes while it is read is reported, not hashed.
//! * Per-entry problems become [`ScanIssue`]s and never abort the scan; only
//!   an unusable root or an invalid policy is fatal.

use std::collections::BTreeMap;
use std::fs::{self, File, Metadata, OpenOptions};
use std::io;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use globset::{GlobBuilder, GlobSet, GlobSetBuilder};
use serde::{Deserialize, Serialize};
use walkdir::WalkDir;

use crate::hash::{Algorithm, BUFFER_SIZE, Digest};
use crate::path::{PathRepr, RelPath, RelPathError};

/// What to do with symbolic links (and Windows junctions).
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SymlinkPolicy {
    /// Record the link and its target; never look behind it. Safe default.
    #[default]
    Record,
    /// Treat links as what they point to. Links may lead outside the root,
    /// and broken links are reported as issues. Loops are detected.
    Follow,
}

/// Everything that determines what a scan records. Stored in the baseline,
/// so a later scan uses exactly the rules the baseline was created with.
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScanPolicy {
    pub algorithm: Algorithm,
    pub symlinks: SymlinkPolicy,
    /// Glob patterns, see [`ScanPolicy::validate`] for the syntax.
    pub exclude: Vec<String>,
    /// Do not descend into other file systems (mount points).
    pub one_file_system: bool,
    /// Files larger than this are reported as issues instead of hashed.
    pub max_file_size: Option<u64>,
}

impl ScanPolicy {
    /// Checks the exclude patterns.
    ///
    /// Patterns always use `/` as separator. A pattern without `/` matches an
    /// entry *name* at any depth (`*.log`). A pattern containing `/` matches
    /// the path relative to the root (`build/**`, `logs/app.log`); a leading
    /// `/` is allowed and ignored. `*` never crosses `/`, `**` does.
    /// Excluding a directory excludes everything below it.
    ///
    /// # Errors
    ///
    /// For empty patterns, `\`, `..` components and invalid glob syntax.
    pub fn validate(&self) -> Result<(), ScanError> {
        Excludes::new(&self.exclude).map(|_| ())
    }
}

/// Recorded state of one directory entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum Record {
    File {
        size: u64,
        digest: Digest,
    },
    Directory {},
    /// The link itself; its target is stored, not followed.
    Symlink {
        #[serde(with = "os_path")]
        target: PathBuf,
    },
    Special {
        kind: SpecialKind,
    },
}

impl Record {
    /// Short type name used in reports.
    pub fn type_name(&self) -> &'static str {
        match self {
            Record::File { .. } => "file",
            Record::Directory {} => "directory",
            Record::Symlink { .. } => "symlink",
            Record::Special { kind } => kind.name(),
        }
    }
}

/// Non-regular, non-directory, non-link entries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SpecialKind {
    Fifo,
    Socket,
    BlockDevice,
    CharDevice,
    Unknown,
}

impl SpecialKind {
    pub fn name(self) -> &'static str {
        match self {
            SpecialKind::Fifo => "fifo",
            SpecialKind::Socket => "socket",
            SpecialKind::BlockDevice => "block_device",
            SpecialKind::CharDevice => "char_device",
            SpecialKind::Unknown => "special",
        }
    }
}

/// Serde adapter storing any OS path losslessly through [`PathRepr`].
pub(crate) mod os_path {
    use super::*;
    use serde::{Deserializer, Serializer};

    pub fn serialize<S: Serializer>(path: &Path, serializer: S) -> Result<S::Ok, S::Error> {
        PathRepr::from_os_str(path.as_os_str()).serialize(serializer)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<PathBuf, D::Error> {
        PathRepr::deserialize(deserializer)?
            .to_os_string()
            .map(PathBuf::from)
            .map_err(serde::de::Error::custom)
    }
}

/// One successfully recorded entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub path: RelPath,
    pub record: Record,
}

/// A problem with one entry. The scan continues, but is incomplete.
#[derive(Debug, thiserror::Error)]
#[error("{}: {kind}", display_location(.path.as_ref()))]
pub struct ScanIssue {
    /// Entry concerned; `None` for the root itself (or a location that could
    /// not be expressed as a [`RelPath`]), meaning nothing below it is known.
    pub path: Option<RelPath>,
    pub kind: IssueKind,
}

impl ScanIssue {
    /// `true` if this issue leaves the state of `path` unknown.
    pub fn covers(&self, path: &RelPath) -> bool {
        self.path.as_ref().is_none_or(|p| path.starts_with(p))
    }
}

#[derive(Debug, thiserror::Error)]
pub enum IssueKind {
    #[error("{0}")]
    Io(#[from] io::Error),
    #[error("file changed while it was being read")]
    ChangedDuringScan,
    #[error("entry was replaced by a different type while being read")]
    TypeChangedDuringScan,
    #[error("file size {size} exceeds the limit of {limit} bytes")]
    TooLarge { size: u64, limit: u64 },
    #[error("unsupported path {path:?}: {source}")]
    InvalidPath { path: String, source: RelPathError },
}

fn display_location(path: Option<&RelPath>) -> String {
    path.map_or_else(|| "<scan root>".to_owned(), ToString::to_string)
}

/// Problems that make the whole scan impossible.
#[derive(Debug, thiserror::Error)]
pub enum ScanError {
    #[error("cannot access scan root {}: {source}", .path.display())]
    RootUnavailable { path: PathBuf, source: io::Error },
    #[error("scan root {} is not a directory", .path.display())]
    RootNotDirectory { path: PathBuf },
    #[error("invalid exclude pattern {pattern:?}: {reason}")]
    InvalidExclude { pattern: String, reason: String },
}

/// Result of a scan.
#[derive(Debug, Default)]
pub struct Snapshot {
    pub entries: BTreeMap<RelPath, Record>,
    pub issues: Vec<ScanIssue>,
}

impl Snapshot {
    /// `true` if every entry under the root was recorded.
    pub fn is_complete(&self) -> bool {
        self.issues.is_empty()
    }

    fn collect(items: impl Iterator<Item = Result<Entry, ScanIssue>>) -> Self {
        let mut snapshot = Snapshot::default();
        for item in items {
            match item {
                Ok(entry) => {
                    snapshot.entries.insert(entry.path, entry.record);
                }
                Err(issue) => snapshot.issues.push(issue),
            }
        }
        snapshot
    }
}

/// Scans `root` completely with `policy`.
///
/// # Errors
///
/// Only if the root is unusable or the policy invalid; problems with
/// individual entries are reported in [`Snapshot::issues`].
pub fn scan(root: &Path, policy: &ScanPolicy) -> Result<Snapshot, ScanError> {
    Ok(Scanner::new(root, policy.clone())?.scan())
}

/// A validated root and policy, ready to scan any number of times.
#[derive(Debug)]
pub struct Scanner {
    root: PathBuf,
    policy: ScanPolicy,
    excludes: Excludes,
}

impl Scanner {
    /// # Errors
    ///
    /// If `root` does not exist, cannot be resolved, or is not a directory,
    /// or if an exclude pattern is invalid.
    pub fn new(root: &Path, policy: ScanPolicy) -> Result<Self, ScanError> {
        let excludes = Excludes::new(&policy.exclude)?;
        // Resolves the operator-supplied root once (following links there is
        // an explicit choice of the operator). On Windows this yields a
        // `\\?\` verbatim path, which disables Win32 name normalization such
        // as stripping trailing dots and spaces: `evil.` stays `evil.` and is
        // not silently opened as `evil`.
        let root = fs::canonicalize(root).map_err(|source| ScanError::RootUnavailable {
            path: root.to_path_buf(),
            source,
        })?;
        if !root.is_dir() {
            return Err(ScanError::RootNotDirectory { path: root });
        }
        Ok(Scanner {
            root,
            policy,
            excludes,
        })
    }

    /// Canonical root.
    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn policy(&self) -> &ScanPolicy {
        &self.policy
    }

    /// Lazy scan of the whole tree, in a deterministic order. Memory use is
    /// bounded by the directory depth, not by the number of files.
    pub fn walk(&self) -> Walk<'_> {
        Walk::new(self, &self.root, 1)
    }

    /// Full scan.
    pub fn scan(&self) -> Snapshot {
        Snapshot::collect(self.walk())
    }

    /// Scans `path` and everything below it. The result is empty if the path
    /// does not exist or is excluded.
    pub fn scan_subtree(&self, path: &RelPath) -> Snapshot {
        if self.is_excluded(path) {
            return Snapshot::default();
        }
        let absolute = path.resolve(&self.root);
        match fs::symlink_metadata(&absolute) {
            Ok(_) => Snapshot::collect(Walk::new(self, &absolute, 0)),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Snapshot::default(),
            Err(e) => Snapshot {
                entries: BTreeMap::new(),
                issues: vec![ScanIssue {
                    path: Some(path.clone()),
                    kind: IssueKind::Io(e),
                }],
            },
        }
    }

    /// `true` if `path` or one of its ancestors matches an exclude pattern.
    pub fn is_excluded(&self, path: &RelPath) -> bool {
        let mut prefix = PathBuf::new();
        path.names().any(|name| {
            prefix.push(name);
            // Every prefix of a valid RelPath is a valid RelPath.
            RelPath::new(&prefix).is_ok_and(|p| self.excludes.matches(&p))
        })
    }

    fn visit(
        &self,
        entry: &walkdir::DirEntry,
        path: RelPath,
        buffer: &mut [u8],
    ) -> Result<Entry, ScanIssue> {
        // From the directory listing; for `Record` it describes the entry
        // itself, for `Follow` the link target.
        let file_type = entry.file_type();
        let record = if file_type.is_symlink() {
            fs::read_link(entry.path())
                .map(|target| Record::Symlink { target })
                .map_err(IssueKind::Io)
        } else if file_type.is_dir() {
            Ok(Record::Directory {})
        } else if file_type.is_file() {
            hash_file(entry.path(), &self.policy, buffer)
        } else {
            Ok(Record::Special {
                kind: special_kind(file_type),
            })
        };

        match record {
            Ok(record) => Ok(Entry { path, record }),
            Err(kind) => Err(ScanIssue {
                path: Some(path),
                kind,
            }),
        }
    }
}

/// Iterator over the entries of a [`Scanner`].
pub struct Walk<'a> {
    scanner: &'a Scanner,
    inner: walkdir::IntoIter,
    /// Read buffer shared by all files of this walk.
    buffer: Vec<u8>,
}

impl<'a> Walk<'a> {
    fn new(scanner: &'a Scanner, start: &Path, min_depth: usize) -> Self {
        let follow = scanner.policy.symlinks == SymlinkPolicy::Follow;
        let inner = WalkDir::new(start)
            .follow_links(follow)
            .follow_root_links(follow)
            .same_file_system(scanner.policy.one_file_system)
            .min_depth(min_depth)
            .sort_by_file_name()
            .into_iter();
        Walk {
            scanner,
            inner,
            buffer: vec![0; BUFFER_SIZE],
        }
    }

    fn walk_issue(&self, error: walkdir::Error) -> ScanIssue {
        // A missing path or the root itself maps to `None`.
        let path = error
            .path()
            .and_then(|p| RelPath::from_root(&self.scanner.root, p).ok());
        ScanIssue {
            path,
            kind: IssueKind::Io(error.into()),
        }
    }
}

impl Iterator for Walk<'_> {
    type Item = Result<Entry, ScanIssue>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            let entry = match self.inner.next()? {
                Ok(entry) => entry,
                Err(error) => return Some(Err(self.walk_issue(error))),
            };
            let path = match RelPath::from_root(&self.scanner.root, entry.path()) {
                Ok(path) => path,
                Err(source) => {
                    return Some(Err(ScanIssue {
                        path: None,
                        kind: IssueKind::InvalidPath {
                            path: entry.path().to_string_lossy().into_owned(),
                            source,
                        },
                    }));
                }
            };
            if self.scanner.excludes.matches(&path) {
                if entry.file_type().is_dir() {
                    self.inner.skip_current_dir();
                }
                continue;
            }
            return Some(self.scanner.visit(&entry, path, &mut self.buffer));
        }
    }
}

/// Compiled exclude patterns.
#[derive(Debug)]
struct Excludes {
    /// Patterns without `/`, matched against the entry name.
    by_name: GlobSet,
    /// Patterns with `/`, matched against the root-relative path.
    by_path: GlobSet,
}

impl Excludes {
    fn new(patterns: &[String]) -> Result<Self, ScanError> {
        let mut by_name = GlobSetBuilder::new();
        let mut by_path = GlobSetBuilder::new();
        for pattern in patterns {
            let invalid = |reason: &str| ScanError::InvalidExclude {
                pattern: pattern.clone(),
                reason: reason.to_owned(),
            };
            let trimmed = pattern.trim_start_matches('/').trim_end_matches('/');
            if trimmed.is_empty() {
                return Err(invalid("pattern is empty"));
            }
            if pattern.contains('\\') {
                return Err(invalid("use '/' as separator; '\\' is not allowed"));
            }
            if trimmed.split('/').any(|part| part == ".." || part == ".") {
                return Err(invalid("'.' and '..' components are not allowed"));
            }
            let glob = GlobBuilder::new(trimmed)
                .literal_separator(true)
                .backslash_escape(false)
                .build()
                .map_err(|e| invalid(&e.kind().to_string()))?;
            if pattern.trim_end_matches('/').contains('/') {
                by_path.add(glob);
            } else {
                by_name.add(glob);
            }
        }
        let build = |builder: GlobSetBuilder| {
            builder.build().map_err(|e| ScanError::InvalidExclude {
                pattern: e.glob().unwrap_or_default().to_owned(),
                reason: e.kind().to_string(),
            })
        };
        Ok(Excludes {
            by_name: build(by_name)?,
            by_path: build(by_path)?,
        })
    }

    fn matches(&self, path: &RelPath) -> bool {
        let name = path.names().last().map(Path::new);
        name.is_some_and(|n| self.by_name.is_match(n)) || self.by_path.is_match(path.as_path())
    }
}

/// Hashes a regular file, guarding against swaps and concurrent changes.
fn hash_file(path: &Path, policy: &ScanPolicy, buffer: &mut [u8]) -> Result<Record, IssueKind> {
    let mut file = open_regular(path, policy.symlinks)?;

    let before = file.metadata()?;
    if !before.is_file() {
        return Err(IssueKind::TypeChangedDuringScan);
    }
    if let Some(limit) = policy.max_file_size
        && before.len() > limit
    {
        return Err(IssueKind::TooLarge {
            size: before.len(),
            limit,
        });
    }

    let output = policy
        .algorithm
        .hash_reader_with_buffer(&mut file, buffer)?;

    let after = file.metadata()?;
    if !is_stable(
        &Fingerprint::of(&before),
        &Fingerprint::of(&after),
        output.bytes_read,
    ) {
        return Err(IssueKind::ChangedDuringScan);
    }

    Ok(Record::File {
        size: output.bytes_read,
        digest: output.digest,
    })
}

/// Opens `path` for reading; with [`SymlinkPolicy::Record`] a final symbolic
/// link is never followed.
#[cfg(unix)]
fn open_regular(path: &Path, symlinks: SymlinkPolicy) -> Result<File, IssueKind> {
    use std::os::unix::fs::OpenOptionsExt;
    // O_NOFOLLOW: fail instead of opening a link's target.
    // O_NONBLOCK: a FIFO swapped in after listing cannot block the scan; it
    // has no effect on reads of regular files.
    let mut flags = libc::O_NONBLOCK;
    if symlinks == SymlinkPolicy::Record {
        flags |= libc::O_NOFOLLOW;
    }
    OpenOptions::new()
        .read(true)
        .custom_flags(flags)
        .open(path)
        .map_err(|e| {
            if e.raw_os_error() == Some(libc::ELOOP) && symlinks == SymlinkPolicy::Record {
                // O_NOFOLLOW reports a symlink as ELOOP.
                IssueKind::TypeChangedDuringScan
            } else {
                IssueKind::Io(e)
            }
        })
}

/// Opens `path` for reading; with [`SymlinkPolicy::Record`] a reparse point
/// is opened itself (and then rejected by the type check), not its target.
#[cfg(windows)]
fn open_regular(path: &Path, symlinks: SymlinkPolicy) -> Result<File, IssueKind> {
    use std::os::windows::fs::OpenOptionsExt;
    // FILE_FLAG_OPEN_REPARSE_POINT (winbase.h). Rust's default share mode
    // lets other processes keep reading, writing and deleting while we hash.
    const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
    let mut options = OpenOptions::new();
    options.read(true);
    if symlinks == SymlinkPolicy::Record {
        options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    }
    options.open(path).map_err(IssueKind::Io)
}

#[cfg(unix)]
fn special_kind(file_type: fs::FileType) -> SpecialKind {
    use std::os::unix::fs::FileTypeExt;
    if file_type.is_fifo() {
        SpecialKind::Fifo
    } else if file_type.is_socket() {
        SpecialKind::Socket
    } else if file_type.is_block_device() {
        SpecialKind::BlockDevice
    } else if file_type.is_char_device() {
        SpecialKind::CharDevice
    } else {
        SpecialKind::Unknown
    }
}

#[cfg(windows)]
fn special_kind(_file_type: fs::FileType) -> SpecialKind {
    SpecialKind::Unknown
}

/// Metadata that changes whenever a file's contents change (to the
/// resolution of the platform's timestamps).
#[derive(Debug, Clone, PartialEq, Eq)]
struct Fingerprint {
    len: u64,
    modified: Option<SystemTime>,
    /// Unix: device, inode and status-change time (ctime cannot be set by
    /// unprivileged users, unlike mtime).
    #[cfg(unix)]
    extra: (u64, u64, i64, i64),
}

impl Fingerprint {
    fn of(metadata: &Metadata) -> Self {
        #[cfg(unix)]
        use std::os::unix::fs::MetadataExt;
        Fingerprint {
            len: metadata.len(),
            modified: metadata.modified().ok(),
            #[cfg(unix)]
            extra: (
                metadata.dev(),
                metadata.ino(),
                metadata.ctime(),
                metadata.ctime_nsec(),
            ),
        }
    }
}

/// A read is trustworthy only if nothing observable changed during it and
/// exactly the advertised number of bytes was read.
fn is_stable(before: &Fingerprint, after: &Fingerprint, bytes_read: u64) -> bool {
    before == after && bytes_read == after.len
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    const ABC_SHA256: &str = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
    const EMPTY_SHA256: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

    fn rel(s: &str) -> RelPath {
        RelPath::new(Path::new(s)).unwrap()
    }

    fn scan_dir(dir: &Path) -> Snapshot {
        scan(dir, &ScanPolicy::default()).expect("root is usable")
    }

    fn scan_with(dir: &Path, policy: ScanPolicy) -> Snapshot {
        scan(dir, &policy).expect("root is usable")
    }

    fn paths(snapshot: &Snapshot) -> Vec<String> {
        snapshot.entries.keys().map(ToString::to_string).collect()
    }

    fn file_digest(snapshot: &Snapshot, path: &str) -> String {
        match &snapshot.entries[&rel(path)] {
            Record::File { digest, .. } => digest.to_string(),
            other => panic!("{path} is not a file: {other:?}"),
        }
    }

    fn excluding(patterns: &[&str]) -> ScanPolicy {
        ScanPolicy {
            exclude: patterns.iter().map(|p| (*p).to_owned()).collect(),
            ..ScanPolicy::default()
        }
    }

    #[test]
    fn empty_directory() {
        let dir = TempDir::new().unwrap();
        let snap = scan_dir(dir.path());
        assert!(snap.entries.is_empty());
        assert!(snap.is_complete());
    }

    #[test]
    fn records_files_directories_and_contents() {
        let dir = TempDir::new().unwrap();
        fs::create_dir_all(dir.path().join("sub/deeper")).unwrap();
        fs::create_dir(dir.path().join("empty-dir")).unwrap();
        fs::write(dir.path().join("abc.txt"), "abc").unwrap();
        fs::write(dir.path().join("sub/deeper/empty"), "").unwrap();

        let snap = scan_dir(dir.path());
        assert!(snap.is_complete(), "{:?}", snap.issues);
        assert_eq!(
            paths(&snap),
            [
                "abc.txt",
                "empty-dir",
                "sub",
                "sub/deeper",
                "sub/deeper/empty"
            ]
        );
        assert_eq!(file_digest(&snap, "abc.txt"), ABC_SHA256);
        assert_eq!(file_digest(&snap, "sub/deeper/empty"), EMPTY_SHA256);
        assert_eq!(snap.entries[&rel("sub")], Record::Directory {});
        assert!(matches!(
            snap.entries[&rel("abc.txt")],
            Record::File { size: 3, .. }
        ));
    }

    #[test]
    fn large_file_spanning_many_buffers() {
        let dir = TempDir::new().unwrap();
        let data = vec![b'a'; 1_000_000];
        fs::write(dir.path().join("big"), &data).unwrap();

        let snap = scan_dir(dir.path());
        assert_eq!(
            file_digest(&snap, "big"),
            "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"
        );
    }

    #[test]
    fn max_file_size_reports_instead_of_hashing() {
        let dir = TempDir::new().unwrap();
        fs::write(dir.path().join("big"), "abcd").unwrap();
        fs::write(dir.path().join("small"), "abc").unwrap();
        let policy = ScanPolicy {
            max_file_size: Some(3),
            ..ScanPolicy::default()
        };

        let snap = scan_with(dir.path(), policy);
        assert_eq!(paths(&snap), ["small"]);
        assert_eq!(snap.issues.len(), 1);
        assert!(matches!(
            snap.issues[0].kind,
            IssueKind::TooLarge { size: 4, limit: 3 }
        ));
    }

    #[test]
    fn missing_root_is_fatal() {
        let dir = TempDir::new().unwrap();
        let err = scan(&dir.path().join("nope"), &ScanPolicy::default()).unwrap_err();
        assert!(matches!(err, ScanError::RootUnavailable { .. }), "{err}");
    }

    #[test]
    fn file_root_is_fatal() {
        let dir = TempDir::new().unwrap();
        let file = dir.path().join("f");
        fs::write(&file, "x").unwrap();
        let err = scan(&file, &ScanPolicy::default()).unwrap_err();
        assert!(matches!(err, ScanError::RootNotDirectory { .. }), "{err}");
    }

    #[test]
    fn exclude_by_name_and_by_path() {
        let dir = TempDir::new().unwrap();
        for d in ["logs", "src/build", "build"] {
            fs::create_dir_all(dir.path().join(d)).unwrap();
        }
        for f in [
            "app.log",
            "logs/x.log",
            "logs/keep.txt",
            "src/main.rs",
            "src/build/out.o",
            "build/top.o",
        ] {
            fs::write(dir.path().join(f), "x").unwrap();
        }

        // "*.log" matches names at any depth; "/build" only at the top.
        let snap = scan_with(dir.path(), excluding(&["*.log", "/build"]));
        assert!(snap.is_complete());
        assert_eq!(
            paths(&snap),
            [
                "logs",
                "logs/keep.txt",
                "src",
                "src/build",
                "src/build/out.o",
                "src/main.rs"
            ]
        );

        // A name pattern on a directory excludes the whole subtree.
        let snap = scan_with(dir.path(), excluding(&["build"]));
        assert!(!paths(&snap).iter().any(|p| p.contains("build")));

        // `*` does not cross `/`, `**` does.
        let snap = scan_with(dir.path(), excluding(&["src/*"]));
        assert!(paths(&snap).contains(&"src".to_owned()));
        assert!(!paths(&snap).iter().any(|p| p.starts_with("src/")));
        let snap = scan_with(dir.path(), excluding(&["**/*.o"]));
        assert!(!paths(&snap).iter().any(|p| p.ends_with(".o")));
    }

    #[test]
    fn invalid_excludes_are_rejected() {
        for bad in ["", "/", r"logs\*.log", "../x", "a/./b", "[unclosed"] {
            let err = excluding(&[bad]).validate().unwrap_err();
            assert!(matches!(err, ScanError::InvalidExclude { .. }), "{bad:?}");
        }
        assert!(excluding(&["*.tmp", "a/**/b", "/top"]).validate().is_ok());
    }

    #[test]
    fn subtree_scan() {
        let dir = TempDir::new().unwrap();
        fs::create_dir_all(dir.path().join("a/b")).unwrap();
        fs::write(dir.path().join("a/b/f"), "abc").unwrap();
        fs::write(dir.path().join("a/g"), "").unwrap();
        fs::write(dir.path().join("other"), "").unwrap();
        let scanner = Scanner::new(dir.path(), excluding(&["g"])).unwrap();

        let snap = scanner.scan_subtree(&rel("a"));
        assert_eq!(paths(&snap), ["a", "a/b", "a/b/f"]);
        let snap = scanner.scan_subtree(&rel("a/b/f"));
        assert_eq!(paths(&snap), ["a/b/f"]);
        assert!(scanner.scan_subtree(&rel("missing")).entries.is_empty());
        assert!(scanner.scan_subtree(&rel("a/g")).entries.is_empty());
        assert!(scanner.is_excluded(&rel("a/g")));
        assert!(!scanner.is_excluded(&rel("a")));
    }

    #[test]
    fn issue_coverage() {
        let issue = ScanIssue {
            path: Some(rel("locked")),
            kind: IssueKind::ChangedDuringScan,
        };
        assert!(issue.covers(&rel("locked")));
        assert!(issue.covers(&rel("locked/inner")));
        assert!(!issue.covers(&rel("locked-not")));
        let root_issue = ScanIssue {
            path: None,
            kind: IssueKind::ChangedDuringScan,
        };
        assert!(root_issue.covers(&rel("anything")));
    }

    #[test]
    fn record_json_forms() {
        let json = |r: &Record| serde_json::to_string(r).unwrap();
        let file = Record::File {
            size: 3,
            digest: crate::hash::Algorithm::Sha256
                .hash_reader(&mut &b"abc"[..])
                .unwrap()
                .digest,
        };
        assert_eq!(
            json(&file),
            format!(r#"{{"type":"file","size":3,"digest":"{ABC_SHA256}"}}"#)
        );
        assert_eq!(json(&Record::Directory {}), r#"{"type":"directory"}"#);
        assert_eq!(
            json(&Record::Symlink {
                target: PathBuf::from("../t")
            }),
            r#"{"type":"symlink","target":"../t"}"#
        );
        assert_eq!(
            json(&Record::Special {
                kind: SpecialKind::Fifo
            }),
            r#"{"type":"special","kind":"fifo"}"#
        );
        for r in [file, Record::Directory {}] {
            assert_eq!(serde_json::from_str::<Record>(&json(&r)).unwrap(), r);
        }
        assert!(serde_json::from_str::<Record>(r#"{"type":"directory","x":1}"#).is_err());
        assert!(serde_json::from_str::<Record>(r#"{"type":"file","size":1}"#).is_err());
    }

    #[test]
    fn stability_check() {
        let base = Fingerprint {
            len: 10,
            modified: Some(SystemTime::UNIX_EPOCH),
            #[cfg(unix)]
            extra: (1, 2, 3, 4),
        };
        assert!(is_stable(&base, &base, 10));
        // Truncated or appended to while reading.
        assert!(!is_stable(&base, &base, 9));
        let grown = Fingerprint {
            len: 11,
            ..base.clone()
        };
        assert!(!is_stable(&base, &grown, 11));
        // Rewritten in place with the same size.
        let touched = Fingerprint {
            modified: Some(SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1)),
            ..base.clone()
        };
        assert!(!is_stable(&base, &touched, 10));
    }

    /// Creates a symlink, or returns `None` where the OS does not allow it
    /// (Windows without Developer Mode or the symlink privilege).
    fn try_symlink(target: &Path, link: &Path, is_dir: bool) -> Option<()> {
        #[cfg(unix)]
        let result = {
            let _ = is_dir;
            std::os::unix::fs::symlink(target, link)
        };
        #[cfg(windows)]
        let result = if is_dir {
            std::os::windows::fs::symlink_dir(target, link)
        } else {
            std::os::windows::fs::symlink_file(target, link)
        };
        match result {
            Ok(()) => Some(()),
            // ERROR_PRIVILEGE_NOT_HELD
            #[cfg(windows)]
            Err(e) if e.raw_os_error() == Some(1314) => {
                eprintln!("SKIPPED: creating symlinks requires Developer Mode on Windows");
                None
            }
            Err(e) => panic!("cannot create symlink: {e}"),
        }
    }

    /// Compares canonical forms: Windows may report targets as `\\?\…`.
    fn assert_link_to(snapshot: &Snapshot, link: &str, expected: &Path) {
        match &snapshot.entries[&rel(link)] {
            Record::Symlink { target } => assert_eq!(
                fs::canonicalize(target).unwrap(),
                fs::canonicalize(expected).unwrap()
            ),
            other => panic!("{link} is not a symlink: {other:?}"),
        }
    }

    #[test]
    fn symlinks_are_recorded_not_followed() {
        let outside = TempDir::new().unwrap();
        fs::write(outside.path().join("secret"), "abc").unwrap();
        let dir = TempDir::new().unwrap();

        let file_link = dir.path().join("file-link");
        let dir_link = dir.path().join("dir-link");
        if try_symlink(&outside.path().join("secret"), &file_link, false).is_none() {
            return;
        }
        try_symlink(outside.path(), &dir_link, true).unwrap();

        let snap = scan_dir(dir.path());
        assert!(snap.is_complete(), "{:?}", snap.issues);
        // Only the two links: nothing behind dir-link was traversed.
        assert_eq!(snap.entries.len(), 2, "{:?}", snap.entries);
        assert_link_to(&snap, "file-link", &outside.path().join("secret"));
        assert_link_to(&snap, "dir-link", outside.path());
    }

    #[test]
    fn follow_policy_looks_behind_links() {
        let outside = TempDir::new().unwrap();
        fs::write(outside.path().join("secret"), "abc").unwrap();
        let dir = TempDir::new().unwrap();
        if try_symlink(outside.path(), &dir.path().join("dir-link"), true).is_none() {
            return;
        }
        let policy = ScanPolicy {
            symlinks: SymlinkPolicy::Follow,
            ..ScanPolicy::default()
        };

        let snap = scan_with(dir.path(), policy);
        assert!(snap.is_complete(), "{:?}", snap.issues);
        assert_eq!(snap.entries[&rel("dir-link")], Record::Directory {});
        assert_eq!(file_digest(&snap, "dir-link/secret"), ABC_SHA256);
    }

    #[test]
    fn follow_policy_detects_loops() {
        let dir = TempDir::new().unwrap();
        fs::create_dir(dir.path().join("a")).unwrap();
        if try_symlink(dir.path(), &dir.path().join("a/loop"), true).is_none() {
            return;
        }
        let policy = ScanPolicy {
            symlinks: SymlinkPolicy::Follow,
            ..ScanPolicy::default()
        };

        // Must terminate, reporting the loop instead of recursing forever.
        let snap = scan_with(dir.path(), policy);
        assert_eq!(snap.issues.len(), 1, "{:?}", snap.issues);
        assert_eq!(snap.issues[0].path, Some(rel("a/loop")));
    }

    #[test]
    fn opening_a_link_as_regular_file_is_refused() {
        // Simulates the race: the listing said "file", but a link is there now.
        let dir = TempDir::new().unwrap();
        fs::write(dir.path().join("target"), "abc").unwrap();
        let link = dir.path().join("link");
        if try_symlink(&dir.path().join("target"), &link, false).is_none() {
            return;
        }
        let result = hash_file(&link, &ScanPolicy::default(), &mut [0; 64]);
        assert!(
            matches!(result, Err(IssueKind::TypeChangedDuringScan)),
            "{result:?}"
        );
    }

    #[cfg(windows)]
    #[test]
    fn junctions_are_not_followed() {
        let outside = TempDir::new().unwrap();
        fs::write(outside.path().join("secret"), "abc").unwrap();
        let dir = TempDir::new().unwrap();
        let junction = dir.path().join("junction");

        // Junctions need no privilege; std has no API to create them.
        let status = std::process::Command::new("cmd")
            .arg("/C")
            .arg("mklink")
            .arg("/J")
            .arg(&junction)
            .arg(outside.path())
            .stdout(std::process::Stdio::null())
            .status()
            .unwrap();
        assert!(status.success());

        let snap = scan_dir(dir.path());
        assert!(snap.is_complete(), "{:?}", snap.issues);
        assert_eq!(snap.entries.len(), 1, "{:?}", snap.entries);
        assert!(matches!(
            snap.entries[&rel("junction")],
            Record::Symlink { .. }
        ));
    }

    #[cfg(windows)]
    #[test]
    fn trailing_dot_names_are_not_confused() {
        // Win32 strips trailing dots, so `evil.` normally opens `evil`.
        let dir = TempDir::new().unwrap();
        let root = fs::canonicalize(dir.path()).unwrap(); // `\\?\` form
        fs::write(root.join("evil"), "").unwrap();
        fs::write(root.join("evil."), "abc").unwrap();

        let snap = scan_dir(dir.path());
        assert!(snap.is_complete(), "{:?}", snap.issues);
        assert_eq!(file_digest(&snap, "evil"), EMPTY_SHA256);
        assert_eq!(file_digest(&snap, "evil."), ABC_SHA256);
    }

    #[cfg(windows)]
    #[test]
    fn locked_file_is_reported_and_scan_continues() {
        use std::os::windows::fs::OpenOptionsExt;
        let dir = TempDir::new().unwrap();
        fs::write(dir.path().join("a-locked"), "x").unwrap();
        fs::write(dir.path().join("b-ok"), "abc").unwrap();
        // Share mode 0: no one else may open the file while this handle lives.
        let _lock = OpenOptions::new()
            .read(true)
            .share_mode(0)
            .open(dir.path().join("a-locked"))
            .unwrap();

        let snap = scan_dir(dir.path());
        assert_eq!(snap.issues.len(), 1, "{:?}", snap.issues);
        assert_eq!(snap.issues[0].path, Some(rel("a-locked")));
        assert!(matches!(snap.issues[0].kind, IssueKind::Io(_)));
        assert_eq!(file_digest(&snap, "b-ok"), ABC_SHA256);
    }

    #[cfg(unix)]
    mod unix {
        use super::*;
        use std::os::unix::fs::PermissionsExt;

        fn chmod(path: &Path, mode: u32) {
            fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
        }

        /// Permission tests are meaningless as root, which bypasses them.
        fn permissions_enforced(dir: &Path) -> bool {
            let probe = dir.join(".probe");
            fs::write(&probe, "x").unwrap();
            chmod(&probe, 0o000);
            let enforced = File::open(&probe).is_err();
            chmod(&probe, 0o600);
            fs::remove_file(&probe).unwrap();
            if !enforced {
                eprintln!("SKIPPED: running as root, permissions are not enforced");
            }
            enforced
        }

        #[test]
        fn unreadable_file_is_reported_and_scan_continues() {
            let dir = TempDir::new().unwrap();
            if !permissions_enforced(dir.path()) {
                return;
            }
            fs::write(dir.path().join("a-secret"), "x").unwrap();
            fs::write(dir.path().join("b-ok"), "abc").unwrap();
            chmod(&dir.path().join("a-secret"), 0o000);

            let snap = scan_dir(dir.path());
            chmod(&dir.path().join("a-secret"), 0o600);

            assert_eq!(snap.issues.len(), 1, "{:?}", snap.issues);
            let issue = &snap.issues[0];
            assert_eq!(issue.path, Some(rel("a-secret")));
            assert!(
                matches!(&issue.kind, IssueKind::Io(e) if e.kind() == io::ErrorKind::PermissionDenied),
                "{issue}"
            );
            assert!(!snap.entries.contains_key(&rel("a-secret")));
            assert_eq!(file_digest(&snap, "b-ok"), ABC_SHA256);
        }

        #[test]
        fn unreadable_directory_is_reported() {
            let dir = TempDir::new().unwrap();
            if !permissions_enforced(dir.path()) {
                return;
            }
            let locked = dir.path().join("locked");
            fs::create_dir(&locked).unwrap();
            fs::write(locked.join("hidden"), "x").unwrap();
            chmod(&locked, 0o000);

            let snap = scan_dir(dir.path());
            chmod(&locked, 0o700);

            // The directory itself is listed, its contents are unknown.
            assert_eq!(snap.entries[&rel("locked")], Record::Directory {});
            assert!(!snap.entries.contains_key(&rel("locked/hidden")));
            assert_eq!(snap.issues.len(), 1, "{:?}", snap.issues);
            assert_eq!(snap.issues[0].path, Some(rel("locked")));
        }

        fn mkfifo(path: &Path) {
            // mkfifo(3) would need unsafe FFI; the coreutils tool is enough.
            let status = std::process::Command::new("mkfifo")
                .arg(path)
                .status()
                .unwrap();
            assert!(status.success());
        }

        #[test]
        fn fifo_is_recorded_and_never_opened() {
            let dir = TempDir::new().unwrap();
            mkfifo(&dir.path().join("pipe"));

            // Would hang forever if the scanner opened the FIFO for reading.
            let snap = scan_dir(dir.path());
            assert!(snap.is_complete(), "{:?}", snap.issues);
            assert_eq!(
                snap.entries[&rel("pipe")],
                Record::Special {
                    kind: SpecialKind::Fifo
                }
            );
        }

        #[test]
        fn fifo_swapped_in_does_not_block() {
            // The listing said "file", but a FIFO is there when we open it.
            let dir = TempDir::new().unwrap();
            let pipe = dir.path().join("pipe");
            mkfifo(&pipe);

            let result = hash_file(&pipe, &ScanPolicy::default(), &mut [0; 64]);
            assert!(
                matches!(result, Err(IssueKind::TypeChangedDuringScan)),
                "{result:?}"
            );
        }

        #[test]
        fn non_utf8_names_are_scanned() {
            use std::ffi::OsStr;
            use std::os::unix::ffi::OsStrExt;
            let dir = TempDir::new().unwrap();
            let name = OsStr::from_bytes(b"bad\xffname");
            fs::write(dir.path().join(name), "abc").unwrap();

            let snap = scan_dir(dir.path());
            assert!(snap.is_complete(), "{:?}", snap.issues);
            let key = RelPath::new(Path::new(name)).unwrap();
            assert!(matches!(snap.entries[&key], Record::File { size: 3, .. }));
        }
    }
}
