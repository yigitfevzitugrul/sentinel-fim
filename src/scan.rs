//! Walking a directory tree and recording the state of every entry.
//!
//! Policy (see the threat model):
//!
//! * Symbolic links are **never followed**; the link itself is recorded with
//!   its target. On Windows this includes junctions and other name-surrogate
//!   reparse points.
//! * Special files (FIFOs, sockets, devices) are recorded by type and never
//!   opened: opening a FIFO can block forever.
//! * Regular files are opened without following links (and, on Unix, without
//!   blocking), then the *opened handle* is checked to still be a regular file.
//!   This closes the window in which an entry is swapped for a link or FIFO
//!   after the directory was listed.
//! * A file whose metadata changes while it is read is reported, not hashed.
//! * Per-entry problems become [`ScanIssue`]s and never abort the scan; only
//!   an unusable root is fatal.

use std::collections::BTreeMap;
use std::fs::{self, File, Metadata, OpenOptions};
use std::io;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use walkdir::WalkDir;

use crate::hash::{Algorithm, Digest};
use crate::path::{RelPath, RelPathError};

/// Settings for a scan.
#[derive(Debug, Clone, Copy, Default)]
pub struct ScanOptions {
    pub algorithm: Algorithm,
}

/// Recorded state of one directory entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Record {
    File {
        size: u64,
        digest: Digest,
    },
    Directory,
    /// The link itself; its target is stored, not followed.
    Symlink {
        target: PathBuf,
    },
    Special(SpecialKind),
}

/// Non-regular, non-directory, non-link entries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpecialKind {
    Fifo,
    Socket,
    BlockDevice,
    CharDevice,
    Unknown,
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

#[derive(Debug, thiserror::Error)]
pub enum IssueKind {
    #[error("{0}")]
    Io(#[from] io::Error),
    #[error("file changed while it was being read")]
    ChangedDuringScan,
    #[error("entry was replaced by a different type while being read")]
    TypeChangedDuringScan,
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
}

/// Result of a full scan.
#[derive(Debug)]
pub struct Snapshot {
    /// Canonical root that was scanned.
    pub root: PathBuf,
    pub algorithm: Algorithm,
    pub entries: BTreeMap<RelPath, Record>,
    pub issues: Vec<ScanIssue>,
}

impl Snapshot {
    /// `true` if every entry under the root was recorded.
    pub fn is_complete(&self) -> bool {
        self.issues.is_empty()
    }
}

/// Scans `root` completely and collects the result.
///
/// # Errors
///
/// Only if the root itself cannot be used; problems with individual entries
/// are reported in [`Snapshot::issues`].
pub fn scan(root: &Path, options: ScanOptions) -> Result<Snapshot, ScanError> {
    let walk = Walk::new(root, options)?;
    let root = walk.root().to_path_buf();

    let mut entries = BTreeMap::new();
    let mut issues = Vec::new();
    for item in walk {
        match item {
            Ok(entry) => {
                entries.insert(entry.path, entry.record);
            }
            Err(issue) => issues.push(issue),
        }
    }

    Ok(Snapshot {
        root,
        algorithm: options.algorithm,
        entries,
        issues,
    })
}

/// Lazy scan: yields one result per entry, in a deterministic order.
///
/// Memory use is bounded by the directory depth, not by the number of files,
/// so callers that do not need the whole [`Snapshot`] can stream.
pub struct Walk {
    root: PathBuf,
    algorithm: Algorithm,
    inner: walkdir::IntoIter,
}

impl Walk {
    /// # Errors
    ///
    /// If `root` does not exist, cannot be resolved, or is not a directory.
    pub fn new(root: &Path, options: ScanOptions) -> Result<Self, ScanError> {
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

        let inner = WalkDir::new(&root)
            .follow_links(false)
            .min_depth(1)
            .sort_by_file_name()
            .into_iter();

        Ok(Walk {
            root,
            algorithm: options.algorithm,
            inner,
        })
    }

    /// Canonical root being walked.
    pub fn root(&self) -> &Path {
        &self.root
    }

    fn visit(&self, entry: &walkdir::DirEntry) -> Result<Entry, ScanIssue> {
        let path = RelPath::from_root(&self.root, entry.path()).map_err(|source| ScanIssue {
            path: None,
            kind: IssueKind::InvalidPath {
                path: entry.path().to_string_lossy().into_owned(),
                source,
            },
        })?;

        // The type comes from the directory listing and does not follow links.
        let file_type = entry.file_type();
        let record = if file_type.is_symlink() {
            fs::read_link(entry.path())
                .map(|target| Record::Symlink { target })
                .map_err(IssueKind::Io)
        } else if file_type.is_dir() {
            Ok(Record::Directory)
        } else if file_type.is_file() {
            hash_file(entry.path(), self.algorithm)
        } else {
            Ok(Record::Special(special_kind(file_type)))
        };

        match record {
            Ok(record) => Ok(Entry { path, record }),
            Err(kind) => Err(ScanIssue {
                path: Some(path),
                kind,
            }),
        }
    }

    fn walk_issue(&self, error: walkdir::Error) -> ScanIssue {
        // A missing path or the root itself maps to `None`.
        let path = error
            .path()
            .and_then(|p| RelPath::from_root(&self.root, p).ok());
        ScanIssue {
            path,
            kind: IssueKind::Io(error.into()),
        }
    }
}

impl Iterator for Walk {
    type Item = Result<Entry, ScanIssue>;

    fn next(&mut self) -> Option<Self::Item> {
        // `?` on an `Option`: the walk is over when walkdir is.
        let item = match self.inner.next()? {
            Ok(entry) => self.visit(&entry),
            Err(error) => Err(self.walk_issue(error)),
        };
        Some(item)
    }
}

/// Hashes a regular file, guarding against swaps and concurrent changes.
fn hash_file(path: &Path, algorithm: Algorithm) -> Result<Record, IssueKind> {
    let mut file = open_regular(path)?;

    let before = file.metadata()?;
    if !before.is_file() {
        return Err(IssueKind::TypeChangedDuringScan);
    }

    let output = algorithm.hash_reader(&mut file)?;

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

/// Opens `path` for reading without following a final symbolic link.
#[cfg(unix)]
fn open_regular(path: &Path) -> Result<File, IssueKind> {
    use std::os::unix::fs::OpenOptionsExt;
    // O_NOFOLLOW: fail instead of opening a link's target.
    // O_NONBLOCK: a FIFO swapped in after listing cannot block the scan; it
    // has no effect on reads of regular files.
    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .map_err(|e| {
            if e.raw_os_error() == Some(libc::ELOOP) {
                // O_NOFOLLOW reports a symlink as ELOOP.
                IssueKind::TypeChangedDuringScan
            } else {
                IssueKind::Io(e)
            }
        })
}

/// Opens `path` for reading without following a reparse point.
#[cfg(windows)]
fn open_regular(path: &Path) -> Result<File, IssueKind> {
    use std::os::windows::fs::OpenOptionsExt;
    // FILE_FLAG_OPEN_REPARSE_POINT (winbase.h): open a symlink or junction
    // itself instead of its target; the type check on the handle then
    // rejects it. Rust's default share mode lets other processes keep
    // reading, writing and deleting while we hash.
    const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
    OpenOptions::new()
        .read(true)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
        .map_err(IssueKind::Io)
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
        scan(dir, ScanOptions::default()).expect("root is usable")
    }

    fn file_digest(snapshot: &Snapshot, path: &str) -> String {
        match &snapshot.entries[&rel(path)] {
            Record::File { digest, .. } => digest.to_string(),
            other => panic!("{path} is not a file: {other:?}"),
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

        let paths: Vec<String> = snap.entries.keys().map(ToString::to_string).collect();
        assert_eq!(
            paths,
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
        assert_eq!(snap.entries[&rel("sub")], Record::Directory);
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
    fn missing_root_is_fatal() {
        let dir = TempDir::new().unwrap();
        let err = scan(&dir.path().join("nope"), ScanOptions::default()).unwrap_err();
        assert!(matches!(err, ScanError::RootUnavailable { .. }), "{err}");
    }

    #[test]
    fn file_root_is_fatal() {
        let dir = TempDir::new().unwrap();
        let file = dir.path().join("f");
        fs::write(&file, "x").unwrap();
        let err = scan(&file, ScanOptions::default()).unwrap_err();
        assert!(matches!(err, ScanError::RootNotDirectory { .. }), "{err}");
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
    fn opening_a_link_as_regular_file_is_refused() {
        // Simulates the race: the listing said "file", but a link is there now.
        let dir = TempDir::new().unwrap();
        fs::write(dir.path().join("target"), "abc").unwrap();
        let link = dir.path().join("link");
        if try_symlink(&dir.path().join("target"), &link, false).is_none() {
            return;
        }
        let result = hash_file(&link, Algorithm::Sha256);
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
            assert_eq!(snap.entries[&rel("locked")], Record::Directory);
            assert!(!snap.entries.contains_key(&rel("locked/hidden")));
            assert_eq!(snap.issues.len(), 1, "{:?}", snap.issues);
            assert_eq!(snap.issues[0].path, Some(rel("locked")));
        }

        #[test]
        fn fifo_is_recorded_and_never_opened() {
            let dir = TempDir::new().unwrap();
            // mkfifo(3) would need unsafe FFI; the coreutils tool is enough.
            let status = std::process::Command::new("mkfifo")
                .arg(dir.path().join("pipe"))
                .status()
                .unwrap();
            assert!(status.success());

            // Would hang forever if the scanner opened the FIFO for reading.
            let snap = scan_dir(dir.path());
            assert!(snap.is_complete(), "{:?}", snap.issues);
            assert_eq!(
                snap.entries[&rel("pipe")],
                Record::Special(SpecialKind::Fifo)
            );
        }

        #[test]
        fn fifo_swapped_in_does_not_block() {
            // The listing said "file", but a FIFO is there when we open it.
            let dir = TempDir::new().unwrap();
            let pipe = dir.path().join("pipe");
            let status = std::process::Command::new("mkfifo")
                .arg(&pipe)
                .status()
                .unwrap();
            assert!(status.success());

            let result = hash_file(&pipe, Algorithm::Sha256);
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
