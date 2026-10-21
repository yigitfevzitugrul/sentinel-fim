//! Lossless, validated paths relative to a scan root.
//!
//! A [`RelPath`] is the key of every baseline entry, so it must satisfy three
//! properties:
//!
//! * **Lossless.** File names are not necessarily UTF-8 (raw bytes on Unix,
//!   possibly unpaired UTF-16 surrogates on Windows). Dropping or mangling such
//!   names would let an attacker hide a file simply by naming it oddly.
//! * **Canonical.** A path has exactly one representation, so two baseline
//!   entries can never alias the same file.
//! * **Contained.** Only plain names are allowed: no `..`, no root, no drive
//!   or UNC prefix and, on Windows, no `:` (alternate data streams). A path
//!   read from an untrusted baseline therefore always stays inside the root
//!   it is joined to.
//!
//! The textual form always uses `/` as separator, on every platform.

use std::ffi::OsStr;
use std::fmt::{self, Write as _};
use std::path::{Component, Path, PathBuf};

#[cfg(not(any(unix, windows)))]
compile_error!("sentinel-fim supports only Unix and Windows targets");

/// Separator of the portable textual form.
const SEPARATOR: char = '/';

/// A non-empty path made only of plain names, relative to a scan root.
///
/// The only ways to obtain one are the validating constructors, so holding a
/// `RelPath` is proof that the path is valid. Ordering is component-wise
/// (`a/b` sorts before `a-b`), which keeps baselines deterministic.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RelPath(PathBuf);

/// Serializable form of a [`RelPath`].
///
/// `Utf8` is used whenever possible. The raw variants exist only for names
/// that are not valid Unicode, and are only accepted on the platform that
/// produced them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PathRepr {
    /// `/`-separated UTF-8 text.
    Utf8(String),
    /// Unix bytes, components separated by `b'/'`.
    UnixBytes(Vec<u8>),
    /// Windows UTF-16 code units, components separated by `'/'` (0x2F).
    WindowsWide(Vec<u16>),
}

/// Reasons a path is rejected.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RelPathError {
    #[error("path is empty")]
    Empty,
    #[error("path is not inside the scan root")]
    OutsideRoot,
    #[error("path contains an empty component")]
    EmptyComponent,
    #[error("path contains {0:?}; only plain names are allowed")]
    ForbiddenComponent(String),
    #[error("path contains an invalid name {0:?}")]
    InvalidName(String),
    #[error("path uses a raw encoding although it is valid UTF-8")]
    NonCanonicalEncoding,
    #[error("path was recorded on {0} and cannot be represented on this platform")]
    ForeignEncoding(&'static str),
}

impl RelPath {
    /// Validates a relative path such as one produced by the directory walker.
    ///
    /// # Errors
    ///
    /// Fails for empty paths and for any component that is not a plain name
    /// (`.`, `..`, a root, a drive or UNC prefix) or is otherwise invalid.
    pub fn new(path: &Path) -> Result<Self, RelPathError> {
        let mut canonical = PathBuf::new();
        for component in path.components() {
            match component {
                Component::Normal(name) => push_name(&mut canonical, name)?,
                other => {
                    let shown = other.as_os_str().to_string_lossy().into_owned();
                    return Err(RelPathError::ForbiddenComponent(shown));
                }
            }
        }
        finish(canonical)
    }

    /// The part of `path` below `root`.
    ///
    /// # Errors
    ///
    /// [`RelPathError::OutsideRoot`] if `path` does not start with `root`,
    /// [`RelPathError::Empty`] if it *is* the root; otherwise as [`RelPath::new`].
    pub fn from_root(root: &Path, path: &Path) -> Result<Self, RelPathError> {
        let relative = path
            .strip_prefix(root)
            .map_err(|_| RelPathError::OutsideRoot)?;
        Self::new(relative)
    }

    /// The path in native form, relative to its root.
    pub fn as_path(&self) -> &Path {
        &self.0
    }

    /// Absolute location of this entry under `root`.
    pub fn resolve(&self, root: &Path) -> PathBuf {
        root.join(&self.0)
    }

    /// Iterates over the plain names that make up the path.
    pub fn names(&self) -> impl Iterator<Item = &OsStr> {
        // The constructors guarantee every component is `Normal`.
        self.0.components().map(Component::as_os_str)
    }

    /// Converts to the serializable form, preferring UTF-8.
    pub fn to_repr(&self) -> PathRepr {
        let utf8: Option<Vec<&str>> = self.names().map(OsStr::to_str).collect();
        match utf8 {
            Some(names) => PathRepr::Utf8(names.join("/")),
            None => self.to_raw_repr(),
        }
    }

    /// Parses the serializable form. Only the canonical encoding is accepted.
    ///
    /// # Errors
    ///
    /// Any violation of the `RelPath` rules, a raw encoding used for a valid
    /// UTF-8 path, or a raw encoding from another platform.
    pub fn from_repr(repr: &PathRepr) -> Result<Self, RelPathError> {
        let path = match repr {
            PathRepr::Utf8(text) => {
                let mut path = PathBuf::new();
                for name in text.split(SEPARATOR) {
                    push_name(&mut path, OsStr::new(name))?;
                }
                path
            }
            raw => Self::from_raw_repr(raw)?,
        };
        let rel = finish(path)?;
        // A raw form must not be a second spelling of a UTF-8 path.
        if !matches!(repr, PathRepr::Utf8(_)) && matches!(rel.to_repr(), PathRepr::Utf8(_)) {
            return Err(RelPathError::NonCanonicalEncoding);
        }
        Ok(rel)
    }

    #[cfg(unix)]
    fn to_raw_repr(&self) -> PathRepr {
        use std::os::unix::ffi::OsStrExt;
        let names: Vec<&[u8]> = self.names().map(OsStrExt::as_bytes).collect();
        PathRepr::UnixBytes(names.join(&b'/'))
    }

    #[cfg(windows)]
    fn to_raw_repr(&self) -> PathRepr {
        use std::os::windows::ffi::OsStrExt;
        let names: Vec<Vec<u16>> = self.names().map(|n| n.encode_wide().collect()).collect();
        PathRepr::WindowsWide(names.join(&(SEPARATOR as u16)))
    }

    #[cfg(unix)]
    fn from_raw_repr(repr: &PathRepr) -> Result<PathBuf, RelPathError> {
        use std::os::unix::ffi::OsStrExt;
        match repr {
            PathRepr::UnixBytes(bytes) => {
                let mut path = PathBuf::new();
                for name in bytes.split(|&b| b == b'/') {
                    push_name(&mut path, OsStr::from_bytes(name))?;
                }
                Ok(path)
            }
            PathRepr::WindowsWide(_) => Err(RelPathError::ForeignEncoding("Windows")),
            PathRepr::Utf8(_) => unreachable!("handled by from_repr"),
        }
    }

    #[cfg(windows)]
    fn from_raw_repr(repr: &PathRepr) -> Result<PathBuf, RelPathError> {
        use std::ffi::OsString;
        use std::os::windows::ffi::OsStringExt;
        match repr {
            PathRepr::WindowsWide(units) => {
                let mut path = PathBuf::new();
                for name in units.split(|&u| u == SEPARATOR as u16) {
                    push_name(&mut path, &OsString::from_wide(name))?;
                }
                Ok(path)
            }
            PathRepr::UnixBytes(_) => Err(RelPathError::ForeignEncoding("Unix")),
            PathRepr::Utf8(_) => unreachable!("handled by from_repr"),
        }
    }
}

/// Validates one name and appends it.
fn push_name(path: &mut PathBuf, name: &OsStr) -> Result<(), RelPathError> {
    if name.is_empty() {
        return Err(RelPathError::EmptyComponent);
    }
    if name == "." || name == ".." {
        return Err(RelPathError::ForbiddenComponent(
            name.to_string_lossy().into_owned(),
        ));
    }
    // The name must parse as exactly one plain component on this platform.
    // This rejects `a\b` and `C:` on Windows, which would otherwise be split
    // or turned into a drive prefix when joined.
    let mut components = Path::new(name).components();
    let single_plain = matches!(
        (components.next(), components.next()),
        (Some(Component::Normal(n)), None) if n == name
    );
    // NUL can never appear in a real file name. `as_encoded_bytes` keeps ASCII
    // as-is on every platform, so byte checks are valid for ASCII characters.
    let bytes = name.as_encoded_bytes();
    let forbidden_byte = bytes.contains(&0) || (cfg!(windows) && bytes.contains(&b':'));
    if !single_plain || forbidden_byte {
        return Err(RelPathError::InvalidName(
            name.to_string_lossy().into_owned(),
        ));
    }
    path.push(name);
    Ok(())
}

fn finish(path: PathBuf) -> Result<RelPath, RelPathError> {
    if path.as_os_str().is_empty() {
        Err(RelPathError::Empty)
    } else {
        Ok(RelPath(path))
    }
}

/// Characters that can reorder or hide text in a terminal ("Trojan Source"
/// style spoofing) even though they are not control characters.
fn is_bidi_control(c: char) -> bool {
    matches!(c, '\u{200E}' | '\u{200F}' | '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}')
}

/// Human-readable form for reports: `/`-separated, invalid Unicode replaced by
/// U+FFFD, and control or bidi characters escaped so a file name cannot inject
/// terminal escape sequences or disguise itself. It is lossy; machine-readable
/// output uses [`RelPath::to_repr`].
impl fmt::Display for RelPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (i, name) in self.names().enumerate() {
            if i > 0 {
                f.write_char(SEPARATOR)?;
            }
            for c in name.to_string_lossy().chars() {
                if c.is_control() || is_bidi_control(c) {
                    write!(f, "{}", c.escape_unicode())?;
                } else {
                    f.write_char(c)?;
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rel(s: &str) -> RelPath {
        RelPath::new(Path::new(s)).unwrap()
    }

    fn utf8(s: &str) -> Result<RelPath, RelPathError> {
        RelPath::from_repr(&PathRepr::Utf8(s.to_owned()))
    }

    #[test]
    fn accepts_plain_relative_paths() {
        let p = rel("dir/sub/file.txt");
        assert_eq!(p.to_string(), "dir/sub/file.txt");
        assert_eq!(p.names().count(), 3);
    }

    #[test]
    fn repeated_separators_are_canonicalized() {
        assert_eq!(rel("a//b/"), rel("a/b"));
        assert_eq!(rel("a//b/").to_repr(), PathRepr::Utf8("a/b".into()));
    }

    #[test]
    fn rejects_empty() {
        assert_eq!(RelPath::new(Path::new("")), Err(RelPathError::Empty));
    }

    #[test]
    fn rejects_non_plain_components() {
        for bad in ["..", "a/../b", "./a", "/etc/passwd"] {
            assert!(
                matches!(
                    RelPath::new(Path::new(bad)),
                    Err(RelPathError::ForbiddenComponent(_))
                ),
                "{bad:?} should be rejected"
            );
        }
    }

    #[cfg(windows)]
    #[test]
    fn rejects_windows_prefixes_and_streams() {
        for bad in [
            r"C:\Windows",
            r"C:x",
            r"\\server\share\x",
            r"\\?\C:\x",
            r"\x",
        ] {
            assert!(
                RelPath::new(Path::new(bad)).is_err(),
                "{bad:?} should be rejected"
            );
        }
        assert!(matches!(
            RelPath::new(Path::new("file.txt:hidden")),
            Err(RelPathError::InvalidName(_))
        ));
    }

    #[cfg(windows)]
    #[test]
    fn windows_backslashes_become_portable() {
        assert_eq!(
            rel(r"dir\sub\file.txt").to_repr(),
            PathRepr::Utf8("dir/sub/file.txt".into())
        );
    }

    #[test]
    fn from_root_strips_root() {
        let root = Path::new("scan-root");
        let p = RelPath::from_root(root, &root.join("a").join("b.txt")).unwrap();
        assert_eq!(p, rel("a/b.txt"));
        assert_eq!(p.resolve(root), root.join("a").join("b.txt"));
    }

    #[test]
    fn from_root_rejects_outside_and_root_itself() {
        let root = Path::new("scan-root");
        assert_eq!(
            RelPath::from_root(root, Path::new("elsewhere/a")),
            Err(RelPathError::OutsideRoot)
        );
        // "scan-root-2" shares a string prefix but not a component prefix.
        assert_eq!(
            RelPath::from_root(root, Path::new("scan-root-2/a")),
            Err(RelPathError::OutsideRoot)
        );
        assert_eq!(RelPath::from_root(root, root), Err(RelPathError::Empty));
    }

    #[test]
    fn utf8_repr_round_trips() {
        for s in ["a", "a/b/c", "ünïcödé/dosya adı.txt", "日本/ファイル"] {
            let p = utf8(s).unwrap();
            assert_eq!(p.to_repr(), PathRepr::Utf8(s.to_owned()));
            assert_eq!(RelPath::from_repr(&p.to_repr()).unwrap(), p);
        }
    }

    #[test]
    fn utf8_repr_must_be_canonical_and_contained() {
        assert_eq!(utf8(""), Err(RelPathError::EmptyComponent));
        for bad in ["a//b", "/a", "a/", "/"] {
            assert_eq!(utf8(bad), Err(RelPathError::EmptyComponent), "{bad:?}");
        }
        for bad in [".", "..", "a/./b", "a/../../etc"] {
            assert!(
                matches!(utf8(bad), Err(RelPathError::ForbiddenComponent(_))),
                "{bad:?}"
            );
        }
        assert!(matches!(utf8("a\0b"), Err(RelPathError::InvalidName(_))));
    }

    #[cfg(windows)]
    #[test]
    fn utf8_repr_rejects_windows_tricks() {
        for bad in [r"a\b", "C:", "C:x", "file.txt:stream", r"..\x"] {
            assert!(
                matches!(utf8(bad), Err(RelPathError::InvalidName(_))),
                "{bad:?}"
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn unix_backslash_and_colon_are_ordinary_characters() {
        let p = utf8(r"a\b:c").unwrap();
        assert_eq!(p.names().count(), 1);
    }

    #[cfg(unix)]
    #[test]
    fn non_utf8_unix_name_round_trips() {
        use std::os::unix::ffi::OsStrExt;
        let name = OsStr::from_bytes(b"bad\xffname");
        let p = RelPath::new(&Path::new("dir").join(name)).unwrap();

        let repr = p.to_repr();
        assert_eq!(repr, PathRepr::UnixBytes(b"dir/bad\xffname".to_vec()));
        assert_eq!(RelPath::from_repr(&repr).unwrap(), p);
        assert_eq!(p.to_string(), "dir/bad\u{FFFD}name");
    }

    #[cfg(unix)]
    #[test]
    fn unix_raw_repr_is_validated() {
        let raw = |b: &[u8]| RelPath::from_repr(&PathRepr::UnixBytes(b.to_vec()));
        assert_eq!(raw(b"valid/utf8"), Err(RelPathError::NonCanonicalEncoding));
        assert_eq!(raw(b"a//\xff"), Err(RelPathError::EmptyComponent));
        assert!(matches!(
            raw(b"../\xff"),
            Err(RelPathError::ForbiddenComponent(_))
        ));
        assert_eq!(
            RelPath::from_repr(&PathRepr::WindowsWide(vec![0xD800])),
            Err(RelPathError::ForeignEncoding("Windows"))
        );
    }

    #[cfg(windows)]
    #[test]
    fn unpaired_surrogate_windows_name_round_trips() {
        use std::ffi::OsString;
        use std::os::windows::ffi::OsStringExt;
        // 'b', 'a', 'd', then an unpaired high surrogate: valid NTFS, not Unicode.
        let name = OsString::from_wide(&[0x62, 0x61, 0x64, 0xD800]);
        let p = RelPath::new(&Path::new("dir").join(&name)).unwrap();

        let repr = p.to_repr();
        assert_eq!(
            repr,
            PathRepr::WindowsWide(vec![0x64, 0x69, 0x72, 0x2F, 0x62, 0x61, 0x64, 0xD800])
        );
        assert_eq!(RelPath::from_repr(&repr).unwrap(), p);
        assert_eq!(p.to_string(), "dir/bad\u{FFFD}");
    }

    #[cfg(windows)]
    #[test]
    fn windows_raw_repr_is_validated() {
        let wide = |s: &str| s.encode_utf16().collect::<Vec<u16>>();
        let raw = |u: Vec<u16>| RelPath::from_repr(&PathRepr::WindowsWide(u));
        assert_eq!(
            raw(wide("valid/utf16")),
            Err(RelPathError::NonCanonicalEncoding)
        );
        assert!(matches!(
            raw(vec![0x2E, 0x2E, 0x2F, 0xD800]),
            Err(RelPathError::ForbiddenComponent(_))
        ));
        assert_eq!(
            RelPath::from_repr(&PathRepr::UnixBytes(vec![0xFF])),
            Err(RelPathError::ForeignEncoding("Unix"))
        );
    }

    #[test]
    fn display_escapes_control_and_bidi_characters() {
        // A name containing an ANSI escape and a newline.
        assert_eq!(
            rel("evil\u{1b}[2Jname\nx").to_string(),
            r"evil\u{1b}[2Jname\u{a}x"
        );
        // U+202E (right-to-left override) can make "exe.txt" look like "txt.exe".
        assert_eq!(rel("a\u{202E}txt.exe").to_string(), r"a\u{202e}txt.exe");
    }

    #[test]
    fn ordering_is_component_wise() {
        let mut paths = vec![rel("a-b"), rel("a/b"), rel("a")];
        paths.sort();
        assert_eq!(paths, vec![rel("a"), rel("a/b"), rel("a-b")]);
    }
}
