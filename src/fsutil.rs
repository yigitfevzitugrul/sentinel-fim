//! Crash-safe file output.

use std::io::{self, Write};
use std::path::Path;

use tempfile::NamedTempFile;

/// Writes `contents` to `path` atomically: readers see either the old file or
/// the complete new one, never a partial write, even after a crash.
///
/// The data goes to a temporary file in the same directory, is flushed to
/// disk, and is then renamed over the destination. With `overwrite == false`
/// an existing destination is an error ([`io::ErrorKind::AlreadyExists`]).
///
/// # Errors
///
/// Any I/O error; the destination is left untouched in that case.
pub fn write_atomic(path: &Path, contents: &[u8], overwrite: bool) -> io::Result<()> {
    let dir = match path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => Path::new("."),
    };
    let mut temp = NamedTempFile::new_in(dir)?;
    temp.write_all(contents)?;
    temp.as_file().sync_all()?;

    if overwrite {
        temp.persist(path).map_err(|e| e.error)?;
    } else {
        temp.persist_noclobber(path).map_err(|e| e.error)?;
    }
    sync_dir(dir)
}

/// Makes the rename itself durable. Windows has no equivalent in std; NTFS
/// journals the rename.
#[cfg(unix)]
fn sync_dir(dir: &Path) -> io::Result<()> {
    std::fs::File::open(dir)?.sync_all()
}

#[cfg(not(unix))]
fn sync_dir(_dir: &Path) -> io::Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    #[test]
    fn creates_and_overwrites() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("out.json");
        write_atomic(&path, b"one", false).unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"one");

        let err = write_atomic(&path, b"two", false).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::AlreadyExists);
        assert_eq!(fs::read(&path).unwrap(), b"one");

        write_atomic(&path, b"two", true).unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"two");
        // No temporary files are left behind.
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 1);
    }

    #[test]
    fn missing_directory_fails_cleanly() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("nope/out.json");
        assert!(write_atomic(&path, b"x", true).is_err());
        assert!(!path.exists());
    }
}
