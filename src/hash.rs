//! Streaming cryptographic digests of file contents.
//!
//! Data is read through a fixed-size buffer, so memory use does not depend on
//! the size of the input. The algorithm is chosen at runtime through
//! [`Algorithm`] (it will be recorded in the baseline), while each concrete
//! implementation sits behind the private [`Hasher`] trait.

use std::fmt;
use std::io::{self, Read};

use sha2::Digest as _;

/// Read buffer size. Large enough to keep syscall overhead low, small enough
/// to be irrelevant for memory use.
const BUFFER_SIZE: usize = 64 * 1024;

/// Supported digest algorithms.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Algorithm {
    /// SHA-256 (FIPS 180-4). The default and the interoperable choice.
    #[default]
    Sha256,
}

impl Algorithm {
    /// Stable identifier, as it will appear in baselines and reports.
    pub fn name(self) -> &'static str {
        match self {
            Algorithm::Sha256 => "sha256",
        }
    }

    /// Hashes everything `reader` yields until end of input.
    ///
    /// The reader is borrowed, not consumed, so the caller still owns it
    /// afterwards (for example to re-check file metadata).
    ///
    /// # Errors
    ///
    /// Returns any I/O error other than [`io::ErrorKind::Interrupted`], which
    /// is retried. A partial read is never turned into a digest.
    pub fn hash_reader<R: Read + ?Sized>(self, reader: &mut R) -> io::Result<HashOutput> {
        match self {
            Algorithm::Sha256 => stream::<Sha256Hasher, R>(reader),
        }
    }
}

impl fmt::Display for Algorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// A 256-bit digest.
///
/// Every algorithm we support (and BLAKE3, the planned candidate) produces 32
/// bytes, so a fixed-size array avoids a heap allocation per file. The
/// algorithm itself is tracked by the caller, not by each digest.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Digest([u8; 32]);

impl Digest {
    /// Raw digest bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Lowercase hexadecimal, the conventional textual form (as `sha256sum`).
impl fmt::Display for Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.iter().try_for_each(|byte| write!(f, "{byte:02x}"))
    }
}

/// Shows hex instead of a list of 32 numbers.
impl fmt::Debug for Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Digest({self})")
    }
}

/// Result of hashing a stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HashOutput {
    /// Digest of all bytes read.
    pub digest: Digest,
    /// Number of bytes that went into the digest. The scanner compares this
    /// with file metadata to detect files that change while being read.
    pub bytes_read: u64,
}

/// Incremental hashing, implemented once per algorithm.
trait Hasher: Default {
    fn update(&mut self, data: &[u8]);
    fn finalize(self) -> Digest;
}

#[derive(Default)]
struct Sha256Hasher(sha2::Sha256);

impl Hasher for Sha256Hasher {
    fn update(&mut self, data: &[u8]) {
        self.0.update(data);
    }

    fn finalize(self) -> Digest {
        Digest(self.0.finalize().into())
    }
}

/// Feeds `reader` into a fresh `H` through a fixed-size buffer.
fn stream<H: Hasher, R: Read + ?Sized>(reader: &mut R) -> io::Result<HashOutput> {
    let mut hasher = H::default();
    // Heap-allocated: 64 KiB on the stack is avoidable pressure on threads
    // with small stacks, which a parallel scanner may use later.
    let mut buffer = vec![0u8; BUFFER_SIZE];
    let mut bytes_read: u64 = 0;

    loop {
        match reader.read(&mut buffer) {
            Ok(0) => break,
            Ok(n) => {
                hasher.update(&buffer[..n]);
                bytes_read += n as u64;
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }

    Ok(HashOutput {
        digest: hasher.finalize(),
        bytes_read,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sha256_hex(data: &[u8]) -> String {
        // `&[u8]` implements `Read`; reading advances the slice, hence `mut`.
        let mut reader = data;
        Algorithm::Sha256
            .hash_reader(&mut reader)
            .expect("reading from a slice cannot fail")
            .digest
            .to_string()
    }

    // Test vectors from NIST FIPS 180-2 / the SHA-256 examples document.

    #[test]
    fn sha256_empty_input() {
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn sha256_abc() {
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn sha256_448_bit_message() {
        assert_eq!(
            sha256_hex(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"),
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
        );
    }

    #[test]
    fn sha256_one_million_a() {
        // 1 000 000 bytes spans many 64 KiB buffer refills.
        let data = vec![b'a'; 1_000_000];
        assert_eq!(
            sha256_hex(&data),
            "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"
        );
    }

    #[test]
    fn counts_bytes_read() {
        let data = vec![7u8; BUFFER_SIZE * 2 + 1];
        let out = Algorithm::Sha256.hash_reader(&mut data.as_slice()).unwrap();
        assert_eq!(out.bytes_read, data.len() as u64);
    }

    /// Yields at most `chunk` bytes per `read` call, to exercise short reads.
    struct Trickle<'a> {
        data: &'a [u8],
        chunk: usize,
    }

    impl Read for Trickle<'_> {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            let n = self.chunk.min(buf.len()).min(self.data.len());
            buf[..n].copy_from_slice(&self.data[..n]);
            self.data = &self.data[n..];
            Ok(n)
        }
    }

    #[test]
    fn short_reads_give_same_digest() {
        // Length deliberately not a multiple of the buffer or SHA block size.
        let data: Vec<u8> = (0..=255u8).cycle().take(BUFFER_SIZE * 3 + 17).collect();
        let whole = Algorithm::Sha256.hash_reader(&mut data.as_slice()).unwrap();

        for chunk in [1, 63, 64, 65, 4096, BUFFER_SIZE + 1] {
            let mut trickle = Trickle { data: &data, chunk };
            let pieces = Algorithm::Sha256.hash_reader(&mut trickle).unwrap();
            assert_eq!(pieces, whole, "chunk size {chunk}");
        }
    }

    /// Fails with `Interrupted` once, then behaves like the inner reader.
    struct InterruptOnce<R> {
        inner: R,
        interrupted: bool,
    }

    impl<R: Read> Read for InterruptOnce<R> {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            if !self.interrupted {
                self.interrupted = true;
                return Err(io::ErrorKind::Interrupted.into());
            }
            self.inner.read(buf)
        }
    }

    #[test]
    fn interrupted_read_is_retried() {
        let mut reader = InterruptOnce {
            inner: &b"abc"[..],
            interrupted: false,
        };
        let out = Algorithm::Sha256.hash_reader(&mut reader).unwrap();
        assert_eq!(
            out.digest.to_string(),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    /// Returns some data, then a hard error.
    struct FailAfter<'a> {
        data: &'a [u8],
    }

    impl Read for FailAfter<'_> {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            if self.data.is_empty() {
                return Err(io::Error::new(io::ErrorKind::PermissionDenied, "denied"));
            }
            let n = buf.len().min(self.data.len());
            buf[..n].copy_from_slice(&self.data[..n]);
            self.data = &self.data[n..];
            Ok(n)
        }
    }

    #[test]
    fn read_error_is_propagated_not_hashed() {
        let mut reader = FailAfter { data: b"partial" };
        let err = Algorithm::Sha256.hash_reader(&mut reader).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
    }

    #[test]
    fn works_through_trait_object() {
        let mut reader: &[u8] = b"abc";
        let dyn_reader: &mut dyn Read = &mut reader;
        assert!(Algorithm::Sha256.hash_reader(dyn_reader).is_ok());
    }

    #[test]
    fn algorithm_name_and_default() {
        assert_eq!(Algorithm::default(), Algorithm::Sha256);
        assert_eq!(Algorithm::Sha256.to_string(), "sha256");
    }

    #[test]
    fn debug_shows_hex() {
        let d = Algorithm::Sha256.hash_reader(&mut &b""[..]).unwrap().digest;
        assert_eq!(
            format!("{d:?}"),
            "Digest(e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855)"
        );
    }
}
