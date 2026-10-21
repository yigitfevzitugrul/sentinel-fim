//! The baseline: a trusted record of a tree's state, and its file format.
//!
//! On disk a baseline is a JSON envelope:
//!
//! ```json
//! {
//!   "format": "sentinel-fim-baseline",
//!   "version": 1,
//!   "body_sha256": "<hex>",
//!   "signature": null,
//!   "body": { "tool_version": "...", "created_at": 0, "root": "...",
//!             "policy": { ... }, "entries": [ ... ] }
//! }
//! ```
//!
//! `body_sha256` and the optional Ed25519 `signature` cover the *exact bytes*
//! of `body` as they appear in the file, so verification never depends on
//! re-serializing. The checksum detects accidental corruption only: anyone
//! who can rewrite the file can recompute it. Tampering is detected only by a
//! signature checked against a public key the operator supplies.

use std::collections::BTreeMap;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use ed25519_dalek::{SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::value::RawValue;

use crate::fsutil;
use crate::hash::{Algorithm, Digest};
use crate::path::RelPath;
use crate::scan::{self, Record, ScanPolicy};
use crate::sign::{self, BaselineSignature};

const FORMAT: &str = "sentinel-fim-baseline";
const VERSION: u32 = 1;

/// A trusted snapshot of a tree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Baseline {
    /// Version of the tool that created it.
    pub tool_version: String,
    /// Creation time, seconds since the Unix epoch.
    pub created_at: u64,
    /// Canonical root that was scanned.
    pub root: PathBuf,
    /// Rules the baseline was created with; later scans reuse them.
    pub policy: ScanPolicy,
    pub entries: BTreeMap<RelPath, Record>,
}

/// Result of checking a baseline's signature.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignatureStatus {
    /// No signature present.
    Unsigned,
    /// Signed, but no public key was supplied, so nothing was verified.
    NotChecked { signer: String },
    /// Signature verified against the operator-supplied key.
    Verified { signer: String },
}

impl SignatureStatus {
    pub fn label(&self) -> &'static str {
        match self {
            SignatureStatus::Unsigned => "unsigned",
            SignatureStatus::NotChecked { .. } => "not checked",
            SignatureStatus::Verified { .. } => "verified",
        }
    }
}

/// How strictly to check signatures when loading.
#[derive(Debug, Clone, Copy, Default)]
pub struct Trust<'a> {
    /// If set, a valid signature by this key is required.
    pub public_key: Option<&'a VerifyingKey>,
    /// Reject unsigned baselines even without a key (then a key is needed
    /// to pass at all).
    pub require_signature: bool,
}

/// A baseline read from disk, with the outcome of its integrity checks.
#[derive(Debug)]
pub struct Loaded {
    pub baseline: Baseline,
    pub signature: SignatureStatus,
}

#[derive(Debug, thiserror::Error)]
pub enum BaselineError {
    #[error("cannot read baseline {path}: {source}")]
    Read { path: String, source: io::Error },
    #[error("cannot write baseline {path}: {source}")]
    Write { path: String, source: io::Error },
    #[error("baseline {path} already exists (use --force to replace it)")]
    Exists { path: String },
    #[error("baseline is malformed: {0}")]
    Malformed(String),
    #[error("baseline integrity check failed: {0}")]
    Integrity(String),
}

impl BaselineError {
    /// Integrity failures are reported with their own exit code.
    pub fn is_integrity_failure(&self) -> bool {
        matches!(self, BaselineError::Integrity(_))
    }
}

impl Baseline {
    /// Builds a baseline from a completed scan.
    pub fn new(root: PathBuf, policy: ScanPolicy, entries: BTreeMap<RelPath, Record>) -> Self {
        Baseline {
            tool_version: env!("CARGO_PKG_VERSION").to_owned(),
            created_at: unix_now(),
            root,
            policy,
            entries,
        }
    }

    /// Serializes to the file format, optionally signed.
    pub fn to_bytes(&self, signer: Option<&SigningKey>) -> Vec<u8> {
        let body = serde_json::to_string_pretty(&BodyRef::from(self))
            .expect("baseline body is always serializable");
        let signature = signer.map(|key| BaselineSignature::create(key, body.as_bytes()));
        envelope(body, signature)
    }

    /// Parses and checks the file format.
    ///
    /// # Errors
    ///
    /// [`BaselineError::Malformed`] for invalid structure,
    /// [`BaselineError::Integrity`] for a checksum or signature failure, or a
    /// missing signature when one is required.
    pub fn from_bytes(bytes: &[u8], trust: Trust<'_>) -> Result<Loaded, BaselineError> {
        let envelope = parse_envelope(bytes)?;
        let body = envelope.body.get().as_bytes();

        let signature = match (&envelope.signature, trust.public_key) {
            (None, None) if !trust.require_signature => SignatureStatus::Unsigned,
            (None, _) => {
                return Err(BaselineError::Integrity(
                    "baseline is not signed, but a signature is required".into(),
                ));
            }
            (Some(_), None) if trust.require_signature => {
                return Err(BaselineError::Integrity(
                    "a signature is required, but no public key was given".into(),
                ));
            }
            (Some(sig), None) => SignatureStatus::NotChecked {
                signer: sig.public_key.clone(),
            },
            (Some(sig), Some(key)) => {
                if !sig.verify(key, body) {
                    return Err(BaselineError::Integrity(format!(
                        "signature does not verify with public key {}",
                        sign::key_id(key)
                    )));
                }
                SignatureStatus::Verified {
                    signer: sign::key_id(key),
                }
            }
        };

        let wire: BodyWire = serde_json::from_slice(body)
            .map_err(|e| BaselineError::Malformed(format!("body: {e}")))?;
        Ok(Loaded {
            baseline: wire.into_baseline()?,
            signature,
        })
    }

    /// Reads and checks a baseline file.
    ///
    /// # Errors
    ///
    /// As [`Baseline::from_bytes`], plus read errors.
    pub fn load(path: &Path, trust: Trust<'_>) -> Result<Loaded, BaselineError> {
        let bytes = fs::read(path).map_err(|source| BaselineError::Read {
            path: path.display().to_string(),
            source,
        })?;
        Self::from_bytes(&bytes, trust)
    }

    /// Writes the baseline atomically.
    ///
    /// # Errors
    ///
    /// If the file exists and `overwrite` is false, or on I/O errors.
    pub fn save(
        &self,
        path: &Path,
        signer: Option<&SigningKey>,
        overwrite: bool,
    ) -> Result<(), BaselineError> {
        write_file(path, &self.to_bytes(signer), overwrite)
    }
}

/// Adds (or replaces) the signature of an existing baseline file without
/// touching its body. The checksum is verified first.
///
/// # Errors
///
/// If the file is malformed, fails its checksum, or cannot be written.
pub fn sign_file(path: &Path, key: &SigningKey) -> Result<(), BaselineError> {
    let bytes = fs::read(path).map_err(|source| BaselineError::Read {
        path: path.display().to_string(),
        source,
    })?;
    let envelope = parse_envelope(&bytes)?;
    // Also make sure the body itself is valid before vouching for it.
    let wire: BodyWire = serde_json::from_str(envelope.body.get())
        .map_err(|e| BaselineError::Malformed(format!("body: {e}")))?;
    wire.into_baseline()?;

    let body = envelope.body.get();
    let signed = envelope_raw(
        envelope.body,
        Some(BaselineSignature::create(key, body.as_bytes())),
    );
    write_file(path, &signed, true)
}

fn write_file(path: &Path, bytes: &[u8], overwrite: bool) -> Result<(), BaselineError> {
    fsutil::write_atomic(path, bytes, overwrite).map_err(|source| {
        if source.kind() == io::ErrorKind::AlreadyExists {
            BaselineError::Exists {
                path: path.display().to_string(),
            }
        } else {
            BaselineError::Write {
                path: path.display().to_string(),
                source,
            }
        }
    })
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

fn body_digest(body: &[u8]) -> Digest {
    let mut reader = body;
    Algorithm::Sha256
        .hash_reader(&mut reader)
        .expect("reading from memory cannot fail")
        .digest
}

#[derive(Serialize)]
struct EnvelopeOut<'a> {
    format: &'static str,
    version: u32,
    body_sha256: Digest,
    signature: Option<BaselineSignature>,
    body: &'a RawValue,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EnvelopeIn<'a> {
    format: String,
    version: u32,
    body_sha256: Digest,
    signature: Option<BaselineSignature>,
    #[serde(borrow)]
    body: &'a RawValue,
}

/// Takes the body by value: it can be large, and is moved, not copied.
fn envelope(body: String, signature: Option<BaselineSignature>) -> Vec<u8> {
    let raw = RawValue::from_string(body).expect("body is valid JSON");
    envelope_raw(&raw, signature)
}

fn envelope_raw(body: &RawValue, signature: Option<BaselineSignature>) -> Vec<u8> {
    let out = EnvelopeOut {
        format: FORMAT,
        version: VERSION,
        body_sha256: body_digest(body.get().as_bytes()),
        signature,
        body,
    };
    let mut bytes = serde_json::to_vec_pretty(&out).expect("envelope is serializable");
    bytes.push(b'\n');
    bytes
}

fn parse_envelope(bytes: &[u8]) -> Result<EnvelopeIn<'_>, BaselineError> {
    let envelope: EnvelopeIn<'_> =
        serde_json::from_slice(bytes).map_err(|e| BaselineError::Malformed(e.to_string()))?;
    if envelope.format != FORMAT {
        return Err(BaselineError::Malformed(format!(
            "not a sentinel-fim baseline (format {:?})",
            envelope.format
        )));
    }
    if envelope.version != VERSION {
        return Err(BaselineError::Malformed(format!(
            "unsupported baseline version {} (this tool reads version {VERSION})",
            envelope.version
        )));
    }
    if body_digest(envelope.body.get().as_bytes()) != envelope.body_sha256 {
        return Err(BaselineError::Integrity(
            "body checksum mismatch (the file is corrupted or was edited)".into(),
        ));
    }
    Ok(envelope)
}

/// One entry as stored: `{"path": ..., "type": ..., ...}`.
#[derive(Serialize, Deserialize)]
struct EntryWire {
    path: RelPath,
    #[serde(flatten)]
    record: Record,
}

#[derive(Serialize)]
struct BodyRef<'a> {
    tool_version: &'a str,
    created_at: u64,
    #[serde(with = "scan::os_path")]
    root: &'a Path,
    policy: &'a ScanPolicy,
    entries: Vec<EntryRef<'a>>,
}

#[derive(Serialize)]
struct EntryRef<'a> {
    path: &'a RelPath,
    #[serde(flatten)]
    record: &'a Record,
}

impl<'a> From<&'a Baseline> for BodyRef<'a> {
    fn from(b: &'a Baseline) -> Self {
        BodyRef {
            tool_version: &b.tool_version,
            created_at: b.created_at,
            root: &b.root,
            policy: &b.policy,
            entries: b
                .entries
                .iter()
                .map(|(path, record)| EntryRef { path, record })
                .collect(),
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BodyWire {
    tool_version: String,
    created_at: u64,
    #[serde(with = "scan::os_path")]
    root: PathBuf,
    policy: ScanPolicy,
    entries: Vec<EntryWire>,
}

impl BodyWire {
    fn into_baseline(self) -> Result<Baseline, BaselineError> {
        self.policy
            .validate()
            .map_err(|e| BaselineError::Malformed(format!("policy: {e}")))?;
        let mut entries = BTreeMap::new();
        for entry in self.entries {
            if let Some(_previous) = entries.insert(entry.path.clone(), entry.record) {
                return Err(BaselineError::Malformed(format!(
                    "duplicate entry {}",
                    entry.path
                )));
            }
        }
        Ok(Baseline {
            tool_version: self.tool_version,
            created_at: self.created_at,
            root: self.root,
            policy: self.policy,
            entries,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scan::SpecialKind;
    use tempfile::TempDir;

    fn rel(s: &str) -> RelPath {
        RelPath::new(Path::new(s)).unwrap()
    }

    fn sample() -> Baseline {
        let digest = Algorithm::Sha256
            .hash_reader(&mut &b"abc"[..])
            .unwrap()
            .digest;
        let mut entries = BTreeMap::new();
        entries.insert(rel("a.txt"), Record::File { size: 3, digest });
        entries.insert(rel("dir"), Record::Directory {});
        entries.insert(
            rel("dir/link"),
            Record::Symlink {
                target: PathBuf::from("../a.txt"),
            },
        );
        entries.insert(
            rel("pipe"),
            Record::Special {
                kind: SpecialKind::Fifo,
            },
        );
        let policy = ScanPolicy {
            exclude: vec!["*.tmp".into()],
            ..ScanPolicy::default()
        };
        Baseline::new(PathBuf::from("/srv/data"), policy, entries)
    }

    fn load(bytes: &[u8]) -> Result<Loaded, BaselineError> {
        Baseline::from_bytes(bytes, Trust::default())
    }

    #[test]
    fn round_trip() {
        let b = sample();
        let loaded = load(&b.to_bytes(None)).unwrap();
        assert_eq!(loaded.baseline, b);
        assert_eq!(loaded.signature, SignatureStatus::Unsigned);
    }

    #[test]
    fn output_is_deterministic() {
        let b = sample();
        assert_eq!(b.to_bytes(None), b.to_bytes(None));
    }

    #[test]
    fn edited_body_fails_checksum() {
        let bytes = String::from_utf8(sample().to_bytes(None)).unwrap();
        let tampered = bytes.replacen("\"size\": 3", "\"size\": 4", 1);
        assert_ne!(bytes, tampered);
        let err = load(tampered.as_bytes()).unwrap_err();
        assert!(err.is_integrity_failure(), "{err}");
    }

    #[test]
    fn truncated_or_garbage_files_are_malformed() {
        let bytes = sample().to_bytes(None);
        for bad in [&bytes[..bytes.len() / 2], b"", b"{}", b"[]", b"not json"] {
            let err = load(bad).unwrap_err();
            assert!(matches!(err, BaselineError::Malformed(_)), "{err}");
        }
    }

    #[test]
    fn wrong_format_or_version_is_rejected() {
        let text = String::from_utf8(sample().to_bytes(None)).unwrap();
        let other = text.replacen(FORMAT, "something-else", 1);
        assert!(matches!(
            load(other.as_bytes()),
            Err(BaselineError::Malformed(_))
        ));
        let newer = text.replacen("\"version\": 1", "\"version\": 2", 1);
        assert!(matches!(
            load(newer.as_bytes()),
            Err(BaselineError::Malformed(_))
        ));
    }

    /// Builds a file whose checksum is valid for an arbitrary body, as an
    /// attacker without the signing key could.
    fn forge(body: &str) -> Vec<u8> {
        envelope(body.to_owned(), None)
    }

    #[test]
    fn body_is_strictly_validated() {
        let ok = r#"{"tool_version":"x","created_at":0,"root":"/r","policy":{"algorithm":"sha256","symlinks":"record","exclude":[],"one_file_system":false,"max_file_size":null},"entries":[]}"#;
        assert!(load(&forge(ok)).is_ok());

        let unknown_field = ok.replacen("\"entries\"", "\"extra\":1,\"entries\"", 1);
        let traversal = ok.replacen(
            "\"entries\":[]",
            r#""entries":[{"path":"../x","type":"directory"}]"#,
            1,
        );
        let duplicate = ok.replacen(
            "\"entries\":[]",
            r#""entries":[{"path":"x","type":"directory"},{"path":"x","type":"directory"}]"#,
            1,
        );
        let unknown_entry_field = ok.replacen(
            "\"entries\":[]",
            r#""entries":[{"path":"x","type":"directory","mode":1}]"#,
            1,
        );
        let bad_exclude = ok.replacen("\"exclude\":[]", r#""exclude":["../x"]"#, 1);
        for bad in [
            unknown_field,
            traversal,
            duplicate,
            unknown_entry_field,
            bad_exclude,
        ] {
            assert!(
                matches!(load(&forge(&bad)), Err(BaselineError::Malformed(_))),
                "{bad}"
            );
        }
    }

    #[test]
    fn signatures() {
        let key = sign::generate().unwrap();
        let public = key.verifying_key();
        let other = sign::generate().unwrap().verifying_key();
        let b = sample();
        let signed = b.to_bytes(Some(&key));
        let unsigned = b.to_bytes(None);

        let with_key = |bytes: &[u8], key| {
            Baseline::from_bytes(
                bytes,
                Trust {
                    public_key: Some(key),
                    require_signature: false,
                },
            )
        };

        let loaded = with_key(&signed, &public).unwrap();
        assert!(matches!(loaded.signature, SignatureStatus::Verified { .. }));
        assert!(matches!(
            load(&signed).unwrap().signature,
            SignatureStatus::NotChecked { .. }
        ));
        assert!(
            with_key(&signed, &other)
                .unwrap_err()
                .is_integrity_failure()
        );
        assert!(
            with_key(&unsigned, &public)
                .unwrap_err()
                .is_integrity_failure()
        );

        let required = Trust {
            public_key: None,
            require_signature: true,
        };
        assert!(
            Baseline::from_bytes(&unsigned, required)
                .unwrap_err()
                .is_integrity_failure()
        );
        assert!(
            Baseline::from_bytes(&signed, required)
                .unwrap_err()
                .is_integrity_failure()
        );
    }

    #[test]
    fn forged_body_with_valid_checksum_fails_signature() {
        let key = sign::generate().unwrap();
        let signed = String::from_utf8(sample().to_bytes(Some(&key))).unwrap();
        // Attacker edits the body and recomputes the checksum, keeping the
        // old signature.
        let start = signed.find("\"body\": ").unwrap() + "\"body\": ".len();
        let end = signed.rfind('}').unwrap();
        let body = signed[start..end]
            .trim_end()
            .replacen("\"size\": 3", "\"size\": 4", 1);
        let sig_start = signed.find("\"signature\": ").unwrap() + "\"signature\": ".len();
        let sig_end = signed[sig_start..].find("},").unwrap() + sig_start + 1;
        let signature: BaselineSignature =
            serde_json::from_str(&signed[sig_start..sig_end]).unwrap();
        let forged = envelope(body, Some(signature));

        let err = Baseline::from_bytes(
            &forged,
            Trust {
                public_key: Some(&key.verifying_key()),
                require_signature: true,
            },
        )
        .unwrap_err();
        assert!(err.is_integrity_failure(), "{err}");
    }

    #[test]
    fn save_and_sign_file() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("baseline.json");
        let b = sample();
        b.save(&path, None, false).unwrap();
        assert!(matches!(
            b.save(&path, None, false),
            Err(BaselineError::Exists { .. })
        ));

        let key = sign::generate().unwrap();
        sign_file(&path, &key).unwrap();
        let loaded = Baseline::load(
            &path,
            Trust {
                public_key: Some(&key.verifying_key()),
                require_signature: true,
            },
        )
        .unwrap();
        assert_eq!(loaded.baseline, b);

        // Signing never changes the body.
        let unsigned = b.to_bytes(None);
        let unsigned_env = parse_envelope(&unsigned).unwrap();
        let signed = fs::read(&path).unwrap();
        let signed_env = parse_envelope(&signed).unwrap();
        assert_eq!(unsigned_env.body.get(), signed_env.body.get());
    }

    #[test]
    fn sign_file_refuses_corrupt_baseline() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("baseline.json");
        let text = String::from_utf8(sample().to_bytes(None)).unwrap();
        fs::write(&path, text.replacen("\"size\": 3", "\"size\": 4", 1)).unwrap();
        let err = sign_file(&path, &sign::generate().unwrap()).unwrap_err();
        assert!(err.is_integrity_failure());
    }
}
