//! Ed25519 keys and baseline signatures.
//!
//! A signature proves that a baseline was approved by the holder of a secret
//! key. It only helps if that key is **not** on the monitored machine: an
//! attacker who can rewrite the baseline and read the key can also re-sign.
//! The intended workflow is to create the baseline on the host, review and
//! sign it elsewhere, and give the host only the public key.
//!
//! Key files are single-line text: `<label> ed25519 <hex>`.

use std::fmt;
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::Path;

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::hex;

const SECRET_LABEL: &str = "sentinel-fim-secret-key-v1";
const PUBLIC_LABEL: &str = "sentinel-fim-public-key-v1";

/// Prefix of every signed message, so a baseline signature can never be
/// mistaken for (or reused as) a signature over anything else.
const DOMAIN: &[u8] = b"sentinel-fim baseline signature v1\0";

#[derive(Debug, thiserror::Error)]
pub enum KeyError {
    #[error("cannot read key file {path}: {source}")]
    Read { path: String, source: io::Error },
    #[error("cannot write key file {path}: {source}")]
    Write { path: String, source: io::Error },
    #[error("{path} is not a sentinel-fim {expected} key file")]
    Format {
        path: String,
        expected: &'static str,
    },
    #[error("{path} does not contain a valid Ed25519 public key")]
    InvalidPublicKey { path: String },
    #[error("cannot obtain randomness from the operating system: {0}")]
    Random(String),
}

/// Generates a new key pair from the operating system's CSPRNG.
///
/// # Errors
///
/// If the OS random source fails.
pub fn generate() -> Result<SigningKey, KeyError> {
    let mut seed = Zeroizing::new([0u8; 32]);
    getrandom::fill(seed.as_mut()).map_err(|e| KeyError::Random(e.to_string()))?;
    Ok(SigningKey::from_bytes(&seed))
}

/// Writes a secret key to a new file (never overwrites). On Unix the file is
/// created with mode 0600; on Windows it inherits the directory's ACL.
///
/// # Errors
///
/// If the file exists or cannot be written.
pub fn write_secret_key(path: &Path, key: &SigningKey) -> Result<(), KeyError> {
    let line = Zeroizing::new(format!(
        "{SECRET_LABEL} ed25519 {}\n",
        hex::encode(key.as_bytes())
    ));
    write_new(path, line.as_bytes(), true)
}

/// Writes a public key to a new file (never overwrites).
///
/// # Errors
///
/// If the file exists or cannot be written.
pub fn write_public_key(path: &Path, key: &VerifyingKey) -> Result<(), KeyError> {
    let line = format!("{PUBLIC_LABEL} ed25519 {}\n", hex::encode(key.as_bytes()));
    write_new(path, line.as_bytes(), false)
}

/// # Errors
///
/// If the file cannot be read or is not a secret key file.
pub fn read_secret_key(path: &Path) -> Result<SigningKey, KeyError> {
    let text = Zeroizing::new(read_key_file(path)?);
    let hex_part = parse_line(&text, SECRET_LABEL).ok_or_else(|| KeyError::Format {
        path: path.display().to_string(),
        expected: "secret",
    })?;
    let bytes =
        Zeroizing::new(
            hex::decode_array::<32>(hex_part).map_err(|_| KeyError::Format {
                path: path.display().to_string(),
                expected: "secret",
            })?,
        );
    Ok(SigningKey::from_bytes(&bytes))
}

/// # Errors
///
/// If the file cannot be read, is not a public key file, or holds an invalid
/// curve point.
pub fn read_public_key(path: &Path) -> Result<VerifyingKey, KeyError> {
    let text = read_key_file(path)?;
    let format_error = || KeyError::Format {
        path: path.display().to_string(),
        expected: "public",
    };
    let hex_part = parse_line(&text, PUBLIC_LABEL).ok_or_else(format_error)?;
    let bytes = hex::decode_array::<32>(hex_part).map_err(|_| format_error())?;
    VerifyingKey::from_bytes(&bytes).map_err(|_| KeyError::InvalidPublicKey {
        path: path.display().to_string(),
    })
}

/// Hex form of a public key, used to tell keys apart in output.
pub fn key_id(key: &VerifyingKey) -> String {
    hex::encode(key.as_bytes())
}

/// Signature over a baseline body, as stored in the baseline file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BaselineSignature {
    pub algorithm: SignatureAlgorithm,
    /// Key that made the signature. Informational only: verification always
    /// uses the key supplied by the operator, never this one.
    pub public_key: String,
    pub value: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SignatureAlgorithm {
    Ed25519,
}

impl BaselineSignature {
    pub(crate) fn create(key: &SigningKey, body: &[u8]) -> Self {
        let signature = key.sign(&message(body));
        BaselineSignature {
            algorithm: SignatureAlgorithm::Ed25519,
            public_key: key_id(&key.verifying_key()),
            value: hex::encode(&signature.to_bytes()),
        }
    }

    /// Strict verification (rejects malleable and small-order encodings).
    pub(crate) fn verify(&self, trusted: &VerifyingKey, body: &[u8]) -> bool {
        let Ok(bytes) = hex::decode_array::<64>(&self.value) else {
            return false;
        };
        let signature = Signature::from_bytes(&bytes);
        trusted.verify_strict(&message(body), &signature).is_ok()
    }
}

impl fmt::Display for SignatureAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ed25519")
    }
}

fn message(body: &[u8]) -> Vec<u8> {
    [DOMAIN, body].concat()
}

fn parse_line<'a>(text: &'a str, label: &str) -> Option<&'a str> {
    let mut parts = text.trim().split(' ');
    match (parts.next(), parts.next(), parts.next(), parts.next()) {
        (Some(l), Some("ed25519"), Some(hex_part), None) if l == label => Some(hex_part),
        _ => None,
    }
}

fn read_key_file(path: &Path) -> Result<String, KeyError> {
    fs::read_to_string(path).map_err(|source| KeyError::Read {
        path: path.display().to_string(),
        source,
    })
}

fn write_new(path: &Path, contents: &[u8], secret: bool) -> Result<(), KeyError> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    if secret {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    #[cfg(not(unix))]
    let _ = secret;
    let result = options
        .open(path)
        .and_then(|mut file| file.write_all(contents).and_then(|()| file.sync_all()));
    result.map_err(|source| KeyError::Write {
        path: path.display().to_string(),
        source,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn sign_and_verify() {
        let key = generate().unwrap();
        let sig = BaselineSignature::create(&key, b"body");
        assert!(sig.verify(&key.verifying_key(), b"body"));
        assert!(!sig.verify(&key.verifying_key(), b"bodY"));

        let other = generate().unwrap();
        assert!(!sig.verify(&other.verifying_key(), b"body"));
        assert_eq!(sig.public_key, key_id(&key.verifying_key()));
    }

    #[test]
    fn signature_is_domain_separated() {
        let key = generate().unwrap();
        let raw = key.sign(b"body");
        let sig = BaselineSignature {
            algorithm: SignatureAlgorithm::Ed25519,
            public_key: key_id(&key.verifying_key()),
            value: hex::encode(&raw.to_bytes()),
        };
        assert!(!sig.verify(&key.verifying_key(), b"body"));
    }

    #[test]
    fn malformed_signature_value_fails() {
        let key = generate().unwrap();
        let mut sig = BaselineSignature::create(&key, b"body");
        sig.value = "00".into();
        assert!(!sig.verify(&key.verifying_key(), b"body"));
    }

    #[test]
    fn key_files_round_trip_and_never_overwrite() {
        let dir = TempDir::new().unwrap();
        let (secret, public) = (dir.path().join("k.secret"), dir.path().join("k.pub"));
        let key = generate().unwrap();
        write_secret_key(&secret, &key).unwrap();
        write_public_key(&public, &key.verifying_key()).unwrap();

        assert_eq!(read_secret_key(&secret).unwrap().to_bytes(), key.to_bytes());
        assert_eq!(read_public_key(&public).unwrap(), key.verifying_key());
        assert!(matches!(
            write_secret_key(&secret, &key),
            Err(KeyError::Write { .. })
        ));

        // A public key is not accepted where a secret key is expected.
        assert!(matches!(
            read_secret_key(&public),
            Err(KeyError::Format { .. })
        ));
        assert!(matches!(
            read_public_key(&secret),
            Err(KeyError::Format { .. })
        ));
    }

    #[cfg(unix)]
    #[test]
    fn secret_key_file_is_private() {
        use std::os::unix::fs::PermissionsExt;
        let dir = TempDir::new().unwrap();
        let secret = dir.path().join("k.secret");
        write_secret_key(&secret, &generate().unwrap()).unwrap();
        let mode = fs::metadata(&secret).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    #[test]
    fn rejects_garbage_key_files() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("k");
        for bad in [
            "",
            "sentinel-fim-public-key-v1 ed25519",
            "sentinel-fim-public-key-v1 rsa 00",
            "sentinel-fim-public-key-v1 ed25519 zz",
            "sentinel-fim-public-key-v1 ed25519 00 extra",
        ] {
            fs::write(&path, bad).unwrap();
            assert!(read_public_key(&path).is_err(), "{bad:?}");
        }
    }
}
