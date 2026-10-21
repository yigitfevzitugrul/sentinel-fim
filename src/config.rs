//! Optional TOML configuration file.
//!
//! The file is only read when given explicitly (`--config`); there is no
//! implicit lookup in the working directory, which an attacker might control.
//! Command-line options take precedence over the file; exclude patterns from
//! both are combined. Relative paths are resolved against the directory that
//! contains the configuration file.
//!
//! ```toml
//! root = "/srv/data"
//! baseline = "/var/lib/sentinel-fim/baseline.json"
//! public_key = "/etc/sentinel-fim/baseline.pub"
//! require_signature = true
//! exclude = ["*.tmp", "/cache"]
//! follow_symlinks = false
//! one_file_system = true
//! max_file_size = 1073741824
//!
//! [watch]
//! debounce_ms = 500
//! rescan_interval_secs = 3600
//! ```

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use serde::Deserialize;

#[derive(Debug, Default, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Directory to monitor (used by `init`).
    pub root: Option<PathBuf>,
    pub baseline: Option<PathBuf>,
    pub public_key: Option<PathBuf>,
    pub require_signature: Option<bool>,
    #[serde(default)]
    pub exclude: Vec<String>,
    pub follow_symlinks: Option<bool>,
    pub one_file_system: Option<bool>,
    pub max_file_size: Option<u64>,
    #[serde(default)]
    pub watch: WatchConfig,
}

#[derive(Debug, Default, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WatchConfig {
    pub debounce_ms: Option<u64>,
    pub rescan_interval_secs: Option<u64>,
}

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("cannot read configuration file {path}: {source}")]
    Read { path: String, source: io::Error },
    #[error("invalid configuration file {path}: {message}")]
    Parse { path: String, message: String },
}

impl Config {
    /// Reads and parses a configuration file.
    ///
    /// # Errors
    ///
    /// If the file cannot be read or contains unknown or mistyped keys.
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        let text = fs::read_to_string(path).map_err(|source| ConfigError::Read {
            path: path.display().to_string(),
            source,
        })?;
        let mut config = Self::parse(&text).map_err(|message| ConfigError::Parse {
            path: path.display().to_string(),
            message,
        })?;
        let base = path.parent().unwrap_or(Path::new(""));
        for field in [
            &mut config.root,
            &mut config.baseline,
            &mut config.public_key,
        ] {
            if let Some(p) = field.as_mut()
                && p.is_relative()
            {
                *p = base.join(&*p);
            }
        }
        Ok(config)
    }

    /// Parses configuration text (paths are left as written).
    ///
    /// # Errors
    ///
    /// A description of the first problem found.
    pub fn parse(text: &str) -> Result<Self, String> {
        toml::from_str(text).map_err(|e| e.message().to_owned())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn full_example_parses() {
        let config = Config::parse(
            r#"
            root = "/srv/data"
            baseline = "base.json"
            public_key = "k.pub"
            require_signature = true
            exclude = ["*.tmp", "/cache"]
            follow_symlinks = false
            one_file_system = true
            max_file_size = 1024
            [watch]
            debounce_ms = 250
            rescan_interval_secs = 60
            "#,
        )
        .unwrap();
        assert_eq!(config.root, Some(PathBuf::from("/srv/data")));
        assert_eq!(config.exclude, ["*.tmp", "/cache"]);
        assert_eq!(config.max_file_size, Some(1024));
        assert_eq!(config.watch.rescan_interval_secs, Some(60));
    }

    #[test]
    fn empty_file_is_valid() {
        assert_eq!(Config::parse("").unwrap(), Config::default());
    }

    #[test]
    fn unknown_and_mistyped_keys_are_errors() {
        // A typo must not silently disable a setting.
        assert!(Config::parse("exclud = [\"x\"]").is_err());
        assert!(Config::parse("[watch]\ndebounce = 1").is_err());
        assert!(Config::parse("max_file_size = \"big\"").is_err());
        assert!(Config::parse("max_file_size = -1").is_err());
        assert!(Config::parse("exclude = \"*.tmp\"").is_err());
    }

    #[test]
    fn relative_paths_resolve_against_config_dir() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("sentinel.toml");
        fs::write(&path, "baseline = \"b.json\"\nroot = \"data\"").unwrap();
        let config = Config::load(&path).unwrap();
        assert_eq!(config.baseline, Some(dir.path().join("b.json")));
        assert_eq!(config.root, Some(dir.path().join("data")));
    }

    #[test]
    fn missing_file_is_a_read_error() {
        let dir = TempDir::new().unwrap();
        assert!(matches!(
            Config::load(&dir.path().join("nope.toml")),
            Err(ConfigError::Read { .. })
        ));
    }
}
