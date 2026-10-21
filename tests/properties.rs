//! Property-based tests of invariants over arbitrary inputs.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use proptest::prelude::*;

use sentinel_fim::baseline::{Baseline, Trust};
use sentinel_fim::diff::{ChangeKind, compare};
use sentinel_fim::hash::Algorithm;
use sentinel_fim::path::{PathRepr, RelPath};
use sentinel_fim::scan::{Record, ScanPolicy, Snapshot};

/// A file name valid on every supported platform.
fn name() -> impl Strategy<Value = String> {
    // Printable characters (including non-ASCII), minus separators and the
    // characters Windows reserves.
    "[^/\\\\:*?\"<>|\\x00-\\x1f]{1,12}"
        .prop_filter("not . or ..", |s| s != "." && s != "..")
        // Windows strips trailing dots and spaces from ordinary paths; such
        // names are valid but not what this test is about.
        .prop_filter("no trailing dot or space", |s| {
            !s.ends_with('.') && !s.ends_with(' ')
        })
}

fn rel_path() -> impl Strategy<Value = RelPath> {
    prop::collection::vec(name(), 1..5).prop_map(|names| {
        let path: PathBuf = names.iter().collect();
        RelPath::new(&path).expect("generated names are valid")
    })
}

fn record() -> impl Strategy<Value = Record> {
    prop_oneof![
        prop::collection::vec(any::<u8>(), 0..16).prop_map(|data| Record::File {
            size: data.len() as u64,
            digest: Algorithm::Sha256
                .hash_reader(&mut data.as_slice())
                .unwrap()
                .digest,
        }),
        Just(Record::Directory {}),
        name().prop_map(|t| Record::Symlink {
            target: PathBuf::from(t)
        }),
    ]
}

fn entries() -> impl Strategy<Value = BTreeMap<RelPath, Record>> {
    prop::collection::btree_map(rel_path(), record(), 0..20)
}

proptest! {
    #[test]
    fn rel_path_repr_round_trips(path in rel_path()) {
        let repr = path.to_repr();
        prop_assert_eq!(RelPath::from_repr(&repr).unwrap(), path.clone());
        let json = serde_json::to_string(&path).unwrap();
        prop_assert_eq!(serde_json::from_str::<RelPath>(&json).unwrap(), path);
    }

    #[test]
    fn rel_path_from_text_never_escapes(text in "\\PC{0,40}") {
        // Whatever untrusted text says, an accepted path stays below the root.
        if let Ok(path) = RelPath::from_repr(&PathRepr::Utf8(text)) {
            let root = Path::new("root");
            prop_assert!(path.resolve(root).starts_with(root));
            prop_assert!(path.names().all(|n| n != ".." && n != "."));
        }
    }

    #[test]
    fn identical_states_have_no_diff(baseline in entries()) {
        let snapshot = Snapshot { entries: baseline.clone(), issues: vec![] };
        prop_assert!(compare(&baseline, &snapshot).is_empty());
    }

    #[test]
    fn diff_accounts_for_every_difference(baseline in entries(), current in entries()) {
        let snapshot = Snapshot { entries: current.clone(), issues: vec![] };
        let diff = compare(&baseline, &snapshot);

        let mut expected = Vec::new();
        for path in baseline.keys().chain(current.keys()) {
            let kind = match (baseline.get(path), current.get(path)) {
                (Some(a), Some(b)) if a == b => continue,
                (Some(_), Some(_)) => None,
                (None, Some(_)) => Some(ChangeKind::Added),
                (Some(_), None) => Some(ChangeKind::Removed),
                (None, None) => unreachable!(),
            };
            expected.push((path.clone(), kind));
        }
        expected.sort_by(|a, b| a.0.cmp(&b.0));
        expected.dedup_by(|a, b| a.0 == b.0);

        prop_assert_eq!(diff.changes.len(), expected.len());
        for (change, (path, kind)) in diff.changes.iter().zip(&expected) {
            prop_assert_eq!(&change.path, path);
            if let Some(kind) = kind {
                prop_assert_eq!(change.kind, *kind);
            } else {
                prop_assert!(matches!(change.kind, ChangeKind::Modified | ChangeKind::TypeChanged));
            }
        }
        prop_assert!(diff.unverified.is_empty());
    }

    #[test]
    fn baseline_round_trips(entries in entries()) {
        let baseline = Baseline::new(PathBuf::from("/root"), ScanPolicy::default(), entries);
        let loaded = Baseline::from_bytes(&baseline.to_bytes(None), Trust::default()).unwrap();
        prop_assert_eq!(loaded.baseline, baseline);
    }

    #[test]
    fn arbitrary_baseline_bytes_never_panic(bytes in prop::collection::vec(any::<u8>(), 0..512)) {
        let _ = Baseline::from_bytes(&bytes, Trust::default());
    }

    #[test]
    fn any_single_byte_flip_is_detected(entries in entries(), index in any::<prop::sample::Index>(), bit in 0u8..8) {
        let baseline = Baseline::new(PathBuf::from("/root"), ScanPolicy::default(), entries);
        let mut bytes = baseline.to_bytes(None);
        let i = index.index(bytes.len());
        bytes[i] ^= 1 << bit;
        // Either rejected, or the flip hit insignificant whitespace/formatting
        // and the content is unchanged.
        if let Ok(loaded) = Baseline::from_bytes(&bytes, Trust::default()) {
            prop_assert_eq!(loaded.baseline, baseline);
        }
    }

    #[test]
    fn arbitrary_exclude_patterns_never_panic(patterns in prop::collection::vec("\\PC{0,12}", 0..4)) {
        let policy = ScanPolicy { exclude: patterns, ..ScanPolicy::default() };
        let _ = policy.validate();
    }
}
