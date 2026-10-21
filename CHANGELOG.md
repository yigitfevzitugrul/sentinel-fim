# Changelog

## 0.1.0 — unreleased

First release.

- `init`, `scan`, `verify`, `report`, `watch`, `keygen`, `sign` commands
- SHA-256 baselines with lossless paths, symlink/special-file policy,
  exclude globs, one-file-system and file size limits
- Baseline checksum over the raw body and optional Ed25519 signatures
- JSON and human-readable reports; NDJSON watch output
- Real-time watching with reconciliation scans
- Exit codes: 0 clean, 1 changes, 2 usage, 3 error/incomplete, 4 baseline rejected
