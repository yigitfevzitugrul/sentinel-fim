# Sentinel FIM

A file integrity monitor for Linux and Windows. It records a trusted
**baseline** of a directory tree (SHA-256 of every file, plus directories,
symlinks and special files) and reports what was **added, removed, modified
or changed type** since.

## Install

```sh
cargo install --path .        # or download a binary from GitHub Releases
```

Requires Rust 1.88+.

## Usage

```sh
sentinel-fim init /srv/data -b baseline.json --exclude '*.log'
sentinel-fim scan -b baseline.json                 # human report
sentinel-fim scan -b baseline.json --format json --report scan.json
sentinel-fim watch -b baseline.json                # real time + periodic rescans
sentinel-fim report scan.json                      # re-render a saved report
```

Signed baselines (keep the secret key **off** the monitored machine):

```sh
sentinel-fim keygen --secret-key fim.secret --public-key fim.pub
sentinel-fim sign -b baseline.json --secret-key fim.secret
sentinel-fim scan -b baseline.json --public-key fim.pub --require-signature
```

Optional TOML config via `--config FILE` (never searched implicitly).
Command-line options win; exclude lists are combined; relative paths are
resolved against the config file's directory:

```toml
root = "/srv/data"
baseline = "/var/lib/sentinel-fim/baseline.json"
public_key = "/etc/sentinel-fim/baseline.pub"
require_signature = true
exclude = ["*.tmp", "/cache"]   # no '/': any name; with '/': path from root
follow_symlinks = false
one_file_system = true
max_file_size = 1073741824

[watch]
debounce_ms = 500
rescan_interval_secs = 3600     # 0 disables periodic full scans
```

Logs go to stderr (`-v`, `-vv`, `-q`, or `SENTINEL_FIM_LOG=debug`); reports
go to stdout.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | clean / baseline valid |
| 1 | changes detected |
| 2 | usage error |
| 3 | runtime error or incomplete scan |
| 4 | baseline rejected (corrupt, edited, bad signature) |

## Security model (short)

- Symlinks and junctions are **recorded, not followed** by default; files are
  opened with `O_NOFOLLOW|O_NONBLOCK` / `FILE_FLAG_OPEN_REPARSE_POINT` and
  re-checked on the handle, so swap races are detected.
- Files changing while hashed, unreadable files and unreadable directories
  are reported (exit 3); their contents are *unverified*, never "removed".
- The baseline checksum only detects corruption. Only a **signature** checked
  against an operator-supplied public key detects tampering.
- Real-time events are hints: every event triggers a re-scan of that path,
  and lost events, queue overflow and a periodic timer trigger full scans.
- Limits: content hash only (no permissions/ACL/xattr/Windows ADS); mtime
  resolution; a root/admin attacker can subvert the tool itself.

Details: [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md),
[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) (formats and design decisions).

## Performance (measured, release build, warm cache)

100 000 × 1 KiB files + one 1 GiB file:

| Platform | `init` | `scan` |
|---|---|---|
| Linux (Docker) | 1.5 s, 53 MiB peak | 1.6 s, 43 MiB peak |
| Windows 11 | 8.5 s, 73 MiB peak | 8.6 s, 47 MiB peak |

SHA-256 ≈ 1.44 GiB/s; single-threaded BLAKE3 was only ~18 % faster, so
SHA-256 stays. Reproduce with `scripts/perf_large_tree.py` and `cargo bench`.

## Development

```sh
cargo test                       # Windows/Linux host
.\scripts\test-linux.ps1         # Linux tests in Docker as non-root
```

License: MIT OR Apache-2.0.
