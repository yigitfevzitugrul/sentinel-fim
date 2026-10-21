# Architecture

A single crate: a library (`src/lib.rs`) with all logic, and a thin binary
(`src/main.rs`, `src/cli.rs`, `src/commands.rs`) for argument parsing, output
and exit codes. A future TUI or service can reuse the library unchanged.

```
               ┌────────── scan::Scanner ──────────┐
 root, policy ─┤ walkdir → visit → hash::Algorithm │─→ Snapshot { entries, issues }
               └───────────────────────────────────┘          │
 baseline.json ─→ baseline::Baseline::load (checksum, sig) ─→ entries
                                                              ▼
                                              diff::compare (merge join)
                                                              ▼
                                   report::ScanReport (JSON / human) → stdout
 watch::run: notify events → dirty paths → Scanner::scan_subtree → diff::compare_within
```

| Module | Responsibility |
|---|---|
| `hash` | Streaming digests behind an `Algorithm` enum and a private `Hasher` trait |
| `path` | `RelPath`: validated, lossless, root-relative paths; safe display |
| `scan` | `ScanPolicy`, `Scanner`, safe opening, issues |
| `baseline` | File format, checksum, signature checks, atomic save |
| `sign` | Ed25519 key files and baseline signatures |
| `diff` | Baseline vs. snapshot: added / removed / modified / type changed / unverified |
| `report` | Versioned JSON report and human rendering |
| `watch` | Real-time monitoring with reconciliation |
| `config` | Optional TOML configuration |
| `fsutil`, `hex` | Atomic writes, hex encoding |

## Formats

- **Baseline** (`format: sentinel-fim-baseline`, `version: 1`): envelope with
  `body_sha256`, optional `signature` (Ed25519 over
  `"sentinel-fim baseline signature v1\0" + body bytes`) and `body`
  (`tool_version`, `created_at`, `root`, `policy`, sorted `entries`).
- **Report** (`format: sentinel-fim-report`, `version: 1`): status, summary,
  changes, unverified entries, issues.
- **Watch output** (`--format json`): one JSON object per line with `time`
  and `event`.
- Paths are strings when valid Unicode, otherwise `{"unix_bytes": "<hex>"}` or
  `{"windows_wide": "<hex>"}`.

## Decisions

### ADR 1 — Symbolic links are recorded, not followed

Following links lets an attacker point the scan outside the root, create
loops, or make one file appear under many names. Recording the link and its
target detects retargeting without those risks. `--follow-symlinks` exists for
trees that rely on links; it is loop-detected and stored in the baseline.

### ADR 2 — SHA-256 by default; BLAKE3 not shipped

Measured (`cargo bench --bench hashing`, x86-64 with SHA extensions): SHA-256
1.44 GiB/s, single-threaded BLAKE3 1.70 GiB/s on 64 MiB inputs. The 18 %
difference is below typical storage throughput and does not justify a second
algorithm. The `Algorithm` enum and the baseline's `algorithm` field keep the
door open.

### ADR 3 — Checksum and signature cover the raw body bytes

Verifying a re-serialized structure would depend on serializer details.
Keeping the body as raw JSON (`serde_json::RawValue`) and hashing/signing
exactly those bytes makes verification independent of formatting.

### ADR 4 — The scan policy lives in the baseline

Exclude rules decide what is checked at all. Taking them from a config file at
scan time would let anyone who can edit that file blind the monitor. They are
recorded (and signed) with the baseline instead.

### ADR 5 — Unreadable means unverified, not removed

Reporting entries below an unreadable directory as removed would be wrong and
noisy; reporting nothing would hide them. They are listed as unverified and
the scan is marked incomplete (exit 3).

### ADR 6 — Notifications are hints

Platform notifications can be lost or coalesced. An event only schedules a
re-scan of its path; correctness comes from scanning, with full
reconciliation scans whenever loss is possible and on a timer.

## Performance (release build, warm cache, measured)

| Tree | Platform | `init` | `scan` |
|---|---|---|---|
| 100 000 × 1 KiB + 1 GiB file | Linux (Docker) | 1.5 s, 53 MiB peak | 1.6 s, 43 MiB peak |
| same | Windows 11 | 8.5 s, 73 MiB peak | 8.6 s, 47 MiB peak |

Reproduce with `python scripts/perf_large_tree.py <binary> <work dir>`.
Windows is dominated by per-file open costs (and antivirus scanning).
