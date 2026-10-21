# Threat model

Sentinel FIM detects changes to a directory tree relative to a trusted
baseline. This document states what that does and does not protect against.

## Assets

- The monitored files and directories.
- The **baseline** (the reference state) and, if used, the signing key.
- The configuration file, reports, and the `sentinel-fim` binary itself.

## Trust boundaries

| Input | Trust |
|---|---|
| Contents of the monitored tree: names, types, sizes, link targets, data | **Untrusted** — an attacker may control them |
| Baseline file | Trusted **only** if protected (signature, read-only medium) |
| Configuration file | Trusted; read only when passed with `--config` (no implicit lookup) |
| Command-line arguments | Trusted (the operator) |
| Kernel, file system driver, the binary | Trusted (see limitations) |

## Attackers

1. **Unprivileged local user** who can write into the monitored tree but not
   the baseline. Primary target: every change is detected.
2. **Attacker with the tool's privileges** who can also rewrite the baseline.
   The baseline's SHA-256 checksum does **not** help (it can be recomputed).
   Only a signature verified against a public key the operator supplies
   (`--public-key`, `--require-signature`), with the secret key kept off the
   machine, detects the forgery. Alternatively keep the baseline on read-only
   or remote storage.
3. **root / Administrator.** Out of scope: such an attacker can replace the
   binary, hide files with a rootkit or kernel module, or stop the monitor.

## Threats and mitigations

| Threat | Mitigation |
|---|---|
| Hiding a file behind an odd name (non-UTF-8, control characters) | Paths are stored losslessly (raw bytes / UTF-16 when not Unicode); names are escaped in human output (terminal escape and bidi spoofing) |
| Path traversal via a forged baseline (`../x`, absolute, `C:`, UNC, `file:stream`) | `RelPath` accepts only plain components; enforced when parsing baselines and reports |
| Symlink tricks: escaping the root, loops | Links (and Windows junctions) are recorded with their target, never followed by default; `--follow-symlinks` is opt-in and loop-detected |
| Swapping a file for a link or FIFO between listing and opening | Opened with `O_NOFOLLOW \| O_NONBLOCK` (Unix) / `FILE_FLAG_OPEN_REPARSE_POINT` (Windows); the opened handle must be a regular file |
| Blocking the scanner with a FIFO or device | Special files are never opened; `O_NONBLOCK` covers swaps |
| Windows trailing-dot/space aliasing (`evil.` opened as `evil`) | The root is canonicalized to a `\\?\` verbatim path |
| File modified while being hashed | Size, mtime (and inode, ctime on Unix) compared before/after on the same handle, bytes read must equal size; otherwise reported, not hashed |
| Unreadable files or directories hiding changes | Reported as issues; their baseline entries are *unverified*, never "removed"; the scan is incomplete (exit 3) and `init` refuses to write such a baseline unless `--allow-incomplete` |
| Corrupted or truncated baseline | Strict schema (unknown fields rejected), format/version check, checksum over the exact body bytes; atomic writes (temp file, fsync, rename) |
| Weakening the rules through configuration (e.g. `exclude = ["**"]`) | The scan policy is stored in (and signed with) the baseline; later scans use it and warn when the configuration differs |
| Resource exhaustion (huge files, many files) | Streaming hash with a fixed 64 KiB buffer; optional `--max-file-size` (reported, never silent); walking needs memory proportional to depth; the in-memory baseline is ~0.5 KiB per entry (measured: 100 000 entries → 53 MiB peak) |
| Lost real-time events | Events only mark paths for re-scanning; full scans run at startup, on OS-reported loss, on queue overflow, after watcher errors and periodically |
| Secrets in logs | File contents are never logged; secret keys are zeroized in memory and written with mode 0600 on Unix |

## Limitations

- A matching hash shows that the **content** equals the baseline at the time
  of the scan. It does not cover permissions, ownership, ACLs, extended
  attributes or Windows alternate data streams, and says nothing about the
  time between scans.
- Change detection during hashing depends on timestamp resolution; a same-size
  rewrite within one timestamp tick may go unnoticed on Windows.
- Real-time notifications are best effort (inotify watch limits, coalescing).
  Detection is guaranteed only at the next full scan.
- With `--follow-symlinks`, links may lead outside the root.
- On Windows the secret key file inherits the directory's ACL; store it on
  removable or offline media.
