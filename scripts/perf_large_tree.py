#!/usr/bin/env python3
"""Measure wall time and peak memory of `init` and `scan` on a large tree.

    python3 scripts/perf_large_tree.py <sentinel-fim binary> <work dir> [--files N] [--big-mib M]

Creates <work dir>/tree with N files of 1 KiB (1000 per directory) and one
file of M MiB, then runs `init` and `scan` against it. Standard library only.
"""

import argparse
import os
import subprocess
import sys
import time


def peak_rss_bytes(proc):
    """Peak resident memory of a finished child process (Windows)."""
    if sys.platform == "win32":
        import ctypes
        from ctypes import wintypes

        class Counters(ctypes.Structure):
            _fields_ = [
                ("cb", wintypes.DWORD),
                ("PageFaultCount", wintypes.DWORD),
                ("PeakWorkingSetSize", ctypes.c_size_t),
                ("WorkingSetSize", ctypes.c_size_t),
                ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
                ("QuotaPagedPoolUsage", ctypes.c_size_t),
                ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
                ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
                ("PagefileUsage", ctypes.c_size_t),
                ("PeakPagefileUsage", ctypes.c_size_t),
            ]

        counters = Counters()
        counters.cb = ctypes.sizeof(Counters)
        psapi = ctypes.WinDLL("psapi")
        handle = wintypes.HANDLE(int(proc._handle))
        if not psapi.GetProcessMemoryInfo(handle, ctypes.byref(counters), counters.cb):
            raise OSError("GetProcessMemoryInfo failed")
        return counters.PeakWorkingSetSize
    raise NotImplementedError


def run(args):
    start = time.perf_counter()
    proc = subprocess.Popen(args, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    if sys.platform == "win32":
        _, stderr = proc.communicate()
        peak = peak_rss_bytes(proc)
        code = proc.returncode
    else:
        stderr = proc.stderr.read()
        # wait4 gives the usage of this child alone (ru_maxrss in KiB).
        _, status, usage = os.wait4(proc.pid, 0)
        proc.returncode = code = os.waitstatus_to_exitcode(status)
        peak = usage.ru_maxrss * 1024
    elapsed = time.perf_counter() - start
    if code not in (0, 1):
        sys.exit(f"{args[1]} failed with {code}: {stderr.decode(errors='replace')}")
    return elapsed, peak, code


def make_tree(root, files, big_mib):
    marker = os.path.join(root, f".complete-{files}-{big_mib}")
    if os.path.exists(marker):
        return
    content = b"x" * 1024
    for i in range(files):
        directory = os.path.join(root, f"d{i // 1000:04}")
        if i % 1000 == 0:
            os.makedirs(directory, exist_ok=True)
        with open(os.path.join(directory, f"f{i:07}"), "wb") as f:
            f.write(content)
    chunk = os.urandom(1024 * 1024)
    with open(os.path.join(root, "big.bin"), "wb") as f:
        for _ in range(big_mib):
            f.write(chunk)
    open(marker, "w").close()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("binary")
    parser.add_argument("workdir")
    parser.add_argument("--files", type=int, default=100_000)
    parser.add_argument("--big-mib", type=int, default=1024)
    opts = parser.parse_args()

    tree = os.path.join(opts.workdir, "tree")
    baseline = os.path.join(opts.workdir, "baseline.json")
    os.makedirs(tree, exist_ok=True)
    start = time.perf_counter()
    make_tree(tree, opts.files, opts.big_mib)
    print(f"tree: {opts.files} files x 1 KiB + {opts.big_mib} MiB file "
          f"(prepared in {time.perf_counter() - start:.1f} s)")

    # Warm the OS cache once so both measurements see the same conditions.
    run([opts.binary, "init", tree, "-b", baseline, "--force", "-q"])
    for command in (["init", tree, "-b", baseline, "--force", "-q"],
                    ["scan", "-b", baseline, "--format", "json", "-q"]):
        elapsed, peak, code = run([opts.binary] + command)
        print(f"{command[0]:<5} {elapsed:7.2f} s   peak memory {peak / 2**20:7.1f} MiB   exit {code}")
    print(f"baseline size: {os.path.getsize(baseline) / 2**20:.1f} MiB")


if __name__ == "__main__":
    main()
