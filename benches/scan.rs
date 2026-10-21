//! Scan and diff throughput over many small files.

use std::fs;

use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use sentinel_fim::diff::compare;
use sentinel_fim::scan::{ScanPolicy, Scanner};
use tempfile::TempDir;

const DIRS: usize = 100;
const FILES_PER_DIR: usize = 100;

fn tree() -> TempDir {
    let dir = TempDir::new().unwrap();
    let content = vec![b'x'; 1024];
    for d in 0..DIRS {
        let sub = dir.path().join(format!("dir{d:03}"));
        fs::create_dir(&sub).unwrap();
        for f in 0..FILES_PER_DIR {
            fs::write(sub.join(format!("file{f:03}.dat")), &content).unwrap();
        }
    }
    dir
}

fn scanning(c: &mut Criterion) {
    let dir = tree();
    let scanner = Scanner::new(dir.path(), ScanPolicy::default()).unwrap();
    let baseline = scanner.scan().entries;

    let mut group = c.benchmark_group("tree_10k_files_1KiB");
    group.sample_size(10);
    group.throughput(Throughput::Elements((DIRS * FILES_PER_DIR) as u64));
    group.bench_function("full_scan", |b| b.iter(|| scanner.scan()));
    let snapshot = scanner.scan();
    group.bench_function("diff_only", |b| b.iter(|| compare(&baseline, &snapshot)));
    group.finish();
}

criterion_group!(benches, scanning);
criterion_main!(benches);
