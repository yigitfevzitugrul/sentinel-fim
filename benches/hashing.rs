//! Hash throughput: the shipped SHA-256 path versus BLAKE3 (evaluation only;
//! BLAKE3 is a dev-dependency, not a product feature).

use std::hint::black_box;

use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use sentinel_fim::hash::Algorithm;

const SIZES: [usize; 3] = [4 * 1024, 1024 * 1024, 64 * 1024 * 1024];

fn hashing(c: &mut Criterion) {
    let mut group = c.benchmark_group("hash");
    for size in SIZES {
        let data: Vec<u8> = (0..size).map(|i| (i % 251) as u8).collect();
        group.throughput(Throughput::Bytes(size as u64));
        if size >= 64 * 1024 * 1024 {
            group.sample_size(10);
        }

        group.bench_function(format!("sha256/{}", label(size)), |b| {
            b.iter(|| {
                let mut reader = black_box(data.as_slice());
                Algorithm::Sha256.hash_reader(&mut reader).unwrap()
            });
        });
        group.bench_function(format!("blake3/{}", label(size)), |b| {
            b.iter(|| {
                // Same 64 KiB chunking as the real reader, single-threaded.
                let mut hasher = blake3::Hasher::new();
                for chunk in black_box(data.as_slice()).chunks(64 * 1024) {
                    hasher.update(chunk);
                }
                hasher.finalize()
            });
        });
    }
    group.finish();
}

fn label(size: usize) -> String {
    if size >= 1024 * 1024 {
        format!("{}MiB", size / (1024 * 1024))
    } else {
        format!("{}KiB", size / 1024)
    }
}

criterion_group!(benches, hashing);
criterion_main!(benches);
