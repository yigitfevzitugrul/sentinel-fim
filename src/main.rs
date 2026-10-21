//! Temporary entry point: prints the SHA-256 of each file argument, in the
//! same format as `sha256sum`. Replaced by the real CLI in a later step.

use std::fs::File;
use std::process::ExitCode;

use sentinel_fim::hash::Algorithm;

fn main() -> ExitCode {
    let mut failed = false;

    // `args_os` instead of `args`: a non-UTF-8 path must not panic.
    for path in std::env::args_os().skip(1) {
        let result =
            File::open(&path).and_then(|mut file| Algorithm::Sha256.hash_reader(&mut file));
        match result {
            Ok(out) => println!("{}  {}", out.digest, path.to_string_lossy()),
            Err(e) => {
                eprintln!("sentinel-fim: {}: {e}", path.to_string_lossy());
                failed = true;
            }
        }
    }

    // Exit code 3 = operational error, as planned for the real CLI.
    if failed {
        ExitCode::from(3)
    } else {
        ExitCode::SUCCESS
    }
}
