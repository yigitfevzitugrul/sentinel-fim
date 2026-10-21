# Runs a cargo command inside the Linux test container (default: cargo test).
#
#   .\scripts\test-linux.ps1
#   .\scripts\test-linux.ps1 clippy --all-targets '--' -D warnings
#   .\scripts\test-linux.ps1 fmt --check
#
# Quote '--': PowerShell consumes a bare `--` before the script sees it.
#
# The source is mounted read-only; build output and the crate cache live in
# named Docker volumes prefixed "sentinel-fim-".
# Failures are detected through $LASTEXITCODE. ErrorActionPreference=Stop is
# deliberately not used: Windows PowerShell 5.1 treats any stderr output of a
# native command (cargo's normal progress messages) as a terminating error.

$root = Split-Path -Parent $PSScriptRoot
$image = 'sentinel-fim-linux-test'

docker build --quiet -t $image -f "$root\docker\linux-test.Dockerfile" "$root\docker" | Out-Null
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

$cargoArgs = if ($args.Count -gt 0) { @($args) } else { @('test') }
$subcommand, $rest = $cargoArgs
$rest = @($rest | Where-Object { $null -ne $_ })

# Never modify Cargo.lock (the source is read-only anyway). --locked goes
# right after the subcommand, since after a `--` it would reach the tool
# (e.g. clippy) instead of cargo; fmt does not accept it at all.
if ($subcommand -in 'build', 'check', 'clippy', 'test', 'run', 'bench', 'doc') {
    $rest = @('--locked') + $rest
}

docker run --rm `
    -v "${root}:/src:ro" `
    -v sentinel-fim-cargo:/home/tester/.cargo `
    -v sentinel-fim-target:/home/tester/target `
    $image cargo $subcommand @rest
exit $LASTEXITCODE
