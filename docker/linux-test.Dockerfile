# Linux test environment for local development on non-Linux hosts.
#
# Tests run as an unprivileged user: root bypasses file permissions, which
# would make permission-denied scenarios silently pass or fail for the wrong
# reason. Run it with scripts/test-linux.ps1.
FROM rust:1.99.1

RUN rustup component add rustfmt clippy \
    && useradd --create-home --uid 1000 tester \
    && mkdir -p /home/tester/.cargo /home/tester/target \
    && chown -R tester:tester /home/tester

USER tester
# Own registry cache and target dir (persisted in named volumes), so the
# read-only source mount and the host's target/ are never written to.
ENV CARGO_HOME=/home/tester/.cargo \
    CARGO_TARGET_DIR=/home/tester/target \
    PATH=/usr/local/cargo/bin:$PATH
WORKDIR /src
