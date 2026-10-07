# Multi-stage build: compile the Rust agent, then ship just the binary in a
# slim runtime image. The dependency set (see Cargo.toml's note) was
# verified locally against Rust 1.95 as of 2026-10-01. A pin at
# rust:1.90-bookworm failed in CI (exit 101 — likely a dependency's
# minimum-supported-Rust-version is newer than 1.90), and this sandbox
# can't reach Docker Hub to check which minor-version tags actually
# exist, so this floats on the `bookworm` stable tag — always current
# Rust on Debian bookworm — rather than guessing a specific pin. Once
# this has built successfully in CI at least once, consider pinning it
# to that exact version for reproducibility (matching the rest of this
# repo's convention — see deploy/relay's iroh-relay pin for why).
FROM rust:bookworm AS builder

# aws-lc-rs (pulled in by reqwest's TLS stack) builds a C library via cmake.
RUN apt-get update && apt-get install -y --no-install-recommends \
    cmake \
    pkg-config \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY src ./src
# dashboard.rs embeds these via include_str! at compile time, so the
# builder stage needs them on disk before `cargo build` runs — brought in
# from apps/web/assets (the canonical copy) rather than regenerated here.
COPY assets ./assets
RUN cargo build --release --locked

FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /build/target/release/backup-buddies-client /usr/local/bin/backup-buddies-client
# Optional PUID/PGID support (see the script). chmod here rather than relying
# on the host's file mode: install.sh downloads files without +x.
COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod 0755 /usr/local/bin/docker-entrypoint.sh

# Persistent state (the Iroh identity key + anything received from a buddy)
# lives here — the customer's docker-compose.yml mounts a named volume or
# host directory at this path.
VOLUME ["/data"]
ENV DATA_DIR=/data

# How this image came to be, so the local dashboard can show the right
# update command (see dashboard.rs's update_command): "source" for a build
# made on the customer's own machine (install.sh), "image" for the prebuilt
# one CI publishes to ghcr.io (.github/workflows/build-client.yml passes
# BB_INSTALL_KIND=image). Those two update differently.
ARG BB_INSTALL_KIND=source
ENV BB_INSTALL_KIND=$BB_INSTALL_KIND

# Local status/restore dashboard (see dashboard.rs). Documentation only —
# docker-compose.yml's `ports:` is what actually publishes it, bound to
# 127.0.0.1 on the host.
EXPOSE 8080

# Passes any arguments through, so `docker compose run --rm client restore
# <node id>` still works.
ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
