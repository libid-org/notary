# Production image for the libID notary.
#
# Pin the builder to bookworm so its glibc matches the bookworm-slim runtime
# stage below. A bare `-slim` tag floats to newer Debian (trixie), producing
# binaries that need GLIBC_2.38+ and fail on bookworm (glibc 2.36) at runtime.
FROM rust:1.95-slim-bookworm AS builder

# git: the libid-rs and tlsn dependencies are git sources.
RUN apt-get update && apt-get install -y pkg-config libssl-dev git && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# ── Layer 1: cache dependency compilation ──────────────────────────────────
# Copy only the manifests first: the (large, slow) dependency graph rebuilds
# only when Cargo.toml/Cargo.lock change, not on every source edit.
COPY Cargo.toml Cargo.lock ./
RUN mkdir -p src \
    && touch src/lib.rs \
    && echo 'fn main() {}' > src/main.rs \
    && cargo build --locked --release
# Remove the stub crate's artifacts so it rebuilds from real source.
RUN rm -rf src \
    && rm -f target/release/notary \
    && rm -rf target/release/deps/notary-* target/release/deps/libnotary-* \
        target/release/.fingerprint/notary-*

# ── Layer 2: real source — only rebuilds this crate ────────────────────────
COPY src/ src/
RUN cargo build --locked --release

# === Runtime ===
FROM debian:bookworm-slim

# netcat: the HEALTHCHECK probes the TCP wire port.
RUN apt-get update && apt-get install -y ca-certificates libssl3 netcat-openbsd && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/target/release/notary /usr/local/bin/notary

# 7047: TCP wire protocol (backend provers, incl. JWKS sessions).
# 7048: HTTP/WebSocket (browser tlsn-js / tlsn_wasm clients).
EXPOSE 7047 7048

# The TCP wire listener accepts as soon as the signer is ready — a connect
# proves the service is up without needing HTTP inside the container.
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD nc -z 127.0.0.1 7047 || exit 1

ENTRYPOINT ["notary"]
