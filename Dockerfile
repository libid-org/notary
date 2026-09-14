# Production image for the libID notary.
#
# Pin the builder to bookworm so its glibc matches the bookworm-slim runtime
# stage below. A bare `-slim` tag floats to newer Debian (trixie), producing
# binaries that need GLIBC_2.38+ and fail on bookworm (glibc 2.36) at runtime.
FROM rust:1.95-slim-bookworm AS builder

# git: the libid-rs and tlsn dependencies are git sources. Nothing else is
# needed — the TLS stack is rustls (aws-lc-sys/ring), so there is no openssl-sys
# in the graph and the binary links only libc, libm and libgcc_s.
RUN apt-get update && apt-get install -y git && rm -rf /var/lib/apt/lists/*

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

# ca-certificates: outbound TLS to AWS KMS when SIGNING_KEY is `kms:<id>`.
# netcat: the HEALTHCHECK probes the TCP wire port.
# No libssl3: `ldd` on the built binary shows libc, libm and libgcc_s only.
RUN apt-get update && apt-get install -y ca-certificates netcat-openbsd && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/target/release/notary /usr/local/bin/notary

# The notary writes nothing to disk and binds only ports above 1024, so it has
# no reason to be root. A fixed uid/gid keeps behaviour stable if a deployment
# ever does mount something.
RUN groupadd --system --gid 10001 notary \
    && useradd --system --uid 10001 --gid notary --no-create-home --shell /usr/sbin/nologin notary
USER 10001:10001

# 7047: TCP wire protocol (Rust backend provers).
# 7048: HTTP/WebSocket (browser tlsn-js / tlsn_wasm clients).
EXPOSE 7047 7048

# The TCP wire listener accepts as soon as the signer is ready — a connect
# proves the service is up without needing HTTP inside the container.
# NOTARY_PORT, not a literal 7047: `--port`/NOTARY_PORT moves the listener, and
# a hard-coded probe would report a healthy server as permanently unhealthy.
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD nc -z 127.0.0.1 "${NOTARY_PORT:-7047}" || exit 1

# Links the ghcr package to this repo and records what the image came from.
LABEL org.opencontainers.image.source="https://github.com/libid-org/notary" \
      org.opencontainers.image.description="libID notary service: MPC-TLS / zkTLS notarization into one signed ceremony attestation." \
      org.opencontainers.image.licenses="MIT OR Apache-2.0"

ENTRYPOINT ["notary"]
