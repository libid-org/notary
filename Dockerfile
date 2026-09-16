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
# netcat: the HEALTHCHECK's HTTP client. The image has no curl or wget, and
# none is added for a one-line probe; nc speaks enough HTTP/1.0 to GET
# /healthcheck and read the status line.
# libssl3 is deliberately not named: nothing links it -- `ldd` on the binary
# lists libc, libm and libgcc_s only. ca-certificates still pulls it in through
# openssl, so dropping the explicit install does not shrink the image; it stops
# the Dockerfile claiming a dependency this service does not have.
RUN apt-get update && apt-get install -y ca-certificates netcat-openbsd && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/target/release/notary /usr/local/bin/notary

# The notary writes nothing to disk and binds only ports above 1024, so it has
# no reason to be root. A fixed uid/gid keeps behaviour stable if a deployment
# ever does mount something.
RUN groupadd --system --gid 10001 notary \
    && useradd --system --uid 10001 --gid notary --no-create-home --shell /usr/sbin/nologin notary
USER 10001:10001

# The port a connection arrives on is its policy; see README "Listeners".
# 7047: MPC-TLS wire, internal (Rust provers in the cluster). Off unless
#       NOTARY_PORT is set; no per-client limits, so never behind the balancer.
# 7048: HTTP/WebSocket, public (browser tlsn_wasm clients, behind the load
#       balancer, every per-client limit in force). On by default.
# 7049: HTTP/WebSocket, internal (ProxyMode for our own services). Off unless
#       NOTARY_INTERNAL_WS_PORT is set; no per-client limits.
EXPOSE 7047 7048 7049

# GET /healthcheck on the public port: 200 while serving, 503 from SIGTERM
# until the in-flight sessions have drained, so an unhealthy container is one
# that should get no new traffic. The public port is the one listener that is
# on by default, which is why it is the probe target: `--port` is off unless
# set, and a probe on it would report a correctly configured server as
# permanently unhealthy. NOTARY_WS_PORT, not a literal 7048, for the same
# reason. With NOTARY_WS_PORT=0 there is nothing to probe and the check fails.
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD printf 'GET /healthcheck HTTP/1.0\r\n\r\n' \
        | nc -w 3 127.0.0.1 "${NOTARY_WS_PORT:-7048}" \
        | head -n 1 | grep -q ' 200 ' || exit 1

# Links the ghcr package to this repo and records what the image came from.
LABEL org.opencontainers.image.source="https://github.com/libid-org/notary" \
      org.opencontainers.image.description="libID notary service: MPC-TLS / zkTLS notarization into one signed ceremony attestation." \
      org.opencontainers.image.licenses="MIT OR Apache-2.0"

ENTRYPOINT ["notary"]
