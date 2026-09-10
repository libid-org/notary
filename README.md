# notary

The libID notary service. One binary, one signing identity, two duties:

* **Platform session notarization** — the notary acts as the MPC-TLS or
  ProxyMode (zkTLS) verifier for a prover's HTTPS session with a platform API
  (X, GitHub, …) and signs the canonical ceremony section 9.1 attested data
  for the authenticated transcript.
* **Notarized JWKS readings** — the notary co-fetches Google's OIDC signing
  keys (`https://www.googleapis.com/oauth2/v3/certs`) over MPC-TLS and signs a
  `JwksRotationProof` that a `JwksOracle` contract accepts, so an on-chain
  OIDC verifier can rotate Google's keys without trusting the submitter.

Both duties share one TCP listener: the notary verifies the MPC-TLS session
first, then dispatches on the TLS-certificate-verified server name. A session
with `www.googleapis.com` is answered with the JWKS proof shape; every other
session with the ceremony attestation. The notary's signature alone registers
nothing — on-chain verifiers recover it against the notary public key served at
`/info`.

## Endpoints

TCP wire protocol on `NOTARY_PORT` (default **7047**) — length-prefixed JSON
after MPC-TLS, for Rust backend provers.

HTTP / WebSocket on `NOTARY_WS_PORT` (default **7048**) — browser TLSNotary:

| Route | What it does |
|---|---|
| `GET /info` | `{version, publicKey}` — compressed SEC1 notary public key, hex |
| `WS /notarize-proxy` | ProxyMode session, then one WebSocket binary message containing the length-prefixed section 9.1 attestation |

A server-side MPC-TLS prover needs no route: it opens the TCP listener itself,
and the same record is written back down that socket.

The live WebSocket carries the TLSNotary session and its final attestation.

## Configuration

Flags or environment variables:

| Flag | Env | Default | Meaning |
|---|---|---|---|
| `--host` | `NOTARY_HOST` | `127.0.0.1` | Bind address |
| `--port` | `NOTARY_PORT` | `7047` | TCP wire port |
| `--ws-port` | `NOTARY_WS_PORT` | `7048` | HTTP/WS port (`0` disables) |
| `--signing-key` | `SIGNING_KEY` | — | Hex secp256k1 key, or `kms:<key-id-or-alias>` for AWS KMS |
| `--max-sessions` | `NOTARY_MAX_SESSIONS` | `1024` | Concurrent browser ProxyMode session cap |
| `--jwks-enabled` | `NOTARY_JWKS_ENABLED` | `true` | Serve JWKS notarization sessions on the TCP listener |

With a KMS key the private material never enters the process: every signature
is a `kms:Sign` call, including ceremony attestations and JWKS rotation proofs.

## Docker

Released images are published to GitHub Container Registry:

```sh
docker run --rm \
  -p 7047:7047 -p 7048:7048 \
  -e NOTARY_HOST=0.0.0.0 \
  -e SIGNING_KEY=<hex-or-kms:…> \
  ghcr.io/libid-org/notary:latest
```

Tags: `<version>` and `latest` on every release; `custom-<suffix>` images can
be built from any ref via the *Custom Docker image* workflow (inputs: `ref`,
`tag-suffix`).

## Browser wasm bundle

Each release also ships `tlsn-wasm-<version>.tar.gz` as a release asset:
`tlsn_wasm.js`, `tlsn_wasm_bg.wasm` and the generated
`snippets/web-spawn-*/js/spawn.js`, built from TLSNotary's `crates/wasm` at the
**exact tlsn revision this server pins** — prover and notary cannot drift onto
different protocol versions. Mount the archive tree unchanged below any
immutable asset path: the wrapper and worker resolve each other through their
generated relative imports, without a root rewrite or generated-source edit.
Unlike the npm `tlsn-js` build, this bundle includes `set_progress_callback`
and reclaimed-channel `finish()`.

To build locally: `./scripts/build-tlsn-wasm.sh --out <dir>` (needs rustup,
wasm-pack 0.15.0, and a clang with a wasm32 backend — the script explains
exactly what is missing if something is).

## Library use

The crate also builds as a library. `notary::jwks` exposes the prover-side
helpers a backend rotation listener needs:

* `jwks::prover::notarize_jwks(socket)` — run the MPC-TLS JWKS prover against
  a notary's TCP port and get back the signed `JwksRotationProof`.
* `jwks::mock::MockProver` — build a structurally identical proof without MPC
  (zeroed handshake fields, real signature) for contract testing.

Shared primitives (digests, wire protocol, transcript math, signers) come
from [libid-rs](https://github.com/libid-org/libid-rs).

## License

MIT or Apache-2.0, at your option. See `LICENSE-MIT` and `LICENSE-APACHE`.
