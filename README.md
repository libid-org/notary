# notary

The libID notary service. One binary, one signing identity, one record.

The notary acts as the MPC-TLS or ProxyMode (zkTLS) verifier for a prover's
HTTPS session and signs the canonical ceremony section 9.1 attested data for
the authenticated transcript. Every session gets the same record —
`{ attested_data, notary_signature }` — whether it is:

* **a platform session** — a prover's request to a platform API (X, GitHub,
  …), read on chain by that platform's Platform Verifier; or
* **a JWKS reading** — the keeper's request for Google's OIDC signing keys
  (`https://www.googleapis.com/oauth2/v3/certs`), read on chain by
  `IdentityJwksRoots`, so Google's keys rotate without trusting the submitter.

The notary does not tell them apart and does not need to: the record carries
the TLS-certificate-verified server name (`authorityId`), and the contract that
reads the record compares it against the authority it pins. What differs is
what the prover reveals. The keeper reveals the whole JWKS session, request
and response, because a public key set has nothing to hide — and a fully
revealed transcript with nothing committed is what lets `IdentityJwksRoots`
read the key set straight out of the record. Both contracts authenticate the
signature through the on-chain `NotaryService`; the notary's signature alone
registers nothing, and its public key is served at `/info`.

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

With a KMS key the private material never enters the process: every signature
is a `kms:Sign` call.

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
`tlsn_wasm.js` and `tlsn_wasm_bg.wasm`, built from upstream
TLSNotary's `crates/wasm` at the **exact tlsn revision this server pins** —
prover and notary can never drift onto different protocol versions. Serve the
two files side by side. The wrapper embeds web-spawn and creates its recursive
workers from blob URLs, so consumers need no `spawn.js` route or rewrite.
Unlike the npm `tlsn-js` build it includes `set_progress_callback`.

The browser prover is upstream code rather than a second libID implementation:
`tlsn_wasm.js` is wasm-bindgen glue generated from TLSNotary's Rust `crates/wasm`,
`tlsn_wasm_bg.wasm` contains the protocol implementation, and its embedded
worker bootstrap comes from TLSNotary's pinned `web-spawn` dependency. This
repository only pins, builds, checks and packages that graph.

To build locally: `./scripts/build-tlsn-wasm.sh --out <dir>` (needs rustup,
wasm-pack 0.15.0, Python 3, and a clang with a wasm32 backend — the script explains
exactly what is missing if something is).

## Library use

The crate also builds as a library. `notary::NotarizedSession` is the record
above, and `notary::jwks` exposes the prover-side helpers the keeper needs:

* `jwks::prover::notarize_jwks(socket)` — run the MPC-TLS JWKS prover against
  a notary's TCP port, revealing everything (`jwks::layout`), and get back the
  signed `NotarizedSession`: the `attestedData` and `proof` arguments of
  `IdentityJwksRoots.rotate`.
* `jwks::mock::MockProver` — build the same record without MPC: fetch the key
  set over plain TLS, synthesize the transcript byte for byte as the real
  session would look (chunked response framing by default, so the on-chain
  de-chunker runs) and sign it with a caller-provided notary key, for
  contract testing.

Shared primitives (digests, wire protocol, transcript math, signers) come
from [libid-rs](https://github.com/libid-org/libid-rs).

## License

MIT or Apache-2.0, at your option. See `LICENSE-MIT` and `LICENSE-APACHE`.
