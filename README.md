# notary

The libID notary service. One binary, one signing identity, one record.

The notary acts as the MPC-TLS or ProxyMode (zkTLS) verifier for a prover's
HTTPS session and signs the canonical ceremony section 9.1 attested data for
the authenticated transcript. Every session gets the same record —
`{ attested_data, notary_signature }` — whether it is a prover's request to a
platform API (X, GitHub, …), read on chain by that platform's Platform
Verifier, or the keeper's reading of Google's OIDC signing keys, read on chain
by `GoogleJwtRoots`. The notary does not tell them apart and does not need to:
the record carries the TLS-certificate-verified server name (`authorityId`),
and the contract that reads it compares that against the authority it pins.
What differs is only what the prover reveals. Every contract authenticates the
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
| `--max-sessions` | `NOTARY_MAX_SESSIONS` | `1024` | Concurrent ProxyMode sessions; past it the upgrade is refused with 503 |
| `--proxy-max-bytes` | `NOTARY_PROXY_MAX_BYTES` | `10000000` | Bytes one ProxyMode session may relay, both directions combined (10 MB); crossing it aborts the session, close code 1008 `PROXY_DATA_CAP_EXCEEDED`, nothing attested |
| `--mpc-max-sessions` | `NOTARY_MPC_MAX_SESSIONS` | `4x` | Concurrent MPC-TLS sessions: a count (`16`) or per-core multiplier (`4x`), resolved at startup; provers past it wait, never refused |
| `--connection-deadline-secs` | `NOTARY_CONNECTION_DEADLINE_SECS` | `300` | Lifetime of one session on either transport, queue time included; past it the connection is dropped |
| `--setup-deadline-secs` | `NOTARY_SETUP_DEADLINE_SECS` | `15` | How long a connection may sit before starting its session; until it does it holds no session slot |
| `--max-sessions-per-ip` | `NOTARY_MAX_SESSIONS_PER_IP` | `4` | Concurrent ProxyMode sessions one client may hold; past it the session is closed with code 1013. `0` disables |
| `--trusted-proxies` | `NOTARY_TRUSTED_PROXIES` | — | Addresses whose `X-Forwarded-For` names the client, as CIDRs; `direct` if nothing proxies this notary |
| `--exempt-networks` | `NOTARY_EXEMPT_NETWORKS` | — | Networks whose direct connections skip the per-client cap: this cluster's pod subnets |

With a KMS key the private material never enters the process: every signature
is a `kms:Sign` call.

The effective limits, with the MPC-TLS data limits libid-tlsn negotiates at
session setup (4 KB sent, 32 KB received; not tunable here), are logged once at
startup as `resource limits in force`.

A session slot is taken when a session starts — the prover's first byte on the
TCP port, the browser's first binary frame on the WebSocket — and not when the
connection is accepted. Opening sockets therefore reserves nothing: an idle
connection costs a socket until `--setup-deadline-secs` drops it, and the
session limits bound sessions rather than connection attempts.

### Who a session counts against

The per-client cap needs to know who is calling, and behind a load balancer
every request arrives from the balancer. Three settings decide it:

- `--trusted-proxies` — the balancer's own subnets. Only from these addresses
  is `X-Forwarded-For` read, and then right to left, stopping at the first
  address outside the set. An AWS ALB *appends* to whatever the client sent, so
  only the rightmost entry is the balancer's own word; everything left of it
  was written by the caller. A trusted peer that forwards no client, or that
  sends the header twice, is refused with 400 rather than counted against the
  balancer — which would quietly make the per-client cap a cap on the whole
  service.
- `--exempt-networks` — this cluster's pod subnets. A direct connection from
  one of them is our own workload and is never capped. Exemption is decided on
  the socket peer alone, so a request that came through the balancer can never
  claim it by naming a private address in a header. The two lists may not
  overlap: a balancer inside the exempt set would exempt the whole internet.
- Anything else reaching the notary directly is a public client keyed on its
  own address.

With a per-client cap on a non-loopback bind, an empty `--trusted-proxies` is a
startup error. Say `direct` to mean it: an empty setting is also what a missing
environment variable looks like, and the failure it causes looks exactly like
ordinary load.

For the testnet cluster the values are the ALB's public subnets and the pods'
private subnets:

```
NOTARY_TRUSTED_PROXIES=10.60.200.0/24,10.60.201.0/24
NOTARY_EXEMPT_NETWORKS=10.60.0.0/20,10.60.16.0/20
```

## Docker

Released images are published to GitHub Container Registry:

```sh
docker run --rm \
  -p 7047:7047 -p 7048:7048 \
  -e NOTARY_HOST=0.0.0.0 \
  -e SIGNING_KEY=<hex-or-kms:…> \
  ghcr.io/libid-org/notary:latest
```

The image runs as uid 10001, not root, and its `HEALTHCHECK` connects to
`NOTARY_PORT` on loopback.

### Tags

| Tag | Moves? | Use it for |
| --- | --- | --- |
| `<version>` | never | deployments, and other repos' CI — **pin this** |
| `latest` | every final release | a quick local try; never pin it |
| `custom-<suffix>` | never | one ref under review, built via the *Custom Docker image* workflow (inputs: `ref`, `tag-suffix`) |

A `custom-` tag is a build artefact, not a release channel: it is fine to pin
while a PR is open, and it should be replaced by a `<version>` tag once that PR
merges and a release is published.

### Pulling from another repository's CI

The `notary` package is **public**. A GitHub Actions job in any repository can

```yaml
- run: docker pull ghcr.io/libid-org/notary:<version>
```

with no `docker/login-action` step, no `packages: read` permission and no PAT —
`GITHUB_TOKEN` is not involved. Nothing is needed on the consumer side beyond
the pull itself.

Every tag these workflows publish is a manifest list covering `linux/amd64`
and `linux/arm64`, so one reference runs on GitHub's `ubuntu-latest` and
`ubuntu-24.04-arm` runners, on x86 and Graviton nodes, and on Apple Silicon —
no `--platform` flag, no emulation. Tags published up to `0.3.0-rc.3` are
amd64 only.

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

The crate also builds as a library: `notary::run` starts the server from a
`NotaryServerConfig` (port `0` binds an ephemeral port, reported back through
`NotaryServerHandle::local_addr`), which is how the smoke tests embed it. It
carries no prover-side code. The keeper's JWKS prover and its mock live in the keeper, on
libid-rs's primitives (`libid_tlsn::prover_generic` for the session,
`libid_transcript` for the layout and the wire frame).

Shared primitives (digests, wire protocol, transcript math, signers) come
from [libid-rs](https://github.com/libid-org/libid-rs).

## License

MIT or Apache-2.0, at your option. See `LICENSE-MIT` and `LICENSE-APACHE`.
