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

## Listeners

Three ports, and the port a connection arrives on is its policy. No CIDR
list, no header, nothing a caller can influence: a connection on an internal
port has no code path that limits it, and one on the public port has no code
path that exempts it.

| Port | Flag | Env | Default | Who | Policy |
|---|---|---|---|---|---|
| **7047** | `--port` | `NOTARY_PORT` | off unless set | Rust provers inside the cluster, MPC-TLS over TCP | Internal: no per-client limits |
| **7048** | `--ws-port` | `NOTARY_WS_PORT` | `7048` | Browsers, ProxyMode over WebSocket, behind the load balancer | Public: every per-client limit in force |
| **7049** | `--internal-ws-port` | `NOTARY_INTERNAL_WS_PORT` | off unless set | Our own services, ProxyMode over WebSocket | Internal: no per-client limits, no `X-Forwarded-For` handling |

The internal ports are off unless set because they have no limits: a
deployment that wants them says so, and publishes them through the cluster
Service only — never through the load balancer, never on a public address.
7047 and 7049 are conventions, not defaults; `0` binds an ephemeral port.
Each internal listener has its own session pool (`--mpc-max-sessions`,
`--internal-max-sessions`), so public load can never queue our own services
behind it.

## Endpoints

TCP wire protocol on the MPC-TLS port — length-prefixed JSON after MPC-TLS,
for Rust backend provers. A server-side prover needs no route: it opens the
TCP listener itself, and the same record is written back down that socket.

HTTP / WebSocket on the public port and on the internal HTTP port:

| Route | What it does |
|---|---|
| `GET /info` | `{version, publicKey}` — compressed SEC1 notary public key, hex |
| `GET /healthcheck` | `200` while serving; `503` from SIGTERM until the process exits, so the balancer stops sending work while in-flight sessions finish. Point health checks here, not at `/` |
| `WS /notarize-proxy` | ProxyMode session, then one WebSocket binary message containing the length-prefixed section 9.1 attestation |

The live WebSocket carries the TLSNotary session and its final attestation.
Whether the internal HTTP port also serves `/info` is unverified; it serves
`/healthcheck` and `/notarize-proxy`.

## Configuration

Flags or environment variables:

| Flag | Env | Default | Meaning |
|---|---|---|---|
| `--host` | `NOTARY_HOST` | `127.0.0.1` | Bind address |
| `--port` | `NOTARY_PORT` | off unless set | Internal MPC-TLS wire port; conventionally `7047`, `0` binds an ephemeral port |
| `--ws-port` | `NOTARY_WS_PORT` | `7048` | Public HTTP/WS port (`0` disables) |
| `--internal-ws-port` | `NOTARY_INTERNAL_WS_PORT` | off unless set | Internal HTTP/WS port; conventionally `7049`, `0` binds an ephemeral port |
| `--signing-key` | `SIGNING_KEY` | — | Hex secp256k1 key, or `kms:<key-id-or-alias>` for AWS KMS |
| `--max-sessions` | `NOTARY_MAX_SESSIONS` | `1024` | Concurrent browser ProxyMode sessions on the public port; past it the upgrade is refused with 503 |
| `--internal-max-sessions` | `NOTARY_INTERNAL_MAX_SESSIONS` | `1024` | Concurrent ProxyMode sessions on the internal HTTP port; its own pool |
| `--proxy-max-bytes` | `NOTARY_PROXY_MAX_BYTES` | `10000000` | Bytes one ProxyMode session may relay, both directions combined (10 MB); crossing it aborts the session, close code 1008 `PROXY_DATA_CAP_EXCEEDED`, nothing attested |
| `--mpc-max-sessions` | `NOTARY_MPC_MAX_SESSIONS` | `4x` | Concurrent MPC-TLS sessions: a count (`16`) or per-core multiplier (`4x`), resolved at startup; provers past it wait, never refused |
| `--connection-deadline-secs` | `NOTARY_CONNECTION_DEADLINE_SECS` | `300` | Lifetime of one session on either transport, queue time included; past it the connection is dropped |
| `--setup-deadline-secs` | `NOTARY_SETUP_DEADLINE_SECS` | `15` | How long a connection may sit before starting its session; until it does it holds no session slot |
| `--max-sessions-per-ip` | `NOTARY_MAX_SESSIONS_PER_IP` | `4` | Concurrent public ProxyMode sessions one client may hold; past it the session is closed with code 1013. One browser ceremony opens two, so the default leaves one ceremony of headroom. `0` disables |
| `--per-ip-upgrades` | `NOTARY_PER_IP_UPGRADES` | `10/1m,60/30m,100/1h` | Sessions one client may start per window on the public port, `<count>/<window>`; every window must have room. Empty disables |
| `--per-ip-bytes` | `NOTARY_PER_IP_BYTES` | `100MB/1m,600MB/30m,1GB/1h` | Bytes one client may relay per window on the public port, `<size>/<window>`, both directions; charged when a session ends, refused at the next upgrade. Empty disables |
| `--trusted-proxies` | `NOTARY_TRUSTED_PROXIES` | — | Addresses whose `X-Forwarded-For` names the client, as CIDRs; `direct` if nothing proxies this notary |
| `--limits-store` | `NOTARY_LIMITS_STORE` | — | Where the per-client counts live: a `postgres://` URL, or `memory` for a single replica |

Windows are `<limit>/<window>` lists: a limit is a count, or bytes with a
`KB`/`MB`/`GB` suffix (powers of ten); a window is `<n>s`, `<n>m` or `<n>h`.
The concurrency cap bounds what a client holds now; the windows bound how
much of the pool's time it consumes by finishing one session and starting the
next. Every per-client limit applies to the public port only.

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

The per-client limits need to know who is calling, and behind a load balancer
every request arrives from the balancer. On the public port:

- `--trusted-proxies` — the balancer's own subnets. Only from these addresses
  is `X-Forwarded-For` read, and then right to left, stopping at the first
  address outside the set. An AWS ALB *appends* to whatever the client sent, so
  only the rightmost entry is the balancer's own word; everything left of it
  was written by the caller. A trusted peer that forwards no client, or that
  sends the header twice, is refused with 400 rather than counted against the
  balancer — which would quietly make the per-client cap a cap on the whole
  service.
- Anything else reaching the public port directly is a public client keyed on
  its own address — and it must not carry `X-Forwarded-For` at all. A direct
  connection with the header is either forged or from a hop this notary was
  not told to trust; both are refused with 400, so a stale trusted list is
  loud on the first request instead of quietly keying every user behind the
  new hop to one address.
- IPv6 clients are keyed by their /48. A residential allocation is a /56, so
  keying finer would let one subscriber mint 256 identities.

Our own workloads are not exempted by address: they use the internal ports,
which have no per-client limits at all (see Listeners).

With a per-client limit on a non-loopback bind, an empty `--trusted-proxies` is
a startup error. Say `direct` to mean it: an empty setting is also what a
missing environment variable looks like, and the failure it causes looks
exactly like ordinary load.

For the testnet cluster the value is the ALB's public subnets:

```
NOTARY_TRUSTED_PROXIES=10.60.200.0/24,10.60.201.0/24
```

### Where the counts live

The per-client counts — sessions held now, sessions started and bytes relayed
per window — are kept in `--limits-store`, which takes one of two forms:

- A Postgres URL, `postgres://user:pass@host/db`. The tables are created at
  startup if they are missing; nothing else is needed. Every replica counts
  in the same place, on the database's clock, and a database that cannot be
  reached is a startup error. While it is unreachable at runtime the public
  port refuses: a limit that fails open under a store outage is a limit an
  attacker can switch off.
- The literal `memory`: counts kept in this process. Correct for exactly one
  replica. Behind a load balancer every replica keeps its own copy, so a
  client gets each limit once per replica, and nothing in the logs says so.

With a per-client limit on a non-loopback bind, an empty setting is a startup
error for the same reason `--trusted-proxies` is: the failure it hides looks
like ordinary load.

## Docker

Released images are published to GitHub Container Registry:

```sh
docker run --rm \
  -p 7048:7048 \
  -e NOTARY_HOST=0.0.0.0 \
  -e NOTARY_TRUSTED_PROXIES=direct \
  -e NOTARY_LIMITS_STORE=memory \
  -e SIGNING_KEY=<hex-or-kms:…> \
  ghcr.io/libid-org/notary:latest
```

That is the public port only. A Rust prover needs the MPC-TLS port, which is
off unless asked for: add `-e NOTARY_PORT=7047 -p 7047:7047`. Likewise
`NOTARY_INTERNAL_WS_PORT=7049` for the internal HTTP port. The image
`EXPOSE`s all three; exposing is documentation, not a listener.

The image runs as uid 10001, not root. Its `HEALTHCHECK` GETs `/healthcheck`
on `NOTARY_WS_PORT` over loopback and passes on `200` only, so a draining
container reads as unhealthy. The probe is `nc`, because the image has no
curl or wget. With `NOTARY_WS_PORT=0` there is nothing to probe and the check
fails; override it if you run the internal ports alone.

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

## Deployment notes

- `NOTARY_PORT` must now be set explicitly (`7047`). A deployment that omits
  it has no MPC-TLS listener, and every Rust prover in the cluster fails to
  connect. Same for `NOTARY_INTERNAL_WS_PORT` (`7049`) if any in-cluster
  service uses ProxyMode.
- Only the public port goes behind the load balancer. 7047 and 7049 are
  published through the cluster Service alone: they have no limits.
- `NOTARY_TRUSTED_PROXIES` = the ALB's subnets, not the VPC. Anything inside
  the set can name its own client.
- `NOTARY_LIMITS_STORE` = a Postgres URL at more than one replica; `memory`
  multiplies every per-client limit by the replica count.
- `terminationGracePeriodSeconds` must exceed `--connection-deadline-secs`
  (default `300`): SIGTERM drains in-flight sessions, and a shorter grace
  period kills them mid-attestation.
- The ALB health check targets `GET /healthcheck` on the public port. It
  returns `503` from SIGTERM until the process exits, which is how the
  balancer learns to stop sending work to a draining pod.

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
