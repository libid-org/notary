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

Two ports and one internal route. The port a connection arrives on, or the
route it asks for, is its policy. No CIDR list, no header, nothing a caller
can influence: an internal endpoint has no code path that limits it, and the
public route has no code path that exempts it.

| Port | Flag | Env | Default | Who | Policy |
|---|---|---|---|---|---|
| **7047** | `--port` | `NOTARY_PORT` | off unless set | Rust provers inside the cluster, MPC-TLS over TCP | Internal: no per-client limits |
| **7048** | `--ws-port` | `NOTARY_WS_PORT` | `7048` | Browsers, ProxyMode over WebSocket, behind the load balancer | Public: every per-client limit in force |
| 7048, `/internal/notarize-proxy` | `--internal-proxy-route` | `NOTARY_INTERNAL_PROXY_ROUTE` | off unless set | Our own services, ProxyMode over WebSocket | Internal: no per-client limits, no client header keyed on |

The internal endpoints are off unless set because they have no limits: a
deployment that wants them says so. The MPC-TLS port is published through
the cluster Service only — never through the load balancer, never on a
public address; 7047 is a convention, not a default, and `0` binds an
ephemeral port. The internal route shares the public port, so it is the
load balancer that keeps it off the internet: the Ingress must refuse
`/internal/*` with a fixed response (see Deployment notes). The notary refuses the route
itself, also with 403, whenever a request carries `X-Forwarded-For` or
`CF-Connecting-IP` — a balancer always adds one — but that is defence in
depth, not the control. Each internal endpoint has its own session pool
(`--mpc-max-sessions`, `--internal-max-sessions`), so public load can never
queue our own services behind it.

## Endpoints

TCP wire protocol on the MPC-TLS port — length-prefixed JSON after MPC-TLS,
for Rust backend provers. A server-side prover needs no route: it opens the
TCP listener itself, and the same record is written back down that socket.

HTTP / WebSocket on the public port:

| Route | What it does |
|---|---|
| `GET /info` | `{version, publicKey}` — compressed SEC1 notary public key, hex |
| `GET /healthcheck` | `200` while serving; `503` from SIGTERM until the process exits, so the balancer stops sending work while in-flight sessions finish. Point health checks here, not at `/` |
| `WS /notarize-proxy` | ProxyMode session, then one WebSocket binary message containing the length-prefixed section 9.1 attestation |
| `WS /internal/notarize-proxy` | Only with `--internal-proxy-route`; otherwise `404`. The same session for our own in-cluster services: no per-client limits, its own pool, the limits store never consulted. `403` if the request carries `X-Forwarded-For` or `CF-Connecting-IP`, because then it came through the load balancer, which is meant to have refused it |

The live WebSocket carries the TLSNotary session and its final attestation.

## Configuration

Flags or environment variables:

| Flag | Env | Default | Meaning |
|---|---|---|---|
| `--host` | `NOTARY_HOST` | `127.0.0.1` | Bind address |
| `--port` | `NOTARY_PORT` | off unless set | Internal MPC-TLS wire port; conventionally `7047`, `0` binds an ephemeral port |
| `--ws-port` | `NOTARY_WS_PORT` | `7048` | Public HTTP/WS port (`0` disables) |
| `--internal-proxy-route` | `NOTARY_INTERNAL_PROXY_ROUTE` | off unless set | Mount `WS /internal/notarize-proxy` on the public port, ProxyMode for our own in-cluster services with no per-client limits. `true`/`false`. The load balancer must refuse `/internal/*` with a fixed response |
| `--signing-key` | `SIGNING_KEY` | — | Hex secp256k1 key, or `kms:<key-id-or-alias>` for AWS KMS |
| `--max-sessions` | `NOTARY_MAX_SESSIONS` | `1024` | Concurrent browser ProxyMode sessions on the public port; past it the upgrade is refused with 503 |
| `--internal-max-sessions` | `NOTARY_INTERNAL_MAX_SESSIONS` | `1024` | Concurrent ProxyMode sessions on the internal route; its own pool |
| `--proxy-max-bytes` | `NOTARY_PROXY_MAX_BYTES` | `10000000` | Bytes one ProxyMode session may relay, both directions combined (10 MB); crossing it aborts the session, close code 1008 `PROXY_DATA_CAP_EXCEEDED`, nothing attested |
| `--mpc-max-sessions` | `NOTARY_MPC_MAX_SESSIONS` | `4x` | Concurrent MPC-TLS sessions: a count (`16`) or per-core multiplier (`4x`), resolved at startup; provers past it wait, never refused |
| `--connection-deadline-secs` | `NOTARY_CONNECTION_DEADLINE_SECS` | `300` | Lifetime of one session on either transport, queue time included; past it the connection is dropped |
| `--setup-deadline-secs` | `NOTARY_SETUP_DEADLINE_SECS` | `15` | How long a connection may sit before starting its session; until it does it holds no session slot |
| `--max-sessions-per-ip` | `NOTARY_MAX_SESSIONS_PER_IP` | `4` | Concurrent public ProxyMode sessions one client may hold; past it the session is closed with code 1013. One browser ceremony opens two, so the default leaves one ceremony of headroom. `0` disables |
| `--per-ip-upgrades` | `NOTARY_PER_IP_UPGRADES` | `10/1m,60/30m,100/1h` | Sessions one client may start per window on the public port, `<count>/<window>`; every window must have room. Empty disables |
| `--per-ip-bytes` | `NOTARY_PER_IP_BYTES` | `100MB/1m,600MB/30m,1GB/1h` | Bytes one client may relay per window on the public port, `<size>/<window>`, both directions; charged when a session ends, refused at the next upgrade. Empty disables |
| `--client-ip-header` | `NOTARY_CLIENT_IP_HEADER` | `x-forwarded-for` | Which header names the client on the public port: `x-forwarded-for` (the rightmost entry; notary directly behind the ALB) or `cf-connecting-ip` (Cloudflare proxied record only). A public upgrade without it is refused with 400 |
| `--limits-store` | `NOTARY_LIMITS_STORE` | — | Where the per-client counts live: a `postgres://` URL, or `memory` for a single replica |
| `--proxy-upstream` | `NOTARY_PROXY_UPSTREAM` | — | Tests only; loopback binds only. `<ip>:<port>` every ProxyMode session dials instead of `<server name>:443`, so the real binary can be run against a local TLS fixture; refuses to start on a non-loopback `--host` |
| `--proxy-upstream-ca` | `NOTARY_PROXY_UPSTREAM_CA` | — | Tests only; with `--proxy-upstream`. A CA certificate file (DER or PEM) added to the roots the upstream's certificate is verified against |

Windows are `<limit>/<window>` lists: a limit is a count, or bytes with a
`KB`/`MB`/`GB` suffix (powers of ten); a window is `<n>s`, `<n>m` or `<n>h`.
The concurrency cap bounds what a client holds now; the windows bound how
much of the pool's time it consumes by finishing one session and starting the
next. Every per-client limit applies to the public route only.

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
every request arrives from the balancer: the socket peer says nothing about
the client. A header does, and `--client-ip-header` says which one:

- `x-forwarded-for` (the default) — the client is the **rightmost**
  `X-Forwarded-For` entry. A balancer appends the address that connected to
  it, after whatever the caller already sent, so the last entry is the
  balancer's own word and everything left of it was written by the caller.
  Only the last entry is read; the rest are neither believed nor validated.
  Set this when the notary sits directly behind the ALB — the Cloudflare DNS
  record is DNS-only (grey cloud), or there is no Cloudflare at all.
- `cf-connecting-ip` — the client is the `CF-Connecting-IP` value Cloudflare
  sets to the address that connected to its edge. Set this **only** when the
  Cloudflare DNS record is proxied (orange cloud). With it set while the
  record is grey, nothing sets the header and every public upgrade is a 400 —
  loud, rather than quietly wrong.

A public upgrade without the configured header, or with it sent twice, is
refused with 400. It is never keyed on the socket peer: behind the balancer
that peer is the balancer, and the per-client cap would quietly become a cap
on the whole service — which looks exactly like ordinary load.

The limitation: nothing verifies who wrote the header. Anything that can
reach the public port directly can set it and choose its own key. So the
public port must be reachable only through the load balancer — a security
group that admits the ALB's subnets alone. That is the deployment's job, not
the notary's.

IPv6 clients are keyed by their /48. A residential allocation is a /56, so
keying finer would let one subscriber mint 256 identities. An IPv4 address
written as `::ffff:a.b.c.d` is keyed as `a.b.c.d`.

Our own workloads are not exempted by address: they use the MPC-TLS port or
the internal route, which key on no header and have no per-client limits at
all (see Listeners). The internal route goes further: a request there that
carries either header is refused, because it came through a proxy.

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
error: the failure it hides looks like ordinary load.

## Docker

Released images are published to GitHub Container Registry:

```sh
docker run --rm \
  -p 7048:7048 \
  -e NOTARY_HOST=0.0.0.0 \
  -e NOTARY_LIMITS_STORE=memory \
  -e SIGNING_KEY=<hex-or-kms:…> \
  ghcr.io/libid-org/notary:latest
```

That is the public port only, and it expects a load balancer in front:
every upgrade must carry `X-Forwarded-For` (or `CF-Connecting-IP` with
`NOTARY_CLIENT_IP_HEADER=cf-connecting-ip`), or it is refused with 400. To
drive it by hand, send the header yourself; for local work without one, mount
the internal route instead — `-e NOTARY_INTERNAL_PROXY_ROUTE=true` — and use
`ws://localhost:7048/internal/notarize-proxy`, which takes no header and has
no per-client limits. A Rust prover needs the MPC-TLS port, which is off
unless asked for: add `-e NOTARY_PORT=7047 -p 7047:7047`. The image
`EXPOSE`s both ports; exposing is documentation, not a listener.

The image runs as uid 10001, not root. Its `HEALTHCHECK` GETs `/healthcheck`
on `NOTARY_WS_PORT` over loopback and passes on `200` only, so a draining
container reads as unhealthy. The probe is `nc`, because the image has no
curl or wget. With `NOTARY_WS_PORT=0` there is nothing to probe and the check
fails; override it if you run the MPC-TLS port alone.

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
  connect.
- `NOTARY_INTERNAL_PROXY_ROUTE=true` if any in-cluster service uses
  ProxyMode; without it `/internal/notarize-proxy` is a 404. The route is
  on the public port, so the Ingress must refuse `/internal/*` with a
  fixed response — `alb.ingress.kubernetes.io/actions.*` on that path,
  ordered before the default backend; 404 hides the route, as o2's
  `deny-v1-internal` does. The notary's own 403 (any
  request carrying `X-Forwarded-For` or `CF-Connecting-IP`) is the
  backstop, not the control: verify the Ingress rule from outside before
  turning the route on.
- Only the public port goes behind the load balancer. 7047 is published
  through the cluster Service alone: it has no limits.
- `NOTARY_CLIENT_IP_HEADER`: leave it at `x-forwarded-for` while the
  Cloudflare record is DNS-only (grey); set `cf-connecting-ip` only once the
  record is proxied (orange). Either way the public port must be reachable
  only through the ALB — nothing checks who wrote the header, so anything
  that can reach the port directly can choose its own key.
- `NOTARY_LIMITS_STORE` is required on any non-loopback bind: `memory` at
  exactly one replica, a Postgres URL beyond that. `memory` multiplies every
  per-client limit by the replica count.
- `terminationGracePeriodSeconds` must exceed `--setup-deadline-secs` +
  `--connection-deadline-secs` (defaults `15` + `300` = `315`): SIGTERM
  drains the sessions in flight, that sum is the longest one can take, and
  a shorter grace period kills them mid-attestation. A second SIGTERM ends
  the drain at once, still with exit 0.
- Point the ALB health check at `GET /healthcheck` on the public port: set
  `alb.ingress.kubernetes.io/healthcheck-path: /healthcheck` and drop
  `alb.ingress.kubernetes.io/success-codes: "404"`, which only existed
  because `/` has no route. It returns `503` from SIGTERM until the process
  exits, which is how the balancer learns to stop sending work to a
  draining pod.
- An idle pod exits within a few tens of milliseconds of SIGTERM: the drain
  has nothing to wait for. A `preStop` sleep of at least the ALB
  health-check interval × unhealthy threshold is what gives the balancer
  time to see the `503` before the listeners close; without it the pod is
  gone before the balancer has stopped routing to it.

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
