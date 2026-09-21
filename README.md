# notary

libID does not implement notarization itself. It relies on
[TLSNotary](https://tlsnotary.org/) and its upstream
[`tlsn`](https://github.com/tlsnotary/tlsn) implementation for the
notarization protocol and cryptography. This repository is a thin integration
wrapper that runs the verifier side and exposes it to backend provers over
MPC-TLS and to browser clients over HTTP/WebSocket, including ProxyMode. We
are grateful to the TLSNotary contributors for building and sharing the
excellent protocol that makes this service possible.

The libID notary service. One binary, one signing identity, one record.

The notary is the MPC-TLS or ProxyMode verifier for a prover's HTTPS session
and signs the section 9.1 attested data of the authenticated transcript. Every
session gets the same record, `{ attested_data, notary_signature }`, whatever
the prover talked to: the record carries the certificate-verified server name,
and the contract that reads it pins the authority it expects. Its signature
registers nothing by itself; the on-chain `NotaryService` authenticates it, and
the public key is served at `/info`.

## Listeners

The port a connection arrives on, or the route it asks for, is its policy.
Nothing a caller sends moves it between the two tiers.

| Port | Flag | Env | Default | Who | Policy |
|---|---|---|---|---|---|
| **7047** | `--port` | `NOTARY_PORT` | off unless set | Rust provers inside the cluster, MPC-TLS over TCP | Internal: no per-client limits |
| **7048** | `--ws-port` | `NOTARY_WS_PORT` | `7048` | Browsers, ProxyMode over WebSocket, behind the load balancer | Public: every per-client limit in force |
| 7048, `/internal/notarize-proxy` | `--internal-proxy-route` | `NOTARY_INTERNAL_PROXY_ROUTE` | off unless set | Our own services, ProxyMode over WebSocket | Internal: no per-client limits, no client header read |

The internal endpoints are off unless set because they have no limits. The
MPC-TLS port is published through the cluster Service only, never through the
load balancer; `0` binds an ephemeral port. The internal route shares the
public port, so the Ingress must refuse `/internal/*` with a fixed response.
The notary also refuses it with 403 whenever the request carries
`X-Forwarded-For` or `CF-Connecting-IP`, which a balancer always adds; that is
the backstop, not the control. Each internal endpoint has its own session pool
(`--mpc-max-sessions`, `--internal-max-sessions`), so public load never queues
our own services.

## Endpoints

On the MPC-TLS port: length-prefixed JSON after MPC-TLS. The prover opens the
socket and the record comes back down it.

On the public port:

| Route | What it does |
|---|---|
| `GET /info` | `{version, publicKey}`: compressed SEC1 notary public key, hex |
| `GET /healthcheck` | `200` while serving; `503` from SIGTERM until the process exits. Point health checks here, not at `/` |
| `WS /notarize-proxy` | ProxyMode session, then one binary message carrying the length-prefixed section 9.1 attestation |
| `WS /internal/notarize-proxy` | The same session for our own services, no per-client limits, its own pool; `404` unless `--internal-proxy-route`, `403` behind a proxy header |

ProxyMode dials the target when the prover's first TLS bytes arrive, so a
target the browser prepares slowly for sees no idle connection. A target that
cannot be reached ends the session during the request: the WebSocket closes
with code 1011 and a reason starting `UPSTREAM_CONNECT_FAILED`.

## Configuration

Flags or environment variables:

| Flag | Env | Default | Meaning |
|---|---|---|---|
| `--host` | `NOTARY_HOST` | `127.0.0.1` | Bind address |
| `--port` | `NOTARY_PORT` | off unless set | Internal MPC-TLS wire port; conventionally `7047`, `0` binds an ephemeral port |
| `--ws-port` | `NOTARY_WS_PORT` | `7048` | Public HTTP/WS port (`0` disables) |
| `--internal-proxy-route` | `NOTARY_INTERNAL_PROXY_ROUTE` | off unless set | Mount `WS /internal/notarize-proxy` on the public port. `true`/`false` |
| `--signing-key` | `SIGNING_KEY` | — | Hex secp256k1 key, or `kms:<key-id-or-alias>` for AWS KMS; with KMS the private material never enters the process |
| `--max-sessions` | `NOTARY_MAX_SESSIONS` | `1024` | Concurrent ProxyMode sessions on the public port; past it the upgrade is refused with 503 |
| `--internal-max-sessions` | `NOTARY_INTERNAL_MAX_SESSIONS` | `1024` | Concurrent ProxyMode sessions on the internal route; its own pool |
| `--proxy-max-bytes` | `NOTARY_PROXY_MAX_BYTES` | `10000000` | Bytes one ProxyMode session may relay, both directions; crossing it aborts the session with close code 1008, nothing attested |
| `--mpc-max-sessions` | `NOTARY_MPC_MAX_SESSIONS` | `4x` | Concurrent MPC-TLS sessions: a count (`16`) or per-core multiplier (`4x`); provers past it wait, never refused |
| `--connection-deadline-secs` | `NOTARY_CONNECTION_DEADLINE_SECS` | `300` | Lifetime of one session on either transport, queue time included |
| `--setup-deadline-secs` | `NOTARY_SETUP_DEADLINE_SECS` | `15` | How long a connection may sit before its request headers, and then before its session, arrive; until then it holds no slot |
| `--max-sessions-per-ip` | `NOTARY_MAX_SESSIONS_PER_IP` | `4` | Concurrent public sessions one client may hold; past it close code 1013. One browser identity flow opens two. `0` disables |
| `--per-ip-upgrades` | `NOTARY_PER_IP_UPGRADES` | `10/1m,60/30m,100/1h` | Sessions one client may start per window, `<count>/<window>`; every window must have room. Empty disables |
| `--per-ip-bytes` | `NOTARY_PER_IP_BYTES` | `100MB/1m,600MB/30m,1GB/1h` | Bytes one client may relay per window, `<size>/<window>`; charged when a session ends, refused at the next upgrade. Empty disables |
| `--client-ip-header` | `NOTARY_CLIENT_IP_HEADER` | `x-forwarded-for` | Who the client is on the public port: `peer`, or the header that names it; an upgrade the mode cannot attribute is refused with 400 |
| `--limits-store` | `NOTARY_LIMITS_STORE` | — | Where the per-client counts live: a `postgres://` URL, or `memory` for a single replica |

Windows are `<limit>/<window>` lists: a count, or bytes with a `KB`/`MB`/`GB`
suffix (powers of ten), per `<n>s`, `<n>m` or `<n>h`. The concurrency cap
bounds what a client holds now; the windows bound how much of the pool's time
it consumes by finishing one session and starting the next. Every per-client
limit applies to the public route only.

The public port speaks HTTP/1.1 only, which is all the ALB sends a target. A
session slot is taken when a session starts (the prover's first byte, the
browser's first binary frame), not at accept: an idle connection costs a socket
until `--setup-deadline-secs` drops it, and nothing else. The MPC-TLS data
limits are libid-tlsn's (4 KB sent, 32 KB received) and are not tunable here.
The limits in force are logged once at startup as `resource limits in force`.

### Who a session counts against

`--client-ip-header` says who the client is:

- `peer`: the socket peer, for a notary that clients reach directly, local
  Docker included. A request carrying `X-Forwarded-For` or `CF-Connecting-IP`
  came through a proxy the configuration does not know about, and the peer
  would be that proxy: refused with 400.
- `x-forwarded-for` (default): the **rightmost** `X-Forwarded-For` entry, which the
  balancer appended; everything left of it was written by the caller and is
  ignored. For a notary directly behind the ALB, with the Cloudflare record
  DNS-only (grey) or no Cloudflare at all.
- `cf-connecting-ip`: the `CF-Connecting-IP` Cloudflare sets. Only for a
  proxied (orange) record; with a grey record every public upgrade becomes a
  400.

In a header mode, a public upgrade without the header, or with it sent twice,
is refused with 400. Nothing verifies who wrote the header, so the public
port must then be reachable only through the load balancer; that is the
deployment's job. IPv6
clients are keyed by their /48 (a residential allocation is a /56); a
`::ffff:a.b.c.d` address is keyed as `a.b.c.d`. Our own workloads are not
exempted by address: they use the MPC-TLS port or the internal route, which
read no header.

### Where the counts live

The schema is `migrations/`, applied by the notary at startup through sqlx's
migrator; a schema change is a new numbered file, never an edit. With several
replicas each one runs the migrator under sqlx's advisory lock, so the first
applies what is pending and the rest find nothing to do. The migration
connection waits up to a minute for the lock and ten minutes per statement,
and startup gives the migrations ten minutes in all; a `startupProbe` must
allow that. The previous release keeps serving during a rolling update, so a
migration must be one it can live with: add, never drop or rename in the same
release.

`--limits-store` takes one of two forms:

- A Postgres URL. Every replica counts in the same place, on the database's
  clock. A database that cannot be reached is a startup error; unreachable at
  runtime, the public port refuses, because a limit that fails open is a limit
  an attacker can switch off.
- `memory`: counts kept in this process, correct for exactly one replica.
  Behind a balancer every replica keeps its own copy and each limit is
  multiplied by the replica count.

On a non-loopback bind the setting is required.

## Docker

The image runs `cargo build --release` with default features; the e2e suite's
`notary-e2e` binary, the same server with a ProxyMode dial override, exists only
under `cargo test --features e2e` and is never in the image.

```sh
docker run --rm \
  -p 7048:7048 \
  -e NOTARY_HOST=0.0.0.0 \
  -e NOTARY_LIMITS_STORE=memory \
  -e SIGNING_KEY=<hex-or-kms:…> \
  ghcr.io/libid-org/notary:latest
```

That is the public port only, expecting a balancer in front: every upgrade
needs the client header. For local work without one, add
`-e NOTARY_CLIENT_IP_HEADER=peer`: the per-client limits then count the
socket peer, and a proxied request is refused. A Rust prover needs
`-e NOTARY_PORT=7047 -p 7047:7047`.

The image runs as uid 10001. Its `HEALTHCHECK` GETs `/healthcheck` on
`NOTARY_WS_PORT` over loopback with `nc` and passes on `200` only; with
`NOTARY_WS_PORT=0` override it.

### Tags

| Tag | Moves? | Use it for |
| --- | --- | --- |
| `<version>` | never | deployments and other repos' CI: **pin this** |
| `latest` | every final release | a quick local try; never pin it |
| `custom-<suffix>` | never | one ref under review, from the *Custom Docker image* workflow (`ref`, `tag-suffix`); replace it with a `<version>` once the PR merges |

The package is public: `docker pull ghcr.io/libid-org/notary:<version>` needs
no login, permission or token. Every tag is a manifest list for `linux/amd64`
and `linux/arm64`.

## Deployment notes

- `NOTARY_PORT=7047` explicitly, or there is no MPC-TLS listener.
- `NOTARY_INTERNAL_PROXY_ROUTE=true` only if an in-cluster service uses
  ProxyMode, with the Ingress refusing `/internal/*` by a fixed response
  (`alb.ingress.kubernetes.io/actions.*` on that path, before the default
  backend). Verify the rule from outside before turning the route on.
- Only the public port goes behind the load balancer.
- `NOTARY_CLIENT_IP_HEADER` follows the Cloudflare record: `x-forwarded-for`
  while grey, `cf-connecting-ip` once orange.
- `NOTARY_LIMITS_STORE`: `memory` at exactly one replica, a Postgres URL
  beyond that.
- `terminationGracePeriodSeconds` above `--setup-deadline-secs` +
  `--connection-deadline-secs` (defaults: 315): SIGTERM drains the sessions
  in flight, and a shorter grace period kills them mid-attestation. A second
  SIGTERM ends the drain at once, still with exit 0.
- ALB health check at `GET /healthcheck` on the public port; it answers 503
  from SIGTERM until exit. An idle pod exits within milliseconds of SIGTERM,
  so a `preStop` sleep of at least the health-check interval times the
  unhealthy threshold is what lets the balancer see the 503 first.

## Browser wasm bundle

Each release ships `tlsn-wasm-<version>.tar.gz`: `tlsn_wasm.js`,
`tlsn_wasm_bg.wasm` and the generated `snippets/web-spawn-*/js/spawn.js`,
built from TLSNotary's `crates/wasm` at the exact tlsn revision this server
pins, so prover and notary cannot drift apart. Mount the tree unchanged below
any immutable asset path; the files resolve each other by relative import.
Unlike the npm `tlsn-js` build it includes `set_progress_callback` and
reclaimed-channel `finish()`. To build locally:
`./scripts/build-tlsn-wasm.sh --out <dir>` (rustup, wasm-pack 0.15.0, a clang
with a wasm32 backend; the script names what is missing).

## Library use

The crate also builds as a library: `notary::run` starts the server from a
`NotaryServerConfig`, and `NotaryServerHandle::local_addr` reports the bound
port. It carries no prover-side code; provers build on
[libID-rs](https://github.com/libid-org/libID-rs), which also provides the
shared primitives (digests, wire protocol, transcript math, signers).

## License

MIT or Apache-2.0, at your option. See `LICENSE-MIT` and `LICENSE-APACHE`.
