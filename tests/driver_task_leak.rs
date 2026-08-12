//! Regression test for the health-probe session leak, ported from
//! libid-tlsn's `driver_task_leak` test to the notary's real TCP listener: a
//! client that connects and immediately disconnects (the kubelet `tcpSocket`
//! probe pattern, ~540x/hour in prod) must leave no live task behind.
//!
//! Before the libid-tlsn v0.2.0 fix this failed two ways:
//! - Racy wedge: when the session driver observed EOF before the verifier's
//!   protocol request was registered, `verifier()` pended forever — pinning
//!   the per-connection handler task and its MPC buffers. Observed in prod as
//!   an unbounded RSS climb on idle notary pods.
//! - Detached driver: every `?` early return dropped the driver `JoinHandle`,
//!   which detaches the task instead of cancelling it.

use std::time::Duration;

use clap::Parser;
use notary::{
    server,
    NotaryServerConfig,
};

/// anvil #0 — public test key.
const TEST_KEY: &str = "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";

/// Number of connect-then-disconnect cycles. The pre-fix wedge hits within a
/// handful of cycles, and each wedged handler (or leaked driver) is one live
/// task above baseline, so both failure modes are unambiguous.
const CYCLES: usize = 20;

#[test]
fn probe_connections_leave_no_live_tasks() {
    // A dedicated runtime whose only tasks are the server's, so
    // `num_alive_tasks` counts leaked handlers/drivers and nothing else.
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("build runtime");

    runtime.block_on(async {
        // TCP wire listener on an ephemeral port; HTTP/WS server disabled
        // (ws_port 0) so the only long-lived tasks are the session sweep and
        // the accept loop, both of which exit on shutdown.
        let config = NotaryServerConfig::parse_from([
            "notary",
            "--host",
            "127.0.0.1",
            "--port",
            "0",
            "--ws-port",
            "0",
            "--signing-key",
            TEST_KEY,
            "--x-zk-verifier-address",
            "0x1111111111111111111111111111111111111111",
            "--verifying-contract",
            "0x2222222222222222222222222222222222222222",
        ]);
        let handle = server::run(config).await.expect("server starts");
        let addr = handle.local_addr();

        // The probe pattern: connect, then go away before speaking the
        // protocol. Each cycle spawns one handler task, whose verifier must
        // fail fast on the dead socket instead of wedging.
        for cycle in 0..CYCLES {
            let stream = tokio::net::TcpStream::connect(addr)
                .await
                .unwrap_or_else(|e| panic!("cycle {cycle}: connect: {e}"));
            drop(stream);
        }

        // The server must still accept fresh connections after the probe
        // storm — i.e. nothing wedged the accept path.
        let probe = tokio::time::timeout(
            Duration::from_secs(5),
            tokio::net::TcpStream::connect(addr),
        )
        .await
        .expect("server unresponsive after probe connections")
        .expect("server refused a connection after probe connections");
        drop(probe);

        // Let the per-connection handlers observe their dead sockets and
        // finish, then stop the long-lived tasks.
        tokio::time::sleep(Duration::from_secs(2)).await;
        handle.shutdown();
        tokio::time::sleep(Duration::from_millis(500)).await;
    });

    // Only the block_on future ran on this runtime, and it has completed, so
    // every task still alive is a leaked handler or session driver.
    let alive = runtime.metrics().num_alive_tasks();
    assert_eq!(
        alive, 0,
        "{alive} task(s) leaked after {CYCLES} aborted connections"
    );
}
