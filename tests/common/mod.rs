//! Shared by the integration tests: a public HTTP port for the server under
//! test, and the retry that absorbs the race in picking one.
//!
//! `--ws-port 0` means "disabled", so the public port cannot be ephemeral;
//! the tests bind-then-drop to learn a free number and hand it to the
//! server. Between the drop and the server's bind another test -- they run
//! in parallel -- can take the same number, and then the start fails with
//! `AddrInUse`. That loss is retried on a fresh port; every other error is
//! the test's.

use notary::{
    server,
    NotaryServerConfig,
    NotaryServerHandle,
};

/// How many free ports are tried before the start is given up on.
pub const TRIES: usize = 16;

/// Reserve an ephemeral port for the public HTTP server: bind-then-drop to
/// learn a free port number. The number is free now, not at the server's
/// bind; see [`start_server`].
pub async fn free_port() -> u16 {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    l.local_addr().unwrap().port()
}

/// Whether `err` is the bind that lost the port race: the OS's
/// `EADDRINUSE`, as it reads on macOS (os error 48) and Linux (98).
pub fn is_addr_in_use(err: &impl std::fmt::Display) -> bool {
    err.to_string().contains("Address already in use")
}

/// Start the server on a free public port, built by `build` from that
/// port. A start that lost the port race is retried on another port, up
/// to [`TRIES`] times; any other error fails the test.
pub async fn start_server(
    build: impl Fn(u16) -> NotaryServerConfig,
) -> (NotaryServerHandle, u16) {
    for _ in 0..TRIES {
        let port = free_port().await;
        match server::run(build(port)).await {
            Ok(handle) => return (handle, port),
            Err(error) if is_addr_in_use(&error) => continue,
            Err(error) => panic!("server start: {error}"),
        }
    }
    panic!("no free public port in {TRIES} tries")
}
