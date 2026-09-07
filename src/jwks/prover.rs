//! Prover-side helpers for obtaining a [`NotarizedSession`] of the JWKS reading
//! from a running notary -- the pieces the keeper consumes.

use libid_tlsn::ProverResult;
use libid_transcript::read_msg;
use tokio::io::{
    AsyncRead,
    AsyncWrite,
};

use crate::{
    error::Result,
    jwks,
    NotarizedSession,
};

/// What the reading calls itself. The keeper is the process Google sees, and
/// this prover is the keeper's; the version is this crate's, because the prover
/// ships in it. Nothing verifies the value -- the contract pins the request
/// line and the `Host` header, not the agent -- and the mock sends
/// `libid-keeper/mock` in the same slot.
const USER_AGENT: &str = concat!("libid-keeper/", env!("CARGO_PKG_VERSION"));

/// Run the MPC-TLS prover for a JWKS reading over `socket` (connected to a
/// notary's TCP wire port). Fetches `https://www.googleapis.com/oauth2/v3/certs`
/// jointly with the notary and reveals the whole transcript in both directions
/// ([`jwks::layout`]): the contract reads the key set out of the record, so
/// every byte of it must be there.
///
/// On success the notary has signed the session; read the
/// [`NotarizedSession`] from the returned `recovered_io` (or use
/// [`notarize_jwks`], which does both).
pub async fn run_jwks_prover<T>(socket: T) -> Result<ProverResult<T>>
where
    T: AsyncWrite + AsyncRead + Send + Unpin + 'static,
{
    let request = jwks::request(USER_AGENT)?;
    let result = libid_tlsn::prover_generic(
        socket,
        request,
        |sent, recv| Ok(jwks::layout(sent, recv)),
        // Nobody waits on a JWKS rotation the way a user waits on a claim: the
        // keeper runs it on a timer and reads the result.
        |_| {},
    )
    .await?;
    Ok(result)
}

/// Full prover round trip: run the MPC-TLS JWKS session against a notary and
/// read back the signed [`NotarizedSession`] over the recovered socket.
pub async fn notarize_jwks<T>(socket: T) -> Result<NotarizedSession>
where
    T: AsyncWrite + AsyncRead + Send + Unpin + 'static,
{
    let result = run_jwks_prover(socket).await?;
    let mut io = result.recovered_io;
    let session: NotarizedSession = read_msg(&mut io).await?;
    Ok(session)
}
