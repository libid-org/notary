//! Prover-side helpers for obtaining a signed [`JwksRotationProof`] from a
//! running notary — the pieces a backend JWKS rotation listener consumes.

use libid_tlsn::{
    HttpRequestSpec,
    ProverResult,
};
use libid_transcript::read_msg;
use tokio::io::{
    AsyncRead,
    AsyncWrite,
};

use crate::{
    error::Result,
    jwks::{
        JwksNotaryResponse,
        JWKS_DOMAIN,
        JWKS_ENDPOINT,
    },
};

/// Run the MPC-TLS prover for a JWKS reading over `socket` (connected to a
/// notary's TCP wire port). Fetches `https://www.googleapis.com/oauth2/v3/certs`
/// jointly with the notary, revealing the request line + Host header and the
/// **entire** received transcript (the notary needs every byte to build one
/// Merkle leaf per JWK object).
///
/// On success the notary has everything it needs; read the
/// [`JwksNotaryResponse`] from the returned `recovered_io` (or use
/// [`notarize_jwks`], which does both).
pub async fn run_jwks_prover<T>(socket: T) -> Result<ProverResult<T>>
where
    T: AsyncWrite + AsyncRead + Send + Unpin + 'static,
{
    let result = libid_tlsn::prover_generic(
        socket,
        &HttpRequestSpec {
            api_host: JWKS_DOMAIN,
            path: JWKS_ENDPOINT,
            method: "GET",
            body: None,
            bearer_token: None,
            user_agent: concat!("libid-notary/", env!("CARGO_PKG_VERSION")),
        },
        // The JWKS session is not part of a ceremony: it reads a public
        // document, no credential passes through it, and no Platform Verifier
        // ever sees the result. The ceremony layouts have nothing to say here,
        // so the ranges below are this caller's own.
        libid_tlsn::RevealMode::CallerSelected,
        // One range covering the whole recv transcript — NOT a range of
        // numbers, which is what the clippy lint guards against.
        #[allow(clippy::single_range_in_vec_init)]
        |recv| Ok(vec![0..recv.len()]),
        |_| {},
    )
    .await?;
    Ok(result)
}

/// Full prover round trip: run the MPC-TLS JWKS session against a notary and
/// read back the signed [`JwksNotaryResponse`] over the recovered socket.
pub async fn notarize_jwks<T>(socket: T) -> Result<JwksNotaryResponse>
where
    T: AsyncWrite + AsyncRead + Send + Unpin + 'static,
{
    let result = run_jwks_prover(socket).await?;
    let mut io = result.recovered_io;
    let response: JwksNotaryResponse = read_msg(&mut io).await?;
    Ok(response)
}
