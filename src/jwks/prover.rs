//! Prover-side helpers for obtaining a signed [`JwksRotationProof`] from a
//! running notary — the pieces a backend JWKS rotation listener consumes.

use libid_tlsn::{
    Bytes,
    HttpBody,
    HttpRequest,
    ProverResult,
};
use libid_transcript::{
    ceremony::Layout,
    read_msg,
};
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
    let request = HttpRequest::builder()
        .method("GET")
        .uri(format!("https://{JWKS_DOMAIN}{JWKS_ENDPOINT}"))
        .header("Host", JWKS_DOMAIN)
        .header("Connection", "close")
        .header("Accept", "application/json")
        .header(
            "User-Agent",
            concat!("libid-notary/", env!("CARGO_PKG_VERSION")),
        )
        .body(HttpBody::new(Bytes::new()))
        .map_err(|e| crate::Error::NotaryServer {
            detail: format!("request build: {e}"),
        })?;

    let result = libid_tlsn::prover_generic(
        socket,
        request,
        // The JWKS session is not part of a ceremony: it reads a public
        // document, no credential passes through it, and no Platform Verifier
        // ever sees the result. So it states its own layout rather than calling
        // `libid_transcript::ceremony` -- the whole response is revealed,
        // because there is nothing in a public key set to hide.
        |sent, recv| {
            Ok((
                Layout {
                    reveal: libid_transcript::find_notary_reveal_ranges(sent),
                    commit: libid_transcript::find_presentation_commit_ranges(sent),
                },
                Layout {
                    reveal: core::iter::once(0..recv.len()).collect(),
                    commit: Vec::new(),
                },
            ))
        },
        // Nobody waits on a JWKS rotation the way a user waits on a claim: the
        // keeper runs it on a timer and reads the result.
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
