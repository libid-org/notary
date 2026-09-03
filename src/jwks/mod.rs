//! The JWKS reading: Google's OIDC signing keys, notarized like any other
//! session.
//!
//! The keeper points the same MPC-TLS machinery at
//! `https://www.googleapis.com/oauth2/v3/certs` and gets back the record every
//! session gets -- a [`NotarizedSession`] -- which it submits to
//! `GoogleJwtRoots.rotate`. That contract authenticates the signature
//! through the Notary Service and reads the key set straight out of the
//! revealed transcript. The notary special-cases nothing here: it signs what it
//! observed, and which host it observed is in the record (`authorityId`), for
//! the contract to compare against the authority it pins.
//!
//! What makes the reading readable on chain is its [`layout`]: everything
//! revealed, nothing committed. The contract concatenates the revealed ranges
//! and parses request line, `Host` header, status line, framing and JSON out
//! of the result; a commitment anywhere in either direction is refused,
//! because a hidden range is where a second `Host` header or a decoy `"keys"`
//! member would live.
//!
//! Prover entry points (library consumers, i.e. the keeper):
//!
//! * [`prover::notarize_jwks`] -- the real one: runs the MPC-TLS prover
//!   against a live notary over any async socket and reads the record back.
//! * [`mock::MockProver`] -- fetches the JWKS over plain TLS (no MPC),
//!   synthesizes the transcript the real session would have produced, and
//!   signs the record with a caller-provided notary key. For end-to-end
//!   contract testing.
//!
//! [`NotarizedSession`]: crate::NotarizedSession

pub mod mock;
pub mod prover;

use libid_tlsn::{
    Bytes,
    HttpBody,
    HttpRequest,
};
use libid_transcript::ceremony::Layout;

/// The TLS server name the JWKS reading authenticates. The record carries
/// `keccak256` of it as `authorityId`, and `GoogleJwtRoots` refuses any
/// other -- and, because googleapis.com serves many virtual hosts under one
/// certificate, also requires the `Host` header the request carries to name
/// this same host.
pub const JWKS_DOMAIN: &str = "www.googleapis.com";

/// The endpoint the JWKS reading requests. The contract pins the request line
/// `GET /oauth2/v3/certs HTTP/1.1` byte for byte.
pub const JWKS_ENDPOINT: &str = "/oauth2/v3/certs";

/// What the JWKS reading discloses: everything, in both directions.
///
/// One revealed range per direction covering the whole transcript, and no
/// commitment. A public key set has nothing to hide, and zero commitments is
/// what lets the contract read the transcript by concatenation safely: with
/// exact coverage and nothing committed, no cut can hide bytes between the
/// request line and the last key.
///
/// The JWKS session is not part of a ceremony, so it states its own layout
/// rather than calling `libid_transcript::ceremony`. The shape is the same --
/// the reveals are named and the commitments are their complement, here empty
/// -- so each direction tiles by construction, which is what the contract's
/// `requireExactCoverage` demands.
pub fn layout(sent: &[u8], recv: &[u8]) -> (Layout, Layout) {
    let whole = |bytes: &[u8]| Layout {
        reveal: std::iter::once(0..bytes.len()).collect(),
        commit: Vec::new(),
    };
    (whole(sent), whole(recv))
}

/// The request the reading sends.
///
/// The URI is absolute because `prover_generic` derives the server to reach
/// from it; on the wire the request-target is origin-form (`prover_generic`
/// rewrites it before sending), so the transcript's first line is the one the
/// contract pins. hyper writes header names in lowercase, in the order they
/// were set, and adds none of its own to a bodiless `GET`, so the sent
/// transcript is exactly:
///
/// ```text
/// GET /oauth2/v3/certs HTTP/1.1\r\n
/// host: www.googleapis.com\r\n
/// connection: close\r\n
/// accept: application/json\r\n
/// user-agent: <user_agent>\r\n
/// \r\n
/// ```
///
/// `connection: close` makes the server delimit the response, so the prover
/// reads to EOF and the transcript ends where the body does. The mock prover
/// synthesizes these same bytes from this same request, and a test drives
/// hyper's encoder to keep the two honest.
pub(crate) fn request(user_agent: &str) -> crate::Result<HttpRequest<HttpBody<Bytes>>> {
    HttpRequest::builder()
        .method("GET")
        .uri(format!("https://{JWKS_DOMAIN}{JWKS_ENDPOINT}"))
        .header("Host", JWKS_DOMAIN)
        .header("Connection", "close")
        .header("Accept", "application/json")
        .header("User-Agent", user_agent)
        .body(HttpBody::new(Bytes::new()))
        .map_err(|e| crate::Error::Jwks {
            detail: format!("request build: {e}"),
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The contract's coverage rule: reveals and commitments account for every
    /// byte of the direction exactly, no gap and no overlap.
    fn assert_tiles(layout: &Layout, length: usize) {
        let mut spans: Vec<_> = layout
            .reveal
            .iter()
            .chain(layout.commit.iter())
            .cloned()
            .collect();
        spans.sort_by_key(|range| range.start);
        let mut at = 0;
        for range in spans {
            assert_eq!(range.start, at, "gap or overlap before {}", range.start);
            at = range.end;
        }
        assert_eq!(at, length, "the spans do not reach the transcript end");
    }

    #[test]
    fn reveals_both_directions_whole_and_commits_nothing() {
        let sent = b"GET /oauth2/v3/certs HTTP/1.1\r\nhost: www.googleapis.com\r\n\r\n";
        let recv = b"HTTP/1.1 200 OK\r\n\r\n{\"keys\":[]}";
        let (s, r) = layout(sent, recv);

        assert_eq!(s.reveal.len(), 1, "one range, not several to cut between");
        assert_eq!(s.reveal[0], 0..sent.len());
        assert_eq!(r.reveal.len(), 1, "one range, not several to cut between");
        assert_eq!(r.reveal[0], 0..recv.len());
        assert!(s.commit.is_empty(), "a commitment would hide request bytes");
        assert!(
            r.commit.is_empty(),
            "a commitment would hide response bytes"
        );
        assert_tiles(&s, sent.len());
        assert_tiles(&r, recv.len());
    }

    #[test]
    fn the_request_names_the_host_the_path_and_the_four_headers() {
        let request = request("libid-keeper/test").unwrap();
        assert_eq!(request.method(), "GET");
        assert_eq!(request.uri().host(), Some(JWKS_DOMAIN));
        assert_eq!(request.uri().path(), JWKS_ENDPOINT);
        let headers: Vec<(&str, &[u8])> = request
            .headers()
            .iter()
            .map(|(name, value)| (name.as_str(), value.as_bytes()))
            .collect();
        let expected: Vec<(&str, &[u8])> = vec![
            ("host", JWKS_DOMAIN.as_bytes()),
            ("connection", b"close"),
            ("accept", b"application/json"),
            ("user-agent", b"libid-keeper/test"),
        ];
        assert_eq!(headers, expected);
    }
}
