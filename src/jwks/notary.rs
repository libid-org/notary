//! Notary-side JWKS proof construction.
//!
//! The MPC-TLS verification itself is shared with the platform duty and
//! lives in [`crate::server`] (via `libid_tlsn::verifier`); this module
//! builds the signed [`JwksRotationProof`] from the verified transcript:
//! one Merkle leaf per parsed JWK, exactly the way the [`super::mock`]
//! prover does, so the on-chain `JwksOracle` accepts the proof.

use std::time::SystemTime;

use libid_crypto::keccak256;
use libid_signer::ManagedSigner;
use serde::{
    Deserialize,
    Serialize,
};

use crate::{
    error::{
        Error,
        Result,
    },
    jwks::{
        crypto::{
            build_merkle_tree,
            double_hash_leaf,
            merkle_proof,
            notary_digest,
        },
        transcript::parse_jwks_body,
        JwkRotationClaim,
        JwksRotationProof,
    },
};

/// The only TLS server identity the JWKS duty notarizes. An MPC-TLS session
/// whose cert-verified SNI equals this is dispatched to the JWKS branch.
pub const JWKS_DOMAIN: &str = "www.googleapis.com";

/// The only endpoint the JWKS duty attests.
pub const JWKS_ENDPOINT: &str = "/oauth2/v3/certs";

/// Wire message sent from notary back to prover after MPC-TLS closes
/// (JWKS sessions only — platform sessions get the ceremony attestation).
#[derive(Debug, Serialize, Deserialize)]
pub struct JwksNotaryResponse {
    /// Full attestation as JSON (forwarded to anyone who later wants to
    /// inspect the TLSN-native form). Currently empty: the on-chain
    /// consumer only needs the EVM-ready proof.
    pub attestation_bytes: Vec<u8>,
    /// EVM-ready proof for `JwksOracle.rotateKeys`.
    pub proof: JwksRotationProof,
}

/// TLS 1.2 certificate-binding fields carried by a JWKS proof.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JwksHandshake {
    /// TLS client random.
    pub client_random: [u8; 32],
    /// TLS server random.
    pub server_random: [u8; 32],
    /// Server ephemeral public key.
    pub server_ephemeral_key: Vec<u8>,
}

/// Build and sign a [`JwksNotaryResponse`] from a verified MPC-TLS
/// transcript whose SNI was [`JWKS_DOMAIN`].
///
/// `sent` / `recv` are the transcript bytes with revealed ranges populated
/// (the JWKS prover reveals the request line + Host header and the entire
/// received transcript). The endpoint is checked against [`JWKS_ENDPOINT`]
/// so the notary never signs a reading of a different googleapis route.
pub async fn build_rotation_response(
    sent: &[u8],
    recv: &[u8],
    handshake: &JwksHandshake,
    signer: &ManagedSigner,
) -> Result<JwksNotaryResponse> {
    // ---- Endpoint check ----
    let req_line_end = sent
        .windows(2)
        .position(|w| w == b"\r\n")
        .unwrap_or(sent.len());
    let req_line =
        std::str::from_utf8(&sent[..req_line_end]).map_err(|e| Error::Jwks {
            detail: format!("request line not utf8: {e}"),
        })?;
    let path = req_line
        .split_whitespace()
        .nth(1)
        .ok_or_else(|| Error::Jwks {
            detail: "malformed request line".into(),
        })?;
    if path != JWKS_ENDPOINT {
        return Err(Error::Jwks {
            detail: format!("unexpected endpoint: got {path} expected {JWKS_ENDPOINT}"),
        });
    }

    // ---- Parse JWKS body from `recv` ----
    let body_start = recv
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or_else(|| Error::Jwks {
            detail: "no body separator".into(),
        })?
        + 4;
    let body = decode_chunked_if_needed(recv, body_start);
    let jwks = parse_jwks_body(&body)?;
    if jwks.is_empty() {
        return Err(Error::Jwks {
            detail: "no JWKs in response".into(),
        });
    }

    // ---- Build leaves: domain, endpoint, then one per JWK ----
    let mut leaves: Vec<[u8; 32]> = Vec::with_capacity(2 + jwks.len());
    leaves.push(double_hash_leaf("domain:", JWKS_DOMAIN.as_bytes()));
    leaves.push(double_hash_leaf("endpoint:", JWKS_ENDPOINT.as_bytes()));
    for j in &jwks {
        leaves.push(double_hash_leaf("recv:", &j.raw_object_bytes));
    }

    let transcript_root = build_merkle_tree(&leaves);
    let domain_path = merkle_proof(&leaves, 0);
    let endpoint_path = merkle_proof(&leaves, 1);
    let claims: Vec<JwkRotationClaim> = jwks
        .iter()
        .enumerate()
        .map(|(i, j)| JwkRotationClaim {
            kid: j.kid.clone(),
            n_b64url: j.n_b64url.clone(),
            jwk_bytes: j.raw_object_bytes.clone(),
            jwk_path: merkle_proof(&leaves, 2 + i),
        })
        .collect();

    let domain_hash = keccak256(JWKS_DOMAIN.as_bytes());
    let timestamp = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or_default();

    let digest = notary_digest(
        domain_hash,
        handshake.client_random,
        handshake.server_random,
        &handshake.server_ephemeral_key,
        transcript_root,
        timestamp,
    );
    // Same 65-byte EIP-191 format the mock prover produced; with KMS the
    // private key never enters this process and the signature is a kms:Sign
    // call.
    let notary_signature = signer.sign_claim(&digest).await?;

    let proof = JwksRotationProof {
        notary_signature,
        domain_hash,
        client_random: handshake.client_random,
        server_random: handshake.server_random,
        server_ephemeral_key: handshake.server_ephemeral_key.clone(),
        transcript_root,
        timestamp,
        domain_path,
        endpoint_path,
        claims,
    };

    Ok(JwksNotaryResponse {
        attestation_bytes: Vec::new(),
        proof,
    })
}

/// Undo HTTP `Transfer-Encoding: chunked` framing when present; otherwise
/// return the raw body bytes.
fn decode_chunked_if_needed(recv: &[u8], body_start: usize) -> Vec<u8> {
    // Look for Transfer-Encoding: chunked in the headers.
    let headers = &recv[..body_start.saturating_sub(4)];
    let chunked = headers
        .windows(7)
        .any(|w| w.eq_ignore_ascii_case(b"chunked"));
    let raw = &recv[body_start..];
    if !chunked {
        return raw.to_vec();
    }
    let mut out = Vec::new();
    let mut pos = 0;
    while pos < raw.len() {
        let size_end = match raw[pos..].windows(2).position(|w| w == b"\r\n") {
            Some(p) => pos + p,
            None => break,
        };
        let size_str = std::str::from_utf8(&raw[pos..size_end]).unwrap_or("0");
        let chunk_size = usize::from_str_radix(size_str.trim(), 16).unwrap_or(0);
        if chunk_size == 0 {
            break;
        }
        let data_start = size_end + 2;
        let data_end = data_start + chunk_size;
        if data_end > raw.len() {
            break;
        }
        out.extend_from_slice(&raw[data_start..data_end]);
        pos = data_end + 2;
    }
    out
}

#[cfg(test)]
mod tests {
    use libid_crypto::{
        pubkey_to_eth_address,
        recover_eth_claim,
    };
    use libid_signer::SignerSource;

    use super::*;
    use crate::jwks::crypto::merkle_verify;

    const JWKS_BODY: &[u8] = br#"{"keys":[{"alg":"RS256","e":"AQAB","n":"AAA","kty":"RSA","kid":"k1","use":"sig"},{"use":"sig","kty":"RSA","kid":"k2","alg":"RS256","n":"BBB","e":"AQAB"}]}"#;

    fn sample_transcript() -> (Vec<u8>, Vec<u8>) {
        let sent = format!("GET {JWKS_ENDPOINT} HTTP/1.1\r\nHost: {JWKS_DOMAIN}\r\n\r\n")
            .into_bytes();
        let mut recv =
            b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n".to_vec();
        recv.extend_from_slice(JWKS_BODY);
        (sent, recv)
    }

    fn sample_handshake() -> JwksHandshake {
        JwksHandshake {
            client_random: [1u8; 32],
            server_random: [2u8; 32],
            server_ephemeral_key: vec![4u8; 65],
        }
    }

    /// The signed digest recovers to the notary address, and every Merkle
    /// path verifies against the transcript root — the exact checks
    /// `JwksOracle.rotateKeys` performs on-chain.
    #[tokio::test]
    async fn rotation_proof_signature_and_paths_verify() {
        let key_hex = "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
        let signer = SignerSource::from_spec(key_hex)
            .unwrap()
            .build_managed(None)
            .await
            .unwrap();
        let (sent, recv) = sample_transcript();
        let handshake = sample_handshake();

        let resp = build_rotation_response(&sent, &recv, &handshake, &signer)
            .await
            .unwrap();
        let proof = &resp.proof;

        assert_eq!(proof.claims.len(), 2);
        assert_eq!(proof.domain_hash, keccak256(JWKS_DOMAIN.as_bytes()));

        // Signature recovers to the notary's address.
        let digest = notary_digest(
            proof.domain_hash,
            proof.client_random,
            proof.server_random,
            &proof.server_ephemeral_key,
            proof.transcript_root,
            proof.timestamp,
        );
        let recovered = recover_eth_claim(&proof.notary_signature, &digest).unwrap();
        assert_eq!(
            pubkey_to_eth_address(&recovered),
            <[u8; 20]>::try_from(signer.address().as_slice()).unwrap(),
        );

        // Every inclusion path verifies against the root.
        let domain_leaf = double_hash_leaf("domain:", JWKS_DOMAIN.as_bytes());
        assert!(merkle_verify(
            &proof.domain_path,
            proof.transcript_root,
            domain_leaf
        ));
        let endpoint_leaf = double_hash_leaf("endpoint:", JWKS_ENDPOINT.as_bytes());
        assert!(merkle_verify(
            &proof.endpoint_path,
            proof.transcript_root,
            endpoint_leaf
        ));
        for claim in &proof.claims {
            let leaf = double_hash_leaf("recv:", &claim.jwk_bytes);
            assert!(merkle_verify(&claim.jwk_path, proof.transcript_root, leaf));
        }
    }

    /// A session for a different googleapis route must be refused — the
    /// notary only ever signs readings of the JWKS endpoint.
    #[tokio::test]
    async fn rejects_unexpected_endpoint() {
        let key_hex = "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
        let signer = SignerSource::from_spec(key_hex)
            .unwrap()
            .build_managed(None)
            .await
            .unwrap();
        let sent =
            b"GET /oauth2/v4/other HTTP/1.1\r\nHost: www.googleapis.com\r\n\r\n".to_vec();
        let (_, recv) = sample_transcript();
        let err = build_rotation_response(&sent, &recv, &sample_handshake(), &signer)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("unexpected endpoint"), "{err}");
    }

    #[test]
    fn decodes_chunked_bodies() {
        let mut recv = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n".to_vec();
        let body_start = recv.len();
        recv.extend_from_slice(b"5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n");
        assert_eq!(decode_chunked_if_needed(&recv, body_start), b"hello world");
    }
}
