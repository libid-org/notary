//! Mock prover: pretends to be the result of a successful TLSNotary MPC-TLS
//! session by fetching the JWKS over plain TLS and signing with a configurable
//! key. Lets a deployment drive the `JwksOracle` contract end-to-end without
//! standing up the MPC plumbing.
//!
//! What's "fake" vs "real":
//!   * **Fake**: TLS handshake bytes (clientRandom, serverRandom,
//!     serverEphemeralKey) are zeroed/dummy. A real MPC-TLS run produces them.
//!   * **Real**: every other piece — the response body bytes, the JWK
//!     parsing, the Merkle leaves, the Merkle root, the digest layout, the
//!     EIP-191 wrapping, the signature format. All identical to what the
//!     real prover emits.
//!
//! The on-chain contract treats handshake fields as opaque (just hashed for
//! the digest). It never enforces specific values, so this mock signs the
//! same digest a real prover would, and the contract verifies it. The only
//! thing missing for production is the cryptographic guarantee that the
//! prover actually saw `googleapis.com`'s real TLS handshake.

use base64::{
    engine::general_purpose::URL_SAFE_NO_PAD,
    Engine as _,
};
use k256::ecdsa::SigningKey;
use libid_crypto::{
    keccak256,
    pubkey_to_eth_address,
    sign_eth_claim,
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
        },
        transcript,
        JwkRotationClaim,
        JwksRotationProof,
        ParsedJwk,
        JWKS_DOMAIN,
        JWKS_ENDPOINT,
    },
};

const JWKS_URL: &str = "https://www.googleapis.com/oauth2/v3/certs";

/// Configuration for [`MockProver`].
#[derive(Debug, Clone)]
pub struct MockProverConfig {
    /// Override the JWKS URL (useful for offline tests with a fixture).
    pub jwks_url: Option<String>,
    /// Override the response body — if set, no HTTP fetch.
    pub fixture_body: Option<Vec<u8>>,
    /// Unix timestamp (seconds) to put in the proof.
    pub timestamp: u64,
}

impl Default for MockProverConfig {
    fn default() -> Self {
        Self {
            jwks_url: None,
            fixture_body: None,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        }
    }
}

/// See the module docs: a no-MPC prover that signs real digests with a
/// caller-provided notary key.
pub struct MockProver {
    cfg: MockProverConfig,
    notary_key: SigningKey,
}

impl MockProver {
    /// Create a mock prover signing with `notary_key`.
    pub fn new(notary_key: SigningKey, cfg: MockProverConfig) -> Self {
        Self { cfg, notary_key }
    }

    /// Notary's Ethereum address (used to populate the on-chain notary set).
    pub fn notary_address(&self) -> [u8; 20] {
        pubkey_to_eth_address(self.notary_key.verifying_key())
    }

    /// Run the full pipeline: fetch (or load) JWKS, build leaves, build the
    /// proof, sign the digest, return the structured proof.
    pub async fn build_proof(&mut self) -> Result<JwksRotationProof> {
        let body = match self.cfg.fixture_body.as_ref() {
            Some(b) => b.clone(),
            None => fetch_jwks(self.cfg.jwks_url.as_deref().unwrap_or(JWKS_URL)).await?,
        };

        let jwks = transcript::parse_jwks_body(&body)?;
        if jwks.is_empty() {
            return Err(Error::Jwks {
                detail: "no JWKs in response".into(),
            });
        }
        self.build_proof_from_jwks(&jwks)
    }

    /// Same as [`Self::build_proof`] but for an already-parsed JWKS — useful
    /// in tests where keys are synthesized with known private parts.
    pub fn build_proof_from_jwks(
        &mut self,
        jwks: &[ParsedJwk],
    ) -> Result<JwksRotationProof> {
        // ---- 1. Build the leaf set ----
        // Layout (must match contract's expectations on caller-supplied paths):
        //   leaf 0: domain
        //   leaf 1: endpoint
        //   leaf 2..2+N: each JWK
        let mut all_leaves: Vec<[u8; 32]> = Vec::with_capacity(2 + jwks.len());
        all_leaves.push(double_hash_leaf("domain:", JWKS_DOMAIN.as_bytes()));
        all_leaves.push(double_hash_leaf("endpoint:", JWKS_ENDPOINT.as_bytes()));
        for j in jwks {
            all_leaves.push(double_hash_leaf("recv:", &j.raw_object_bytes));
        }

        // ---- 2. Compute the transcript root ----
        let transcript_root = build_merkle_tree(&all_leaves);

        // ---- 3. Build paths ----
        let domain_path = merkle_proof(&all_leaves, 0);
        let endpoint_path = merkle_proof(&all_leaves, 1);

        let claims: Vec<JwkRotationClaim> = jwks
            .iter()
            .enumerate()
            .map(|(i, j)| JwkRotationClaim {
                kid: j.kid.clone(),
                n_b64url: j.n_b64url.clone(),
                jwk_bytes: j.raw_object_bytes.clone(),
                jwk_path: merkle_proof(&all_leaves, 2 + i),
            })
            .collect();

        // ---- 4. TLS handshake fields (mock — zeroed) ----
        let client_random = [0u8; 32];
        let server_random = [0u8; 32];
        let server_ephemeral_key = vec![0u8; 65]; // dummy uncompressed point

        // ---- 5. Notary digest + EIP-191 sig ----
        let domain_hash = keccak256(JWKS_DOMAIN.as_bytes());
        let digest = notary_digest(
            domain_hash,
            client_random,
            server_random,
            &server_ephemeral_key,
            transcript_root,
            self.cfg.timestamp,
        );
        let notary_signature = sign_eth_claim(&self.notary_key, &digest)?;

        Ok(JwksRotationProof {
            notary_signature,
            domain_hash,
            client_random,
            server_random,
            server_ephemeral_key,
            transcript_root,
            timestamp: self.cfg.timestamp,
            domain_path,
            endpoint_path,
            claims,
        })
    }
}

async fn fetch_jwks(url: &str) -> Result<Vec<u8>> {
    let body = reqwest::get(url).await?.bytes().await?;
    Ok(body.to_vec())
}

/// Compute the same notary digest the contract verifies in `_notaryDigest`.
pub use super::crypto::notary_digest;

/// Convenience wrapper to be used in tests / CLI: parse the `n` field as a
/// 256-byte big-endian integer.
pub fn decode_modulus(n_b64url: &str) -> Result<[u8; 256]> {
    let raw = URL_SAFE_NO_PAD.decode(n_b64url)?;
    if raw.len() != 256 {
        return Err(Error::Jwks {
            detail: format!("expected 256-byte modulus, got {}", raw.len()),
        });
    }
    let mut out = [0u8; 256];
    out.copy_from_slice(&raw);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use libid_crypto::recover_eth_claim;

    use super::*;

    const JWKS_BODY: &[u8] = br#"{"keys":[{"alg":"RS256","e":"AQAB","n":"AAA","kty":"RSA","kid":"k1","use":"sig"},{"use":"sig","kty":"RSA","kid":"k2","alg":"RS256","n":"BBB","e":"AQAB"}]}"#;

    /// The mock proof carries the same digest layout the real notary signs:
    /// signature recovers to the mock's notary address.
    #[tokio::test]
    async fn mock_proof_signature_recovers_to_notary_address() {
        let (sk, _) = libid_crypto::generate_keypair();
        let mut prover = MockProver::new(
            sk,
            MockProverConfig {
                jwks_url: None,
                fixture_body: Some(JWKS_BODY.to_vec()),
                timestamp: 1_700_000_000,
            },
        );
        let expected_addr = prover.notary_address();
        let proof = prover.build_proof().await.unwrap();
        assert_eq!(proof.claims.len(), 2);

        let digest = notary_digest(
            proof.domain_hash,
            proof.client_random,
            proof.server_random,
            &proof.server_ephemeral_key,
            proof.transcript_root,
            proof.timestamp,
        );
        let recovered = recover_eth_claim(&proof.notary_signature, &digest).unwrap();
        assert_eq!(pubkey_to_eth_address(&recovered), expected_addr);
    }

    #[test]
    fn decode_modulus_rejects_wrong_length() {
        assert!(decode_modulus("AAA").is_err());
    }

    #[test]
    fn proof_round_trips_through_json() {
        let (sk, _) = libid_crypto::generate_keypair();
        let mut prover = MockProver::new(
            sk,
            MockProverConfig {
                jwks_url: None,
                fixture_body: Some(JWKS_BODY.to_vec()),
                timestamp: 1000,
            },
        );
        let proof = futures_blocking(prover.build_proof());
        let json = serde_json::to_string(&proof).unwrap();
        assert!(json.contains("0x"), "byte fields serialize as 0x-hex");
        let back: JwksRotationProof = serde_json::from_str(&json).unwrap();
        assert_eq!(back.transcript_root, proof.transcript_root);
        assert_eq!(back.claims.len(), proof.claims.len());
    }

    /// Tiny current-thread executor for a future that never actually awaits
    /// (fixture_body set → no HTTP).
    fn futures_blocking(
        fut: impl std::future::Future<Output = crate::Result<JwksRotationProof>>,
    ) -> JwksRotationProof {
        tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap()
            .block_on(fut)
            .unwrap()
    }
}
