//! The JWKS notarization duty and its prover-side helpers.
//!
//! Points the same MPC-TLS machinery at Google's OIDC JWKS endpoint
//! (`https://www.googleapis.com/oauth2/v3/certs`) instead of platform
//! user-info endpoints. The notary side is served by the main TCP wire
//! listener (see [`crate::server`]): after MPC-TLS verification the session
//! dispatches on the TLS-cert-verified SNI, and a `www.googleapis.com`
//! session is answered with a signed [`JwksRotationProof`].
//!
//! Prover entry points (library consumers, e.g. a backend rotation listener):
//!
//! * [`prover::notarize_jwks`] — the real one: runs the MPC-TLS prover
//!   against a live notary over any async socket and returns the signed
//!   proof.
//! * [`mock::MockProver`] — fetches the JWKS over plain TLS (no MPC), then
//!   constructs every field of the proof and signs the digest with a
//!   provided notary signing key. For end-to-end contract testing.
//!
//! The wire format matches `JwksOracle.sol::NotarizedJwksProof` and
//! `JwkClaim` exactly, so the proofs produced here are submittable
//! straight to chain.

mod crypto;
pub mod mock;
pub mod notary;
pub mod prover;
pub mod sol_types;
pub mod transcript;

pub use notary::{
    build_rotation_response,
    JwksHandshake,
    JwksNotaryResponse,
    JWKS_DOMAIN,
    JWKS_ENDPOINT,
};

use serde::{
    Deserialize,
    Serialize,
};

/// One JWK as parsed from `oauth2/v3/certs`. Uses the raw bytes the notary
/// committed to (not a re-serialized JSON), so substring checks line up
/// byte-for-byte with the on-chain transcript.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParsedJwk {
    /// Key id.
    pub kid: String,
    /// RSA modulus, base64url without padding, as Google sent it.
    pub n_b64url: String,
    /// The raw `{...}` object slice from the response body.
    pub raw_object_bytes: Vec<u8>,
}

/// Everything the on-chain `rotateKeys` call needs. Byte fields serialize as
/// `0x`-prefixed hex strings to make Foundry / TypeScript consumption easy.
#[serde_with::serde_as]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwksRotationProof {
    /// EIP-191 notary signature over the JWKS notary digest.
    #[serde(with = "hex_prefixed")]
    pub notary_signature: Vec<u8>,
    /// `keccak256("www.googleapis.com")`.
    #[serde(with = "hex_prefixed_32")]
    pub domain_hash: [u8; 32],
    /// TLS client random.
    #[serde(with = "hex_prefixed_32")]
    pub client_random: [u8; 32],
    /// TLS server random.
    #[serde(with = "hex_prefixed_32")]
    pub server_random: [u8; 32],
    /// Server ephemeral public key (uncompressed SEC1 point).
    #[serde(with = "hex_prefixed")]
    pub server_ephemeral_key: Vec<u8>,
    /// Merkle root over `[domain, endpoint, jwk_0, jwk_1, …]` leaves.
    #[serde(with = "hex_prefixed_32")]
    pub transcript_root: [u8; 32],
    /// Unix seconds at proof construction.
    pub timestamp: u64,
    /// Inclusion path for the domain leaf (index 0).
    #[serde(with = "hex_prefixed_32_vec")]
    pub domain_path: Vec<[u8; 32]>,
    /// Inclusion path for the endpoint leaf (index 1).
    #[serde(with = "hex_prefixed_32_vec")]
    pub endpoint_path: Vec<[u8; 32]>,
    /// One claim per JWK in the response.
    pub claims: Vec<JwkRotationClaim>,
}

/// One JWK claim inside a [`JwksRotationProof`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwkRotationClaim {
    /// Key id.
    pub kid: String,
    /// RSA modulus, base64url without padding.
    pub n_b64url: String,
    /// Raw JWK object bytes (the Merkle leaf preimage after the `recv:` tag).
    #[serde(with = "hex_prefixed")]
    pub jwk_bytes: Vec<u8>,
    /// Inclusion path for this JWK's leaf.
    #[serde(with = "hex_prefixed_32_vec")]
    pub jwk_path: Vec<[u8; 32]>,
}

mod hex_prefixed {
    use serde::{
        Deserialize,
        Deserializer,
        Serializer,
    };
    pub fn serialize<S: Serializer>(b: &Vec<u8>, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&format!("0x{}", hex::encode(b)))
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let s = String::deserialize(d)?;
        let s = s.strip_prefix("0x").unwrap_or(&s);
        hex::decode(s).map_err(serde::de::Error::custom)
    }
}

mod hex_prefixed_32 {
    use serde::{
        Deserialize,
        Deserializer,
        Serializer,
    };
    pub fn serialize<S: Serializer>(b: &[u8; 32], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&format!("0x{}", hex::encode(b)))
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 32], D::Error> {
        let s = String::deserialize(d)?;
        let s = s.strip_prefix("0x").unwrap_or(&s);
        let v = hex::decode(s).map_err(serde::de::Error::custom)?;
        if v.len() != 32 {
            return Err(serde::de::Error::custom(format!(
                "expected 32 bytes, got {}",
                v.len()
            )));
        }
        let mut out = [0u8; 32];
        out.copy_from_slice(&v);
        Ok(out)
    }
}

mod hex_prefixed_32_vec {
    use serde::{
        Deserialize,
        Deserializer,
        Serialize,
        Serializer,
    };
    pub fn serialize<S: Serializer>(v: &[[u8; 32]], s: S) -> Result<S::Ok, S::Error> {
        let strs: Vec<String> =
            v.iter().map(|b| format!("0x{}", hex::encode(b))).collect();
        strs.serialize(s)
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(
        d: D,
    ) -> Result<Vec<[u8; 32]>, D::Error> {
        let strs = Vec::<String>::deserialize(d)?;
        strs.into_iter()
            .map(|s| {
                let s = s.strip_prefix("0x").unwrap_or(&s);
                let v = hex::decode(s).map_err(serde::de::Error::custom)?;
                if v.len() != 32 {
                    return Err(serde::de::Error::custom(format!(
                        "expected 32 bytes, got {}",
                        v.len()
                    )));
                }
                let mut out = [0u8; 32];
                out.copy_from_slice(&v);
                Ok(out)
            })
            .collect()
    }
}
