//! One error type for the whole service.

/// Errors the notary service can produce.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Server-side protocol or state failure.
    #[error("notary server error: {detail}")]
    NotaryServer {
        /// Human-readable failure detail.
        detail: String,
    },
    /// The revealed HTTP request line could not be parsed.
    #[error("malformed request line: {detail}")]
    MalformedRequestLine {
        /// Human-readable failure detail.
        detail: String,
    },
    /// A JWKS session could not be built (request construction, or the mock
    /// prover's synthesized record).
    #[error("jwks: {detail}")]
    Jwks {
        /// Human-readable failure detail.
        detail: String,
    },
    /// Socket I/O failed.
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    /// JSON (de)serialization failed.
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
    /// MPC-TLS session driving failed.
    #[error(transparent)]
    Tlsn(#[from] libid_tlsn::Error),
    /// Wire protocol / transcript range failure.
    #[error(transparent)]
    Transcript(#[from] libid_transcript::Error),
    /// Signing (local or KMS) failed.
    #[error(transparent)]
    Signer(#[from] libid_signer::SignerError),
    /// Crypto primitive failure.
    #[error(transparent)]
    Crypto(#[from] libid_crypto::Error),
    /// HTTP fetch failed (mock JWKS prover only).
    #[error("http: {0}")]
    Http(#[from] reqwest::Error),
}

/// Result alias for this crate.
pub type Result<T> = std::result::Result<T, Error>;
