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
    /// A ProxyMode session relayed more than its byte cap. The relay was
    /// aborted on the operation that crossed it; nothing was attested.
    #[error(
        "ProxyMode session to {authority} relayed {used} bytes, over the {limit}-byte \
         cap; aborted, nothing attested"
    )]
    ProxyDataCapExceeded {
        /// The server name the session was relaying to.
        authority: String,
        /// Bytes relayed when the cap was crossed, both directions combined.
        used: usize,
        /// The configured cap.
        limit: usize,
    },
    /// The ProxyMode target could not be dialled; nothing was relayed.
    #[error("ProxyMode target {authority} unreachable: {detail}")]
    UpstreamConnectFailed {
        /// The server name the browser asked for.
        authority: String,
        /// The connect error, as the operating system put it.
        detail: String,
    },
    /// The browser left after setup and before the session was established.
    #[error("ProxyMode browser left before the session was established")]
    ProverLeft,
    /// The revealed HTTP request line could not be parsed.
    #[error("malformed request line: {detail}")]
    MalformedRequestLine {
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
}

/// Result alias for this crate.
pub type Result<T> = std::result::Result<T, Error>;
