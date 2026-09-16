//! The libID notary service.
//!
//! One binary, one signing identity, one record. The notary takes part as the
//! MPC-TLS or ProxyMode (zkTLS) verifier in a prover's HTTPS session and signs
//! the canonical ceremony section 9.1 attestation for the authenticated
//! transcript -- `libid_transcript::AttestationWire`, the attested data and the
//! signature over it and nothing else. The notary does not know, and does not
//! ask, what the session was for: a platform API call (X, GitHub, …) and the
//! keeper's reading of Google's OIDC JWKS get the same record, and the contract
//! that reads the record decides whether it wanted that host. What differs is
//! only what the prover chose to reveal.
//!
//! The TCP wire listener serves Rust backend provers; the browser-facing
//! HTTP/WS API (tlsn_wasm compatible) lives on a second port. The crate builds
//! as a library so tests can embed [`run`]; the prover-side helpers for the
//! JWKS reading live in the keeper, on libid-rs's primitives.

pub mod client_ip;
pub mod config;
pub mod error;
pub mod limits;
pub mod server;
pub mod store;

pub use config::NotaryServerConfig;
pub use error::{
    Error,
    Result,
};
pub use server::{
    run,
    NotaryServerHandle,
};
