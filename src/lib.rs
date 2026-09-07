//! The libID notary service.
//!
//! One binary, one signing identity, one record. The notary takes part as the
//! MPC-TLS or ProxyMode (zkTLS) verifier in a prover's HTTPS session and signs
//! the canonical ceremony section 9.1 attestation for the authenticated
//! transcript -- a [`NotarizedSession`]. That is true of a platform API
//! session (X, GitHub, …) and of a reading of Google's OIDC JWKS
//! (`https://www.googleapis.com/oauth2/v3/certs`) alike: the notary does not
//! know, and does not ask, which one it is serving. The sessions differ only in
//! what the prover reveals -- a JWKS reading reveals everything, because a
//! public key set has nothing to hide -- and in which contract reads the
//! record: a Platform Verifier, or `GoogleJwtRoots`, both through the
//! on-chain Notary Service.
//!
//! The TCP wire listener serves Rust backend provers; the browser-facing
//! HTTP/WS API (tlsn-js / tlsn_wasm compatible) lives on a second port.
//!
//! The crate is a library too: [`jwks`] exposes the prover-side helpers the
//! keeper uses to obtain a notarized JWKS reading from a running notary, and a
//! mock that synthesizes one without MPC for contract testing.

pub mod attestation;
pub mod config;
pub mod error;
pub mod jwks;
pub mod server;

pub use attestation::NotarizedSession;
pub use config::NotaryServerConfig;
pub use error::{
    Error,
    Result,
};
pub use server::{
    run,
    NotaryServerHandle,
};
