//! The libID notary service.
//!
//! One binary, one signing identity, two notary duties:
//!
//! * **Platform sessions** — MPC-TLS / zkTLS (ProxyMode) notarization of
//!   platform API sessions (X, GitHub, …), producing tlsn attestations,
//!   `EvmProof`s and on-demand token/me hash-commit attestations.
//! * **JWKS readings** — notarized readings of Google's OIDC JWKS
//!   (`https://www.googleapis.com/oauth2/v3/certs`), producing signed
//!   `JwksRotationProof`s for the on-chain `JwksOracle`.
//!
//! Both duties are served by the same TCP wire listener: the notary runs the
//! MPC-TLS verifier first, then dispatches on the TLS-cert-verified server
//! name — `www.googleapis.com` gets the JWKS response shape, everything else
//! the platform response shape. The browser-facing HTTP/WS API (tlsn-js /
//! tlsn_wasm compatible) lives on a second port.
//!
//! The crate is a library too: [`jwks`] exposes the prover-side helpers a
//! backend rotation listener needs to obtain a `JwksRotationProof` from a
//! running notary.

pub mod config;
pub mod error;
pub mod jwks;
pub mod server;

pub use config::NotaryServerConfig;
pub use error::{
    Error,
    Result,
};
pub use server::{
    run,
    NotaryServerHandle,
};
