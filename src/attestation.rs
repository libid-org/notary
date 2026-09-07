//! The notary's answer to a completed session: the section 9.1 record and the
//! signature over it.
//!
//! One record for every session. A platform session and a JWKS reading differ
//! in what the prover chose to reveal, and in nothing the notary writes: the
//! record is built from what the session disclosed, the server the notary
//! authenticated, the commitments over the rest, and the notary's own clock.
//! Which contract reads it -- a Platform Verifier, or `GoogleJwtRoots` --
//! is decided by whoever submits it, and both authenticate the signature
//! through the on-chain Notary Service.
//!
//! The type is libid-transcript's [`AttestationWire`]. Both parties speak it --
//! the notary writes it, a prover reads it back -- so it is defined once, where
//! both can reach it, rather than held privately here and mirrored in every
//! consumer: a renamed field would then fail at parse time with an error that
//! says nothing about which side moved. The name here says what the record IS
//! to a consumer: one notarized session, ready to be spent on chain.
//!
//! [`AttestationWire`]: libid_transcript::AttestationWire

/// A notarized session.
///
/// `attested_data` is the exact bytes of ceremony-common section 9.1;
/// `notary_signature` is EIP-191 over `keccak256(attested_data)`. Those are
/// the `attestedData` and `proof` arguments of `NotaryService.verify`, and of
/// everything built on it (`GoogleJwtRoots.rotate` included).
///
/// Serialized as `{ "attested_data": [u8...], "notary_signature": [u8...] }`:
/// one length-prefixed JSON message on the recovered socket for an MPC prover,
/// and the final WebSocket message for a browser.
pub type NotarizedSession = libid_transcript::AttestationWire;
