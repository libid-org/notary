//! The section 9.1 ceremony attestation: the attested data for what a
//! session observed, and the notary's signature over its keccak256.
//!
//! The record carries nothing the notary derived by applying a profile
//! rule -- no handle, account, client or chain address (REQ-COMMON-61).
//! Each is derivable from the revealed ranges, and a second signed
//! representation could disagree with the bytes it was taken from.

use std::time::SystemTime;

use libid_ceremony::AttestedData;
use libid_tlsn::attest::{
    FromObserved,
    ObservedSession,
};
use libid_transcript::{
    write_msg,
    AttestationWire,
};
use tlsn::transcript::{
    PartialTranscript,
    TranscriptCommitment,
};

use super::NotaryState;
use crate::error::{
    Error,
    Result,
};

impl NotaryState {
    /// Build the section 9.1 attested data for one completed session, stamped
    /// with the notary's own clock, and sign it.
    ///
    /// Both transports end here and receive the same record on their reclaimed
    /// channel, because transport says nothing about the TLS session it
    /// describes.
    pub(super) async fn attest(
        &self,
        transcript: &PartialTranscript,
        authority: &str,
        commitments: &[TranscriptCommitment],
    ) -> Result<AttestationWire> {
        let attested = AttestedData::from_observed(ObservedSession {
            transcript,
            authority,
            commitments,
            created_at: SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        })
        .map_err(|e| Error::NotaryServer {
            detail: format!("attested data: {e}"),
        })?;
        let encoded = attested.encode().map_err(|e| Error::NotaryServer {
            detail: format!("encode attested data: {e}"),
        })?;

        // The notary signs `keccak256(attestedData)` and no other preimage
        // (REQ-COMMON-47).
        let notary_signature = self
            .signer
            .sign_claim(&libid_crypto::keccak256(&encoded))
            .await?;
        Ok(AttestationWire {
            attested_data: encoded,
            notary_signature,
        })
    }
}

/// The attestation as one WebSocket message: the framing `write_msg` puts on
/// the TCP wire, so a browser and a Rust prover read the same bytes.
pub(super) async fn attestation_frame(attestation: &AttestationWire) -> Result<Vec<u8>> {
    let mut frame = Vec::new();
    write_msg(&mut frame, attestation).await?;
    Ok(frame)
}

#[cfg(test)]
mod tests {
    #[tokio::test]
    async fn attestation_is_one_length_prefixed_frame_then_eof() {
        use libid_transcript::read_msg;
        use tokio::io::AsyncReadExt;

        use super::{
            attestation_frame,
            AttestationWire,
        };

        let frame = attestation_frame(&AttestationWire {
            attested_data: vec![1, 2, 3],
            notary_signature: vec![4; 65],
        })
        .await
        .unwrap();
        let mut browser = frame.as_slice();

        let frame: serde_json::Value = read_msg(&mut browser).await.unwrap();
        assert_eq!(frame["attested_data"], serde_json::json!([1, 2, 3]));
        assert_eq!(frame["notary_signature"].as_array().unwrap().len(), 65);
        assert_eq!(browser.read(&mut [0]).await.unwrap(), 0);
    }
}
