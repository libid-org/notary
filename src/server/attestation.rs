//! Ceremony attestation.

use std::time::SystemTime;

use libid_ceremony::AttestedData;
use libid_tlsn::attest::{
    FromObserved,
    ObservedSession,
};
use libid_transcript::AttestationWire;
use tlsn::transcript::{
    PartialTranscript,
    TranscriptCommitment,
};

use super::NotaryState;
use crate::error::{
    Error,
    Result,
};

// The wire record itself is `libid_transcript::AttestationWire`. It is defined
// there, beside the `write_msg`/`read_msg` that frame it, because a prover has
// to read exactly what this writes -- and a copy here would be a second
// definition of one message, agreeing only for as long as nobody renames a
// field. What the notary puts in it is still decided here, and it is nothing
// it derived by applying a profile rule: no handle, no account identifier, no
// client identifier, no chain address (REQ-COMMON-61). Every one is derivable
// from the revealed ranges, and a second signed representation can disagree
// with the bytes it was taken from. That is why this endpoint no longer takes
// `handle`, `user_id` or `session_addr` -- the Platform Verifier reads them
// itself, and the notary deciding them would be the profile-specific
// judgement REQ-COMMON-33 forbids it.

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

pub(super) fn attestation_frame(attestation: &AttestationWire) -> Result<Vec<u8>> {
    const MAX_FRAME_BYTES: usize = 10 * 1024 * 1024;

    let json = serde_json::to_vec(attestation)?;
    if json.len() > MAX_FRAME_BYTES {
        return Err(Error::NotaryServer {
            detail: format!("attestation frame is too large: {} bytes", json.len()),
        });
    }
    let len = u32::try_from(json.len())
        .map_err(|_| Error::NotaryServer {
            detail: format!("attestation frame is too large: {} bytes", json.len()),
        })?
        .to_be_bytes();
    let mut frame = Vec::with_capacity(len.len() + json.len());
    frame.extend_from_slice(&len);
    frame.extend_from_slice(&json);
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
        .unwrap();
        let mut browser = frame.as_slice();

        let frame: serde_json::Value = read_msg(&mut browser).await.unwrap();
        assert_eq!(frame["attested_data"], serde_json::json!([1, 2, 3]));
        assert_eq!(frame["notary_signature"].as_array().unwrap().len(), 65);
        assert_eq!(browser.read(&mut [0]).await.unwrap(), 0);
    }
}
