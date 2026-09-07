//! Mock prover: pretends to be the result of a successful MPC-TLS session by
//! fetching the JWKS over plain TLS, synthesizing the transcript the real
//! session would have produced, and signing the record with a configurable
//! key. Lets a deployment drive `GoogleJwtRoots` end-to-end without standing
//! up the MPC plumbing.
//!
//! What's "fake" vs "real":
//!   * **Fake**: nobody authenticated `www.googleapis.com`. The mock composes
//!     the request and response bytes itself and stamps the authority in.
//!   * **Real**: everything the contract reads -- the body bytes Google sent,
//!     the request line and headers as hyper writes them, the response
//!     framing, the section 9.1 layout, the encoding, the EIP-191 signature.
//!     A record from here is byte for byte what a real session with the same
//!     body would produce, so the contract runs every check it runs in
//!     production; only the notary key it recovers is one the deployment
//!     chose to trust.

use k256::ecdsa::SigningKey;
use libid_ceremony::{
    attestation::tag,
    AttestedData,
    DirectionBlock,
    RevealedRange,
};
use libid_crypto::{
    keccak256,
    pubkey_to_eth_address,
    sign_eth_claim,
};
use libid_transcript::ceremony::Layout;

use crate::{
    error::{
        Error,
        Result,
    },
    jwks::{
        self,
        JWKS_DOMAIN,
    },
    NotarizedSession,
};

const JWKS_URL: &str = "https://www.googleapis.com/oauth2/v3/certs";

/// What the mock calls itself in the `user-agent` it synthesizes. The real
/// prover sends `libid-keeper/<version>` in the same slot; the contract reads
/// neither.
pub const MOCK_USER_AGENT: &str = "libid-keeper/mock";

/// Chunk size of the synthesized `transfer-encoding: chunked` body. Small
/// enough that a boundary falls inside every base64url modulus (342
/// characters), so the on-chain de-chunker is exercised where it matters, not
/// only at the framing's ends.
const CHUNK_SIZE: usize = 256;

/// Configuration for [`MockProver`].
#[derive(Debug, Clone)]
pub struct MockProverConfig {
    /// Override the JWKS URL (useful for offline tests with a local server).
    pub jwks_url: Option<String>,
    /// Override the response body — if set, no HTTP fetch.
    pub fixture_body: Option<Vec<u8>>,
    /// Unix timestamp (seconds) to put in the record as `createdAt`.
    pub timestamp: u64,
    /// Frame the synthesized response as `transfer-encoding: chunked`, which is
    /// what Google sends today, so the contract's de-chunker runs. `false`
    /// frames it with `content-length`, the other framing the contract accepts.
    pub chunked: bool,
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
            chunked: true,
        }
    }
}

/// See the module docs: a no-MPC prover that signs real records with a
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

    /// Notary's Ethereum address (what the deployment registers as a trusted
    /// notary on its `NotaryService`).
    pub fn notary_address(&self) -> [u8; 20] {
        pubkey_to_eth_address(self.notary_key.verifying_key())
    }

    /// Run the full pipeline: fetch (or load) the JWKS, synthesize the
    /// transcript, lay it out, encode the record, sign it.
    pub async fn build_session(&mut self) -> Result<NotarizedSession> {
        let body = match self.cfg.fixture_body.as_ref() {
            Some(b) => b.clone(),
            None => fetch_jwks(self.cfg.jwks_url.as_deref().unwrap_or(JWKS_URL)).await?,
        };

        let sent = request_bytes(MOCK_USER_AGENT)?;
        let received = response_bytes(&body, self.cfg.chunked);
        let (sent_layout, recv_layout) = jwks::layout(&sent, &received);

        let data = AttestedData {
            authority_id: tag(JWKS_DOMAIN),
            created_at: self.cfg.timestamp,
            sent_transcript_length: offset(sent.len())?,
            recv_transcript_length: offset(received.len())?,
            sent: direction(&sent, &sent_layout)?,
            received: direction(&received, &recv_layout)?,
        };
        let attested_data = data.encode().map_err(|e| Error::Jwks {
            detail: format!("encode attested data: {e}"),
        })?;
        // The same preimage the real notary signs, and the only one
        // (REQ-COMMON-47): keccak256 of the encoded record, EIP-191 wrapped.
        let notary_signature =
            sign_eth_claim(&self.notary_key, &keccak256(&attested_data))?;

        Ok(NotarizedSession {
            attested_data,
            notary_signature,
        })
    }
}

async fn fetch_jwks(url: &str) -> Result<Vec<u8>> {
    let body = reqwest::get(url).await?.bytes().await?;
    Ok(body.to_vec())
}

/// The bytes hyper writes for [`jwks::request`]: the request line in
/// origin-form, each header as `name: value` in lowercase and in the order it
/// was set, then the empty line. Derived from the same request the real prover
/// sends rather than typed out, and pinned against hyper's own encoder in the
/// tests below.
pub(crate) fn request_bytes(user_agent: &str) -> Result<Vec<u8>> {
    let request = jwks::request(user_agent)?;
    // What `prover_generic` puts on the wire: the path and query only.
    let target = request
        .uri()
        .path_and_query()
        .map_or("/", |target| target.as_str());
    let mut out = format!("{} {target} HTTP/1.1\r\n", request.method()).into_bytes();
    for (name, value) in request.headers() {
        out.extend_from_slice(name.as_str().as_bytes());
        out.extend_from_slice(b": ");
        out.extend_from_slice(value.as_bytes());
        out.extend_from_slice(b"\r\n");
    }
    out.extend_from_slice(b"\r\n");
    Ok(out)
}

/// The response as the contract will read it: the status line it pins, the
/// content type Google sends, and the body under one of the two framings the
/// contract de-frames.
fn response_bytes(body: &[u8], chunked: bool) -> Vec<u8> {
    let mut out =
        b"HTTP/1.1 200 OK\r\ncontent-type: application/json; charset=UTF-8\r\n".to_vec();
    if chunked {
        out.extend_from_slice(b"transfer-encoding: chunked\r\n\r\n");
        out.extend_from_slice(&chunk(body));
    } else {
        out.extend_from_slice(
            format!("content-length: {}\r\n\r\n", body.len()).as_bytes(),
        );
        out.extend_from_slice(body);
    }
    out
}

/// RFC 9112 chunked framing: `size CRLF data CRLF` per chunk, the size in
/// hex, then the `0 CRLF CRLF` terminator with no trailers -- exactly the
/// grammar the contract's de-chunker accepts.
fn chunk(body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(body.len() + 8 * (body.len() / CHUNK_SIZE + 2));
    for piece in body.chunks(CHUNK_SIZE) {
        out.extend_from_slice(format!("{:x}\r\n", piece.len()).as_bytes());
        out.extend_from_slice(piece);
        out.extend_from_slice(b"\r\n");
    }
    out.extend_from_slice(b"0\r\n\r\n");
    out
}

/// One direction of the record from its transcript and layout, the way
/// `libid_tlsn::attest` builds it from a real session.
fn direction(bytes: &[u8], layout: &Layout) -> Result<DirectionBlock> {
    // A mock has no blinder to commit with. The JWKS layout commits nothing,
    // so a layout that asks for one is a bug here, not something to paper
    // over with a made-up commitment the contract would refuse anyway.
    if !layout.commit.is_empty() {
        return Err(Error::Jwks {
            detail: "the mock prover cannot commit a range".into(),
        });
    }
    let revealed = layout
        .reveal
        .iter()
        .map(|range| {
            Ok(RevealedRange {
                start: offset(range.start)?,
                bytes: bytes[range.clone()].to_vec(),
            })
        })
        .collect::<Result<_>>()?;
    Ok(DirectionBlock {
        revealed,
        commitments: Vec::new(),
    })
}

fn offset(value: usize) -> Result<u32> {
    u32::try_from(value).map_err(|_| Error::Jwks {
        detail: format!(
            "transcript offset {value} does not fit the format's 32-bit field"
        ),
    })
}

#[cfg(test)]
mod tests {
    use libid_crypto::recover_eth_claim;

    use super::*;
    use crate::jwks::JWKS_ENDPOINT;

    /// Google's real body, fetched 2026-09-03 with `curl --http1.1`:
    /// pretty-printed, two-space indent, LF newlines, a space after each colon
    /// -- the shape the contract's parser has to read.
    const GOOGLE_BODY: &[u8] = include_bytes!("../../tests/fixtures/certs.json");

    const TIMESTAMP: u64 = 1_700_000_000;

    fn prover(chunked: bool) -> MockProver {
        let (sk, _) = libid_crypto::generate_keypair();
        MockProver::new(
            sk,
            MockProverConfig {
                jwks_url: None,
                fixture_body: Some(GOOGLE_BODY.to_vec()),
                timestamp: TIMESTAMP,
                chunked,
            },
        )
    }

    // --- A reader for the record ---------------------------------------------
    //
    // libid-ceremony encodes and does not decode: whoever decodes also checks,
    // and that is the chain and the client. These tests need to look inside
    // what they built, so they carry their own one-way reader for the fixed
    // layout -- header, then per direction a count of revealed ranges
    // (`u32 start, u64 len, bytes`) and a count of commitments
    // (`u32 start, u32 end, bytes32`).

    struct Block {
        revealed: Vec<(u32, Vec<u8>)>,
        commitments: usize,
    }

    struct Decoded {
        authority_id: [u8; 32],
        created_at: u64,
        sent_length: u32,
        recv_length: u32,
        sent: Block,
        received: Block,
    }

    struct Reader<'a> {
        bytes: &'a [u8],
        at: usize,
    }

    impl<'a> Reader<'a> {
        fn take(&mut self, n: usize) -> &'a [u8] {
            let out = &self.bytes[self.at..self.at + n];
            self.at += n;
            out
        }

        fn u32(&mut self) -> u32 {
            u32::from_be_bytes(self.take(4).try_into().unwrap())
        }

        fn u64(&mut self) -> u64 {
            u64::from_be_bytes(self.take(8).try_into().unwrap())
        }

        fn block(&mut self) -> Block {
            let revealed = (0..self.u64())
                .map(|_| {
                    let start = self.u32();
                    let len = usize::try_from(self.u64()).unwrap();
                    (start, self.take(len).to_vec())
                })
                .collect();
            let commitments = usize::try_from(self.u64()).unwrap();
            for _ in 0..commitments {
                self.take(4 + 4 + 32);
            }
            Block {
                revealed,
                commitments,
            }
        }
    }

    fn decode(bytes: &[u8]) -> Decoded {
        let mut r = Reader { bytes, at: 0 };
        let decoded = Decoded {
            authority_id: r.take(32).try_into().unwrap(),
            created_at: r.u64(),
            sent_length: r.u32(),
            recv_length: r.u32(),
            sent: r.block(),
            received: r.block(),
        };
        assert_eq!(r.at, bytes.len(), "bytes after the last commitment");
        decoded
    }

    /// The contract's `_dechunk`, as a test oracle: strict about every
    /// delimiter, so a framing slip in `chunk` fails here rather than on chain.
    fn dechunk(mut raw: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        loop {
            let line = raw
                .windows(2)
                .position(|w| w == b"\r\n")
                .expect("a chunk-size line");
            let size =
                usize::from_str_radix(std::str::from_utf8(&raw[..line]).unwrap(), 16)
                    .expect("a hex chunk size with no extension");
            raw = &raw[line + 2..];
            if size == 0 {
                assert_eq!(raw, b"\r\n", "no trailers, nothing after the last chunk");
                return out;
            }
            out.extend_from_slice(&raw[..size]);
            assert_eq!(&raw[size..size + 2], b"\r\n", "CRLF after the chunk data");
            raw = &raw[size + 2..];
        }
    }

    fn split_head(recv: &[u8]) -> (&[u8], &[u8]) {
        let boundary = recv
            .windows(4)
            .position(|w| w == b"\r\n\r\n")
            .expect("a head boundary");
        (&recv[..boundary + 4], &recv[boundary + 4..])
    }

    #[tokio::test]
    async fn the_record_names_google_as_its_authority() {
        let session = prover(true).build_session().await.unwrap();
        let decoded = decode(&session.attested_data);
        assert_eq!(
            decoded.authority_id,
            libid_crypto::keccak256(b"www.googleapis.com")
        );
        assert_eq!(
            &session.attested_data[..32],
            &decoded.authority_id,
            "the authority is the first field of the record"
        );
        assert_eq!(decoded.created_at, TIMESTAMP);
    }

    #[tokio::test]
    async fn the_record_reveals_both_directions_whole_and_commits_nothing() {
        let session = prover(true).build_session().await.unwrap();
        let decoded = decode(&session.attested_data);

        for (block, length) in [
            (&decoded.sent, decoded.sent_length),
            (&decoded.received, decoded.recv_length),
        ] {
            let [(start, bytes)] = block.revealed.as_slice() else {
                panic!(
                    "expected exactly one revealed range, got {}",
                    block.revealed.len()
                );
            };
            assert_eq!(*start, 0, "the range must begin at the transcript origin");
            assert_eq!(bytes.len(), length as usize, "the range must reach the end");
            assert_eq!(block.commitments, 0, "a commitment would hide bytes");
        }
        assert!(decoded.recv_length > 0);
    }

    #[tokio::test]
    async fn the_request_is_the_line_the_contract_pins() {
        let session = prover(true).build_session().await.unwrap();
        let decoded = decode(&session.attested_data);
        let sent = &decoded.sent.revealed[0].1;
        assert_eq!(
            sent.as_slice(),
            b"GET /oauth2/v3/certs HTTP/1.1\r\n\
              host: www.googleapis.com\r\n\
              connection: close\r\n\
              accept: application/json\r\n\
              user-agent: libid-keeper/mock\r\n\
              \r\n"
                .as_slice()
        );
    }

    #[tokio::test]
    async fn the_signature_recovers_to_the_notary_address() {
        let mut prover = prover(true);
        let expected = prover.notary_address();
        let session = prover.build_session().await.unwrap();
        assert_eq!(session.notary_signature.len(), 65);
        let recovered = recover_eth_claim(
            &session.notary_signature,
            &keccak256(&session.attested_data),
        )
        .unwrap();
        assert_eq!(pubkey_to_eth_address(&recovered), expected);
    }

    #[tokio::test]
    async fn chunked_framing_round_trips_the_body() {
        let session = prover(true).build_session().await.unwrap();
        let decoded = decode(&session.attested_data);
        let (head, body) = split_head(&decoded.received.revealed[0].1);
        assert_eq!(
            head,
            b"HTTP/1.1 200 OK\r\n\
              content-type: application/json; charset=UTF-8\r\n\
              transfer-encoding: chunked\r\n\
              \r\n"
        );
        assert_eq!(dechunk(body), GOOGLE_BODY);
        assert!(
            GOOGLE_BODY.len() > CHUNK_SIZE,
            "the fixture must span several chunks for this to mean anything"
        );
    }

    #[tokio::test]
    async fn content_length_framing_carries_the_body_verbatim() {
        let session = prover(false).build_session().await.unwrap();
        let decoded = decode(&session.attested_data);
        let (head, body) = split_head(&decoded.received.revealed[0].1);
        assert_eq!(
            head,
            format!(
                "HTTP/1.1 200 OK\r\n\
                 content-type: application/json; charset=UTF-8\r\n\
                 content-length: {}\r\n\
                 \r\n",
                GOOGLE_BODY.len()
            )
            .as_bytes()
        );
        assert_eq!(body, GOOGLE_BODY);
    }

    /// The mock claims its request is what hyper writes. hyper is the
    /// authority on that: drive its HTTP/1 client over an in-memory pipe with
    /// the request the real prover builds, and compare the bytes.
    #[tokio::test]
    async fn hyper_writes_the_request_the_mock_synthesizes() {
        use hyper_util::rt::TokioIo;
        use tokio::io::AsyncReadExt;

        let (client_io, mut server_io) = tokio::io::duplex(1 << 12);
        let (mut sender, connection) =
            hyper::client::conn::http1::handshake(TokioIo::new(client_io))
                .await
                .unwrap();
        tokio::spawn(connection);

        let mut request = jwks::request(MOCK_USER_AGENT).unwrap();
        // `prover_generic` rewrites the URI to origin-form before sending; the
        // wire is what is under test here, so do the same.
        *request.uri_mut() = JWKS_ENDPOINT.parse().unwrap();
        let sending = tokio::spawn(async move { sender.send_request(request).await });

        let mut wire = Vec::new();
        let mut buf = [0u8; 1024];
        while !wire.ends_with(b"\r\n\r\n") {
            let n = server_io.read(&mut buf).await.unwrap();
            assert!(n > 0, "the connection closed before the request head");
            wire.extend_from_slice(&buf[..n]);
        }
        assert_eq!(wire, request_bytes(MOCK_USER_AGENT).unwrap());

        // No response ever comes; the pending send fails, which is expected.
        drop(server_io);
        let _ = sending.await;
    }
}
