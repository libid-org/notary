//! The MPC-TLS path: a TCP prover, its session slot, and the attestation
//! written back down the socket it opened.

use std::{
    sync::Arc,
    time::{
        Duration,
        Instant,
    },
};

use libid_transcript::write_msg;
use tlsn::connection::ServerName;
use tokio::{
    io::AsyncReadExt,
    sync::TryAcquireError,
};
use tracing::info;

use super::NotaryState;
use crate::{
    error::{
        Error,
        Result,
    },
    limits::PeekedIo,
};

impl NotaryState {
    /// TCP client (Rust backend prover) — uses the full custom wire protocol.
    pub(super) async fn handle_tcp_prover<T>(&self, socket: T) -> Result<()>
    where
        T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Sync + Unpin + 'static,
    {
        // The slot is taken on the first byte, not on accept: an open socket
        // that sends nothing would otherwise hold it for the connection deadline.
        let socket = await_session_start(socket, self.setup_deadline).await?;
        self.with_mpc_slot(self.handle_notary_session(socket)).await
    }

    /// Run `session` holding one of the MPC-TLS slots, waiting for one first if
    /// they are all taken.
    ///
    /// Waiting, not refusing, is the point: MPC-TLS is the heavy path, and a
    /// prover refused after paying for its setup would pay again, so the slots
    /// only bound how many run at once. The queue is FIFO. The connection
    /// deadline covers the whole session -- the wait for a slot and then the
    /// session itself -- so no client, however broken, pins this handler task
    /// past it, and a queued prover never waits forever either.
    async fn with_mpc_slot<F, T>(&self, session: F) -> Result<T>
    where
        F: std::future::Future<Output = Result<T>>,
    {
        let deadline = self.connection_deadline;
        let shutting_down = || Error::NotaryServer {
            detail: "notary is shutting down; not starting a session".into(),
        };
        tokio::time::timeout(deadline, async {
            let slots = Arc::clone(&self.mpc_sessions);
            let slot = match slots.clone().try_acquire_owned() {
                Ok(slot) => slot,
                Err(TryAcquireError::Closed) => return Err(shutting_down()),
                Err(TryAcquireError::NoPermits) => {
                    info!("MPC-TLS: all session slots busy; prover queued");
                    let queued = Instant::now();
                    let slot =
                        slots.acquire_owned().await.map_err(|_| shutting_down())?;
                    info!(
                        waited_ms = queued.elapsed().as_millis(),
                        "MPC-TLS: prover left the queue and starts its session"
                    );
                    slot
                }
            };
            let outcome = session.await;
            drop(slot);
            outcome
        })
        .await
        .map_err(|_| Error::NotaryServer {
            detail: format!("connection exceeded the {}s deadline", deadline.as_secs()),
        })?
    }

    async fn handle_notary_session<T>(&self, socket: T) -> Result<()>
    where
        T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Sync + Unpin + 'static,
    {
        let result = libid_tlsn::verifier(socket).await?;
        self.handle_verified_session(result).await
    }

    async fn handle_verified_session<T>(
        &self,
        result: libid_tlsn::VerifierResult<T>,
    ) -> Result<()>
    where
        T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Sync + Unpin + 'static,
    {
        let transcript = &result.partial_transcript;
        let sent = transcript.sent_unsafe();
        let recv = transcript.received_unsafe();
        info!(
            "Verification complete: {} sent, {} recv bytes",
            sent.len(),
            recv.len()
        );

        let ServerName::Dns(ref dns_name) = result.server_name;
        let domain = dns_name.as_str().to_string();
        info!("Domain from SNI: {}", domain);

        // One record whatever host the session reached: whether that host was
        // wanted is the reading contract's decision, not the notary's
        // (REQ-COMMON-33).
        let attestation = self
            .attest(
                &result.partial_transcript,
                &domain,
                &result.transcript_commitments,
            )
            .await?;

        let mut io = result.recovered_io;
        write_msg(&mut io, &attestation).await?;
        info!("attestation sent to prover");

        Ok(())
    }
}

/// `socket` with its first byte read and put back, once the prover sends one.
///
/// Reading is what proves a connection is a client rather than an open socket.
/// The byte read here belongs to the session that follows, so it is replayed
/// into it and the session sees the stream it would have seen.
async fn await_session_start<T>(mut socket: T, deadline: Duration) -> Result<PeekedIo<T>>
where
    T: tokio::io::AsyncRead + Unpin,
{
    let mut first = [0u8; 1];
    let read = tokio::time::timeout(deadline, socket.read(&mut first))
        .await
        .map_err(|_| Error::NotaryServer {
            detail: format!(
                "no prover data within the {}s setup deadline",
                deadline.as_secs()
            ),
        })?
        .map_err(|e| Error::NotaryServer {
            detail: format!("reading the first prover byte: {e}"),
        })?;
    if read == 0 {
        return Err(Error::NotaryServer {
            detail: "prover closed the connection before sending anything".into(),
        });
    }
    Ok(PeekedIo::new(first[..read].to_vec(), socket))
}

#[cfg(test)]
mod tests {
    use crate::server::tests::ONE_SESSION_AT_A_TIME;

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn mpc_protocol_returns_attestation_on_the_recovered_socket() {
        use std::time::Duration;

        use libid_signer::SignerSource;
        use libid_transcript::read_msg;
        use tlsn::{
            config::verifier::VerifierConfig,
            verifier::{
                VerifierCommitStart,
                VerifierOutput,
            },
            webpki::{
                CertificateDer,
                RootCertStore,
            },
            Session,
        };
        use tlsn_sdk_core::{
            HttpRequest,
            ProverConfig,
            Reveal,
            SdkProver,
        };
        use tlsn_server_fixture_certs::{
            CA_CERT_DER,
            SERVER_DOMAIN,
        };
        use tokio::io::AsyncReadExt;
        use tokio_util::compat::{
            FuturesAsyncReadCompatExt,
            TokioAsyncReadCompatExt,
        };

        use super::NotaryState;
        use libid_transcript::AttestationWire;

        const TEST_KEY: &str =
            "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";

        let session_slot = ONE_SESSION_AT_A_TIME.lock().await;
        let signer = SignerSource::from_spec(TEST_KEY)
            .unwrap()
            .build_managed(None)
            .await
            .unwrap();
        let expected_pubkey = signer.compressed_public_key().to_vec();
        let state = NotaryState::for_tests(signer);

        let (prover_io, notary_io) = tokio::io::duplex(2 << 23);
        let (target_io, fixture_io) = tokio::io::duplex(1 << 17);
        let fixture_task = tokio::spawn(async move {
            tlsn_server_fixture::bind(fixture_io.compat())
                .await
                .unwrap();
        });

        let notary_task = tokio::spawn(async move {
            let session = Session::new(notary_io.compat());
            let (driver, mut handle) = session.split();
            let driver_task = tokio::spawn(driver);
            let verifier = handle
                .new_verifier(
                    VerifierConfig::builder()
                        .root_store(RootCertStore {
                            roots: vec![CertificateDer(CA_CERT_DER.to_vec())],
                        })
                        .build()
                        .unwrap(),
                )
                .unwrap();
            let verifier = verifier.commit().await.unwrap();
            let VerifierCommitStart::Mpc(verifier) = verifier else {
                panic!("expected MPC mode");
            };
            let verifier = verifier.accept().await.unwrap().run().await.unwrap();
            let tls_transcript = verifier.tls_transcript().clone();
            let (output, verifier) =
                verifier.verify().await.unwrap().accept().await.unwrap();
            verifier.close().await.unwrap();
            handle.close();

            let VerifierOutput {
                server_name,
                transcript,
                transcript_commitments,
                ..
            } = output;
            let recovered_io = driver_task.await.unwrap().unwrap().into_inner();
            state
                .handle_verified_session(libid_tlsn::VerifierResult {
                    partial_transcript: transcript.unwrap(),
                    server_name: server_name.unwrap(),
                    tls_transcript,
                    transcript_commitments,
                    recovered_io,
                })
                .await
                .unwrap();
        });

        let protocol = async {
            let mut prover = SdkProver::new(
                ProverConfig::builder(SERVER_DOMAIN)
                    .root_certs(vec![CA_CERT_DER.to_vec()])
                    .build()
                    .unwrap(),
            )
            .unwrap();
            prover.setup(prover_io.compat()).await.unwrap();
            let response = prover
                .send_request_mpc(
                    target_io.compat(),
                    HttpRequest::get(format!("https://{SERVER_DOMAIN}/bytes?size=16"))
                        .header("Host", SERVER_DOMAIN)
                        .header("Connection", "close"),
                )
                .await
                .unwrap();
            assert_eq!(response.status, 200);

            let transcript = prover.transcript().unwrap();
            prover
                .reveal(
                    Reveal::new()
                        .sent(0..transcript.sent.len())
                        .recv(0..transcript.recv.len())
                        .server_identity(true),
                    None,
                )
                .await
                .unwrap();

            let mut io = prover.finish().await.unwrap().compat();
            let attestation: AttestationWire = read_msg(&mut io).await.unwrap();
            assert_eq!(
                &attestation.attested_data[..32],
                &libid_crypto::keccak256(SERVER_DOMAIN.as_bytes())
            );
            let recovered = libid_crypto::recover_eth_claim(
                &attestation.notary_signature,
                &libid_crypto::keccak256(&attestation.attested_data),
            )
            .unwrap();
            assert_eq!(recovered.to_encoded_point(true).as_bytes(), expected_pubkey);
            assert_eq!(io.read(&mut [0]).await.unwrap(), 0);
        };

        tokio::time::timeout(Duration::from_secs(60), protocol)
            .await
            .expect("local MPC smoke timed out");
        notary_task.await.unwrap();
        fixture_task.await.unwrap();
        drop(session_slot);
    }

    /// A connection that says nothing fails at the setup deadline, holds no
    /// session slot while it waits, and never pins the handler past the
    /// connection deadline, whatever future bug makes a session pend.
    /// Paused time: the runtime auto-advances the clock to the deadline the
    /// moment everything is blocked, so the test finishes in milliseconds.
    #[tokio::test(start_paused = true)]
    async fn silent_connection_hits_the_setup_deadline_and_takes_no_slot() {
        use std::time::Duration;

        use libid_signer::SignerSource;

        use super::NotaryState;

        // anvil #0 — public test key.
        let key_hex = "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
        let signer = SignerSource::from_spec(key_hex)
            .unwrap()
            .build_managed(None)
            .await
            .unwrap();
        let state = NotaryState::for_tests(signer);
        let slots = state.mpc_sessions.available_permits();

        // The client half stays open and never writes a byte.
        let (client, server) = tokio::io::duplex(1 << 16);

        let started = tokio::time::Instant::now();
        let connection = {
            let state = state.clone();
            tokio::spawn(async move { state.handle_tcp_prover(server).await })
        };

        // A moment in: the connection is alive and still holds nothing.
        tokio::time::sleep(Duration::from_secs(1)).await;
        assert!(!connection.is_finished(), "the connection failed too early");
        assert_eq!(
            state.mpc_sessions.available_permits(),
            slots,
            "a connection that has sent nothing took a session slot"
        );

        let err = connection
            .await
            .unwrap()
            .expect_err("a silent connection must fail, not pend");
        assert!(
            err.to_string().contains("setup deadline"),
            "expected the setup-deadline error, got: {err}"
        );
        assert!(
            started.elapsed() >= state.setup_deadline,
            "failed before the setup deadline — some step errored spuriously"
        );
        assert!(
            started.elapsed() < state.connection_deadline,
            "an idle socket must not be held for the whole connection deadline"
        );
        drop(client);
    }

    /// The limits an operator sets, tripped for real: the MPC-TLS session
    /// queue.
    mod limits {
        use std::{
            sync::{
                atomic::{
                    AtomicBool,
                    Ordering,
                },
                Arc,
            },
            time::Duration,
        };

        use libid_transcript::{
            read_msg,
            AttestationWire,
        };
        use tlsn::{
            config::verifier::VerifierConfig,
            verifier::{
                VerifierCommitStart,
                VerifierOutput,
            },
            webpki::{
                CertificateDer,
                RootCertStore,
            },
            Session,
        };
        use tlsn_sdk_core::{
            HttpRequest,
            ProverConfig,
            Reveal,
            SdkProver,
        };
        use tlsn_server_fixture_certs::{
            CA_CERT_DER,
            SERVER_DOMAIN,
        };
        use tokio::{
            io::{
                AsyncWriteExt,
                DuplexStream,
            },
            sync::Semaphore,
        };
        use tokio_util::compat::{
            FuturesAsyncReadCompatExt,
            TokioAsyncReadCompatExt,
        };

        use super::super::{
            NotaryState,
            Result,
        };
        use crate::server::tests::{
            test_signer,
            ONE_SESSION_AT_A_TIME,
        };

        /// The notary's half of an MPC-TLS session against the test fixture:
        /// what `libid_tlsn::verifier` does, with the fixture's CA trusted,
        /// ending in the real attestation path.
        async fn fixture_mpc_session(
            notary_io: DuplexStream,
            state: &NotaryState,
        ) -> Result<()> {
            let session = Session::new(notary_io.compat());
            let (driver, mut handle) = session.split();
            let driver_task = tokio::spawn(driver);
            let verifier = handle
                .new_verifier(
                    VerifierConfig::builder()
                        .root_store(RootCertStore {
                            roots: vec![CertificateDer(CA_CERT_DER.to_vec())],
                        })
                        .build()
                        .unwrap(),
                )
                .unwrap();
            let VerifierCommitStart::Mpc(verifier) = verifier.commit().await.unwrap()
            else {
                panic!("expected MPC mode");
            };
            let verifier = verifier.accept().await.unwrap().run().await.unwrap();
            let tls_transcript = verifier.tls_transcript().clone();
            let (output, verifier) =
                verifier.verify().await.unwrap().accept().await.unwrap();
            verifier.close().await.unwrap();
            handle.close();
            let VerifierOutput {
                server_name,
                transcript,
                transcript_commitments,
                ..
            } = output;
            let recovered_io = driver_task.await.unwrap().unwrap().into_inner();
            state
                .handle_verified_session(libid_tlsn::VerifierResult {
                    partial_transcript: transcript.unwrap(),
                    server_name: server_name.unwrap(),
                    tls_transcript,
                    transcript_commitments,
                    recovered_io,
                })
                .await
        }

        /// With one MPC-TLS slot taken, a second prover is not refused: it
        /// waits, and once the slot frees it runs a whole session and gets
        /// its attestation. The first "prover" is a silent TCP client on the
        /// real handler; the second is a real prover behind the same queue.
        #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
        async fn mpc_prover_queues_behind_a_full_slot_and_then_succeeds() {
            let session_slot = ONE_SESSION_AT_A_TIME.lock().await;
            let mut state = NotaryState::for_tests(test_signer().await);
            state.mpc_sessions = Arc::new(Semaphore::new(1));
            let expected_pubkey = state.signer.compressed_public_key().to_vec();

            // A holds the only slot: it sent the byte that starts a session,
            // then said nothing more. Connecting alone would take no slot.
            let (mut a_client, a_server) = tokio::io::duplex(1 << 16);
            let a_state = state.clone();
            let a_task =
                tokio::spawn(async move { a_state.handle_tcp_prover(a_server).await });
            a_client.write_all(b"\x00").await.unwrap();
            let slot_taken = async {
                while state.mpc_sessions.available_permits() != 0 {
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
            };
            tokio::time::timeout(Duration::from_secs(5), slot_taken)
                .await
                .expect("the stalled client never took the slot");

            // B: a real prover, whose notary side goes through the queue.
            let (prover_io, notary_io) = tokio::io::duplex(2 << 23);
            let (target_io, fixture_io) = tokio::io::duplex(1 << 17);
            let fixture_task = tokio::spawn(async move {
                tlsn_server_fixture::bind(fixture_io.compat())
                    .await
                    .unwrap();
            });
            let b_started = Arc::new(AtomicBool::new(false));
            let b_state = state.clone();
            let b_task = tokio::spawn({
                let b_started = Arc::clone(&b_started);
                async move {
                    b_state
                        .with_mpc_slot(async {
                            b_started.store(true, Ordering::SeqCst);
                            fixture_mpc_session(notary_io, &b_state).await
                        })
                        .await
                }
            });

            let mut prover = SdkProver::new(
                ProverConfig::builder(SERVER_DOMAIN)
                    .root_certs(vec![CA_CERT_DER.to_vec()])
                    .build()
                    .unwrap(),
            )
            .unwrap();
            let mut setup = Box::pin(prover.setup(prover_io.compat()));

            // Queued: B's setup neither completes nor fails while A holds the
            // slot, and B's session has not started.
            assert!(
                tokio::time::timeout(Duration::from_secs(1), &mut setup)
                    .await
                    .is_err(),
                "B ran, or was refused, while A held the only slot"
            );
            assert!(!b_started.load(Ordering::SeqCst), "B started before A left");
            assert!(!b_task.is_finished(), "B was refused instead of queued");

            // A goes away: its verifier fails fast on the dead socket and the
            // slot is released. B, still on the same connection, proceeds.
            drop(a_client);
            let a_outcome = tokio::time::timeout(Duration::from_secs(5), a_task)
                .await
                .expect("the stalled client did not release the slot")
                .unwrap();
            assert!(a_outcome.is_err(), "a stalled client cannot have succeeded");

            tokio::time::timeout(Duration::from_secs(60), &mut setup)
                .await
                .expect("the queued prover never set up after the slot freed")
                .unwrap();
            drop(setup);
            assert!(b_started.load(Ordering::SeqCst));

            let protocol = async {
                let response = prover
                    .send_request_mpc(
                        target_io.compat(),
                        HttpRequest::get(format!(
                            "https://{SERVER_DOMAIN}/bytes?size=16"
                        ))
                        .header("Host", SERVER_DOMAIN)
                        .header("Connection", "close"),
                    )
                    .await
                    .unwrap();
                assert_eq!(response.status, 200);
                let transcript = prover.transcript().unwrap();
                prover
                    .reveal(
                        Reveal::new()
                            .sent(0..transcript.sent.len())
                            .recv(0..transcript.recv.len())
                            .server_identity(true),
                        None,
                    )
                    .await
                    .unwrap();
                let mut io = prover.finish().await.unwrap().compat();
                let attestation: AttestationWire = read_msg(&mut io).await.unwrap();
                let recovered = libid_crypto::recover_eth_claim(
                    &attestation.notary_signature,
                    &libid_crypto::keccak256(&attestation.attested_data),
                )
                .unwrap();
                assert_eq!(recovered.to_encoded_point(true).as_bytes(), expected_pubkey);
            };
            tokio::time::timeout(Duration::from_secs(60), protocol)
                .await
                .expect("the queued prover never finished after the slot freed");
            b_task.await.unwrap().expect("the queued session failed");
            fixture_task.await.unwrap();
            drop(session_slot);
        }

        /// A queued prover is still under the connection deadline: it fails
        /// with the deadline error, not later. Paused time, as in
        /// `silent_connection_hits_the_deadline`.
        #[tokio::test(start_paused = true)]
        async fn queued_prover_hits_the_deadline_while_waiting() {
            let mut state = NotaryState::for_tests(test_signer().await);
            state.mpc_sessions = Arc::new(Semaphore::new(1));
            let running = Arc::clone(&state.mpc_sessions)
                .acquire_owned()
                .await
                .unwrap();

            let started = tokio::time::Instant::now();
            let err = state
                .with_mpc_slot(async { Ok(()) })
                .await
                .expect_err("a queued prover must not wait past the deadline");
            assert!(err.to_string().contains("deadline"), "got: {err}");
            assert!(started.elapsed() >= state.connection_deadline);
            drop(running);
        }

        /// Shutdown closes the queue: a prover waiting for a slot fails at
        /// once with a message that says so, instead of sitting there until
        /// the runtime is torn down under it.
        #[tokio::test]
        async fn queued_prover_fails_fast_when_the_queue_closes() {
            let mut state = NotaryState::for_tests(test_signer().await);
            state.mpc_sessions = Arc::new(Semaphore::new(1));
            let running = Arc::clone(&state.mpc_sessions)
                .acquire_owned()
                .await
                .unwrap();

            let queued_state = state.clone();
            let queued = tokio::spawn(async move {
                queued_state.with_mpc_slot(async { Ok(()) }).await
            });
            tokio::time::sleep(Duration::from_millis(50)).await;
            assert!(!queued.is_finished(), "the prover was not queued");

            state.mpc_sessions.close();
            let err = tokio::time::timeout(Duration::from_secs(1), queued)
                .await
                .expect("the queued prover did not drain on shutdown")
                .unwrap()
                .expect_err("a drained prover has no session to succeed");
            assert!(err.to_string().contains("shutting down"), "got: {err}");
            drop(running);
        }
    }
}
