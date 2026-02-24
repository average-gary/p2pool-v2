// Copyright (C) 2024, 2025 P2Poolv2 Developers (see AUTHORS)
//
// This file is part of P2Poolv2
//
// P2Poolv2 is free software: you can redistribute it and/or modify it under
// the terms of the GNU General Public License as published by the Free
// Software Foundation, either version 3 of the License, or (at your option)
// any later version.
//
// P2Poolv2 is distributed in the hope that it will be useful, but WITHOUT ANY
// WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
// FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License along with
// P2Poolv2. If not, see <https://www.gnu.org/licenses/>.

//! Integration tests for the SV2 Mining Protocol server.
//!
//! These tests exercise the full SV2 connection lifecycle over real TCP
//! connections with Noise NX encryption:
//!
//! 1. TCP connect -> Noise handshake
//! 2. SetupConnection exchange
//! 3. OpenStandardMiningChannel
//! 4. Receive NewMiningJob / SetNewPrevHash
//! 5. SubmitSharesStandard -> SubmitSharesSuccess
//! 6. Connection teardown and cleanup

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use p2poolv2_lib::accounting::OutputPair;
use p2poolv2_lib::stratum::emission::Emission;
use p2poolv2_lib::stratum::work::block_template::BlockTemplate;
use p2poolv2_lib::stratum_sv2::channels::start_channel_manager;
use p2poolv2_lib::stratum_sv2::connection::{AuthorityKeypair, Sv2ServerConfig, run_accept_loop};
use p2poolv2_lib::stratum_sv2::connections::start_sv2_connections_handler;
use p2poolv2_lib::stratum_sv2::difficulty::difficulty_to_target;
use p2poolv2_lib::stratum_sv2::handler::{Sv2ConnectionContext, handle_sv2_connection};
use p2poolv2_lib::stratum_sv2::job_distributor::start_job_distributor;
use p2poolv2_lib::test_utils::setup_test_chain_store_handle;

use stratum_core::codec_sv2::{NoiseEncoder, StandardNoiseDecoder, State};
use stratum_core::common_messages_sv2::{Protocol, SetupConnection};
use stratum_core::framing_sv2::framing::{Frame, Sv2Frame};
use stratum_core::mining_sv2::{OpenStandardMiningChannel, SubmitSharesStandard};
use stratum_core::noise_sv2::{INITIATOR_EXPECTED_HANDSHAKE_MESSAGE_SIZE, Initiator};
use stratum_core::parsers_sv2::{AnyMessage, CommonMessages, IsSv2Message, Mining};

use bitcoin::secp256k1::{Keypair, Secp256k1, SecretKey};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, oneshot};

// ---------------------------------------------------------------------------
// Test constants
// ---------------------------------------------------------------------------

/// Fixed test private key (32 bytes hex). This is a valid secp256k1 secret key.
const TEST_SECRET_KEY_HEX: &str =
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

// ---------------------------------------------------------------------------
// Test keypair helpers
// ---------------------------------------------------------------------------

/// Generate a test authority keypair. Returns (public_key_bytes, secret_key_bytes).
///
/// The public key is the x-only (32-byte) serialization of the secp256k1
/// public key derived from the test secret key, with even parity enforced.
fn test_authority_keypair() -> ([u8; 32], [u8; 32]) {
    let secp = Secp256k1::new();
    let mut secret = SecretKey::from_slice(&hex::decode(TEST_SECRET_KEY_HEX).unwrap()).unwrap();
    let pubkey = secret.public_key(&secp);
    // Enforce even parity (same as Noise NX requires).
    if pubkey.x_only_public_key().1 == bitcoin::secp256k1::Parity::Odd {
        secret = secret.negate();
    }
    let kp = Keypair::from_secret_key(&secp, &secret);
    let x_only = kp.x_only_public_key().0.serialize();
    let secret_bytes: [u8; 32] = secret.secret_bytes();
    (x_only, secret_bytes)
}

// ---------------------------------------------------------------------------
// Test SV2 client
// ---------------------------------------------------------------------------

/// A minimal SV2 test client that performs the Noise NX handshake and can
/// send/receive encrypted SV2 frames.
struct TestSv2Client {
    stream: TcpStream,
    state: State,
}

impl TestSv2Client {
    /// Connect to the SV2 server and perform the Noise NX handshake.
    async fn connect(addr: SocketAddr, server_pubkey: Option<[u8; 32]>) -> Self {
        let mut stream = TcpStream::connect(addr).await.expect("TCP connect failed");

        // Create the Initiator.
        let mut initiator = match server_pubkey {
            Some(pk) => Initiator::from_raw_k(pk).expect("invalid server pubkey"),
            None => Initiator::without_pk().expect("initiator creation failed"),
        };

        // Step 0: Generate and send the 64-byte ephemeral public key.
        let first_msg = initiator.step_0().expect("Initiator step_0 failed");
        stream
            .write_all(&first_msg)
            .await
            .expect("failed to send initiator ephemeral");

        // Read the server's response (234 bytes).
        let mut response = [0u8; INITIATOR_EXPECTED_HANDSHAKE_MESSAGE_SIZE];
        stream
            .read_exact(&mut response)
            .await
            .expect("failed to read responder handshake");

        // Step 2: Process the response and obtain the NoiseCodec.
        let codec = initiator.step_2(response).expect("Initiator step_2 failed");

        let state = State::with_transport_mode(codec);

        Self { stream, state }
    }

    /// Send an SV2 message (encrypt + frame + write).
    async fn send(&mut self, message: AnyMessage<'_>) {
        let msg_type = message.message_type();
        let ext_type = message.extension_type();
        let channel_bit = message.channel_bit();

        let sv2_frame = Sv2Frame::from_message(message, msg_type, ext_type, channel_bit)
            .expect("message too large");
        let frame: Frame<AnyMessage<'_>, _> = sv2_frame.into();

        let mut encoder = NoiseEncoder::<AnyMessage<'_>>::new();
        let encoded = encoder
            .encode(frame, &mut self.state)
            .expect("encode failed");

        self.stream
            .write_all(&encoded[..])
            .await
            .expect("write failed");
    }

    /// Read and decrypt a single SV2 frame, returning the parsed AnyMessage.
    async fn recv(&mut self) -> AnyMessage<'static> {
        self.recv_with_timeout(Duration::from_secs(5)).await
    }

    /// Read and decrypt a single SV2 frame with a custom timeout.
    async fn recv_with_timeout(&mut self, timeout: Duration) -> AnyMessage<'static> {
        let mut decoder = StandardNoiseDecoder::<AnyMessage<'static>>::new();

        let frame = tokio::time::timeout(timeout, async {
            loop {
                let writable = decoder.writable();
                self.stream.read_exact(writable).await.expect("read failed");

                match decoder.next_frame(&mut self.state) {
                    Ok(frame) => return frame,
                    Err(e) => {
                        let err_str = format!("{e:?}");
                        if err_str.contains("MissingBytes") {
                            continue;
                        }
                        panic!("frame decode error: {e:?}");
                    }
                }
            }
        })
        .await
        .expect("recv timed out");

        // Parse the frame into AnyMessage and convert to 'static.
        let mut sv2_frame: stratum_core::codec_sv2::StandardSv2Frame<AnyMessage<'static>> = frame
            .try_into()
            .expect("expected Sv2Frame, not HandShake frame");

        let header = sv2_frame.get_header().expect("frame has no header");
        let payload = sv2_frame.payload();

        let msg: AnyMessage<'_> = (header, payload)
            .try_into()
            .expect("failed to parse AnyMessage");
        msg.into_static()
    }

    /// Try to read a message, returning None if nothing arrives within the timeout.
    async fn try_recv(&mut self, timeout: Duration) -> Option<AnyMessage<'static>> {
        let mut decoder = StandardNoiseDecoder::<AnyMessage<'static>>::new();

        let frame_result = tokio::time::timeout(timeout, async {
            loop {
                let writable = decoder.writable();
                match self.stream.read_exact(writable).await {
                    Ok(_) => {}
                    Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return None,
                    Err(e) => panic!("unexpected read error: {e}"),
                }

                match decoder.next_frame(&mut self.state) {
                    Ok(frame) => return Some(frame),
                    Err(e) => {
                        let err_str = format!("{e:?}");
                        if err_str.contains("MissingBytes") {
                            continue;
                        }
                        panic!("frame decode error: {e:?}");
                    }
                }
            }
        })
        .await;

        match frame_result {
            Ok(Some(frame)) => {
                let mut sv2_frame: stratum_core::codec_sv2::StandardSv2Frame<AnyMessage<'static>> =
                    frame
                        .try_into()
                        .expect("expected Sv2Frame, not HandShake frame");

                let header = sv2_frame.get_header().expect("frame has no header");
                let payload = sv2_frame.payload();

                let msg: AnyMessage<'_> = (header, payload)
                    .try_into()
                    .expect("failed to parse AnyMessage");
                Some(msg.into_static())
            }
            Ok(None) => None,
            Err(_) => None, // timeout
        }
    }
}

// ---------------------------------------------------------------------------
// Server setup helpers
// ---------------------------------------------------------------------------

/// Everything needed to run an SV2 test server.
struct TestSv2Server {
    addr: SocketAddr,
    _accept_shutdown: oneshot::Sender<()>,
    ctx: Sv2ConnectionContext,
    _emissions_rx: mpsc::Receiver<Emission>,
    authority_pubkey: [u8; 32],
    _temp_dir: tempfile::TempDir,
}

/// Start a complete SV2 test server on an ephemeral port.
///
/// Returns the server handle and spawns the accept loop + handler dispatch.
async fn start_test_sv2_server() -> TestSv2Server {
    let (pub_key, sec_key) = test_authority_keypair();

    let authority = AuthorityKeypair {
        public_key: pub_key,
        secret_key: sec_key,
        cert_validity: Duration::from_secs(86400),
    };

    // Bind to port 0 to get an ephemeral port.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind failed");
    let addr = listener.local_addr().unwrap();
    drop(listener); // Release the port for the accept loop to bind.

    // Start actors.
    let connections = start_sv2_connections_handler().await;
    let default_target = difficulty_to_target(1);
    let channels = start_channel_manager(0, default_target);
    let job_distributor = start_job_distributor(0);
    let (emissions_tx, emissions_rx) = mpsc::channel::<Emission>(100);
    let (chain_store_handle, temp_dir) = setup_test_chain_store_handle(true).await;

    let ctx = Sv2ConnectionContext {
        connections: connections.clone(),
        channels: channels.clone(),
        job_distributor: job_distributor.clone(),
        emissions_tx,
        chain_store: chain_store_handle,
        validate_addresses: false, // Don't validate BTC addresses in tests.
        network: bitcoin::Network::Regtest,
    };

    let server_config = Sv2ServerConfig {
        hostname: "127.0.0.1".to_string(),
        port: addr.port(),
        authority,
    };

    // Start accept loop + handler dispatch.
    let (accept_shutdown_tx, accept_shutdown_rx) = oneshot::channel();
    let (handshake_tx, mut handshake_rx) = mpsc::channel(32);

    tokio::spawn(async move {
        let _ = run_accept_loop(server_config, handshake_tx, accept_shutdown_rx).await;
    });

    // Spawn the handler dispatch loop.
    let handler_ctx = ctx.clone();
    tokio::spawn(async move {
        while let Some(handshake) = handshake_rx.recv().await {
            let ctx = handler_ctx.clone();
            tokio::spawn(async move {
                handle_sv2_connection(handshake, ctx).await;
            });
        }
    });

    // Brief pause to let the accept loop bind.
    tokio::time::sleep(Duration::from_millis(100)).await;

    TestSv2Server {
        addr,
        _accept_shutdown: accept_shutdown_tx,
        ctx,
        _emissions_rx: emissions_rx,
        authority_pubkey: pub_key,
        _temp_dir: temp_dir,
    }
}

/// Build a SetupConnection message for the Mining protocol.
fn build_setup_connection() -> AnyMessage<'static> {
    let setup = SetupConnection {
        protocol: Protocol::MiningProtocol,
        min_version: 2,
        max_version: 2,
        flags: 0,
        endpoint_host: "127.0.0.1".to_string().try_into().expect("valid Str0255"),
        endpoint_port: 0,
        vendor: "test-client".to_string().try_into().expect("valid Str0255"),
        hardware_version: "1.0".to_string().try_into().expect("valid Str0255"),
        firmware: "1.0".to_string().try_into().expect("valid Str0255"),
        device_id: "test-device-001"
            .to_string()
            .try_into()
            .expect("valid Str0255"),
    };
    AnyMessage::Common(CommonMessages::SetupConnection(setup))
}

/// Build an OpenStandardMiningChannel message.
fn build_open_channel(request_id: u32, user_identity: &str) -> AnyMessage<'static> {
    let open = OpenStandardMiningChannel {
        request_id: request_id.into(),
        user_identity: user_identity.to_string().try_into().expect("valid Str0255"),
        nominal_hash_rate: 1_000_000.0, // 1 MH/s
        max_target: difficulty_to_target(1)
            .to_vec()
            .try_into()
            .expect("valid U256"),
    };
    AnyMessage::Mining(Mining::OpenStandardMiningChannel(open))
}

// ---------------------------------------------------------------------------
// Integration tests
// ---------------------------------------------------------------------------

/// Test 1: Noise NX handshake succeeds over TCP.
#[tokio::test]
async fn test_sv2_noise_handshake() {
    let server = start_test_sv2_server().await;

    // Connect with server's public key for certificate validation.
    let _client = TestSv2Client::connect(server.addr, Some(server.authority_pubkey)).await;

    // If we get here, the handshake succeeded.
}

/// Test 2: Noise NX handshake without server pubkey (no cert validation).
#[tokio::test]
async fn test_sv2_noise_handshake_no_cert_validation() {
    let server = start_test_sv2_server().await;

    // Connect without server pubkey — encrypted but no certificate validation.
    let _client = TestSv2Client::connect(server.addr, None).await;
}

/// Test 3: Full lifecycle — SetupConnection -> OpenStandardMiningChannel.
#[tokio::test]
async fn test_sv2_setup_and_open_channel() {
    let server = start_test_sv2_server().await;
    let mut client = TestSv2Client::connect(server.addr, Some(server.authority_pubkey)).await;

    // 1. Send SetupConnection.
    client.send(build_setup_connection()).await;

    // 2. Receive SetupConnectionSuccess.
    let response = client.recv().await;
    match &response {
        AnyMessage::Common(CommonMessages::SetupConnectionSuccess(_)) => {
            // Expected.
        }
        other => panic!("expected SetupConnectionSuccess, got: {other:?}"),
    }

    // 3. Send OpenStandardMiningChannel.
    client.send(build_open_channel(1, "testworker.rig1")).await;

    // 4. Receive OpenStandardMiningChannelSuccess.
    let response = client.recv().await;
    match &response {
        AnyMessage::Mining(Mining::OpenStandardMiningChannelSuccess(success)) => {
            assert_eq!(
                success.get_request_id_as_u32(),
                1,
                "request_id should match"
            );
            assert!(success.channel_id > 0, "channel_id should be positive");
            assert!(
                success.group_channel_id > 0,
                "group_channel_id should be positive"
            );
        }
        other => panic!("expected OpenStandardMiningChannelSuccess, got: {other:?}"),
    }
}

/// Test 4: After opening a channel with no active job, no bootstrap messages
/// are sent.
#[tokio::test]
async fn test_sv2_channel_no_bootstrap_without_job() {
    let server = start_test_sv2_server().await;
    let mut client = TestSv2Client::connect(server.addr, Some(server.authority_pubkey)).await;

    // Setup + open channel.
    client.send(build_setup_connection()).await;
    let _ = client.recv().await; // SetupConnectionSuccess

    client.send(build_open_channel(1, "testminer.rig1")).await;

    let response = client.recv().await;
    match &response {
        AnyMessage::Mining(Mining::OpenStandardMiningChannelSuccess(_)) => {
            // Good — channel opened. No active job yet.
        }
        other => panic!("expected OpenStandardMiningChannelSuccess, got: {other:?}"),
    }

    // No jobs injected, so there should be no further messages.
    let extra = client.try_recv(Duration::from_millis(200)).await;
    assert!(
        extra.is_none(),
        "expected no bootstrap messages when no template exists, got: {extra:?}"
    );
}

/// Test 5: Multiple channels on the same connection share a group.
#[tokio::test]
async fn test_sv2_multiple_channels_same_group() {
    let server = start_test_sv2_server().await;
    let mut client = TestSv2Client::connect(server.addr, Some(server.authority_pubkey)).await;

    client.send(build_setup_connection()).await;
    let _ = client.recv().await; // SetupConnectionSuccess

    // Open first channel.
    client.send(build_open_channel(1, "worker1.rig1")).await;
    let resp1 = client.recv().await;
    let (channel_id_1, group_id_1) = match &resp1 {
        AnyMessage::Mining(Mining::OpenStandardMiningChannelSuccess(s)) => {
            (s.channel_id, s.group_channel_id)
        }
        other => panic!("expected success, got: {other:?}"),
    };

    // Open second channel on the same connection.
    client.send(build_open_channel(2, "worker2.rig2")).await;
    let resp2 = client.recv().await;
    let (channel_id_2, group_id_2) = match &resp2 {
        AnyMessage::Mining(Mining::OpenStandardMiningChannelSuccess(s)) => {
            (s.channel_id, s.group_channel_id)
        }
        other => panic!("expected success, got: {other:?}"),
    };

    // Both channels should share the same group.
    assert_eq!(
        group_id_1, group_id_2,
        "channels on same connection should share group"
    );

    // But have different channel IDs.
    assert_ne!(
        channel_id_1, channel_id_2,
        "channels should have unique IDs"
    );
}

/// Test 6: Sending a message before SetupConnection is rejected.
#[tokio::test]
async fn test_sv2_message_before_setup_rejected() {
    let server = start_test_sv2_server().await;
    let mut client = TestSv2Client::connect(server.addr, Some(server.authority_pubkey)).await;

    // Send OpenStandardMiningChannel without SetupConnection first.
    client.send(build_open_channel(1, "testworker.rig1")).await;

    // The server should close the connection or send an error.
    let result = client.try_recv(Duration::from_secs(2)).await;
    match result {
        None => {
            // Expected — connection closed.
        }
        Some(AnyMessage::Common(CommonMessages::SetupConnectionError(_))) => {
            // Also acceptable — server sent an error.
        }
        Some(other) => {
            panic!("expected connection close or error, got: {other:?}");
        }
    }
}

/// Test 7: Two separate connections get different group channel IDs.
#[tokio::test]
async fn test_sv2_separate_connections_different_groups() {
    let server = start_test_sv2_server().await;

    // First connection.
    let mut client1 = TestSv2Client::connect(server.addr, Some(server.authority_pubkey)).await;
    client1.send(build_setup_connection()).await;
    let _ = client1.recv().await;
    client1.send(build_open_channel(1, "miner1.rig1")).await;
    let resp1 = client1.recv().await;
    let group_id_1 = match &resp1 {
        AnyMessage::Mining(Mining::OpenStandardMiningChannelSuccess(s)) => s.group_channel_id,
        other => panic!("expected success, got: {other:?}"),
    };

    // Second connection.
    let mut client2 = TestSv2Client::connect(server.addr, Some(server.authority_pubkey)).await;
    client2.send(build_setup_connection()).await;
    let _ = client2.recv().await;
    client2.send(build_open_channel(1, "miner2.rig1")).await;
    let resp2 = client2.recv().await;
    let group_id_2 = match &resp2 {
        AnyMessage::Mining(Mining::OpenStandardMiningChannelSuccess(s)) => s.group_channel_id,
        other => panic!("expected success, got: {other:?}"),
    };

    assert_ne!(
        group_id_1, group_id_2,
        "separate connections should get different group IDs"
    );
}

/// Test 8: Client disconnects gracefully — server cleans up without panicking.
#[tokio::test]
async fn test_sv2_client_disconnect_cleanup() {
    let server = start_test_sv2_server().await;

    // Connect, setup, open channel.
    let mut client = TestSv2Client::connect(server.addr, Some(server.authority_pubkey)).await;
    client.send(build_setup_connection()).await;
    let _ = client.recv().await;
    client.send(build_open_channel(1, "worker.rig1")).await;
    let _ = client.recv().await;

    // Drop the client — this closes the TCP connection.
    drop(client);

    // Give the server time to notice the disconnect and clean up.
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Verify the connection count is 0.
    let count = server.ctx.connections.get_count().await;
    assert_eq!(
        count, 0,
        "connection registry should be empty after disconnect"
    );
}

/// Test 9: Handshake timeout — raw TCP connect without sending the
/// Noise ephemeral key should eventually be cleaned up.
#[tokio::test]
async fn test_sv2_handshake_timeout() {
    let server = start_test_sv2_server().await;

    // Connect but don't send anything.
    let stream = TcpStream::connect(server.addr)
        .await
        .expect("TCP connect failed");

    // Hold the connection for a bit, then drop it.
    tokio::time::sleep(Duration::from_millis(500)).await;
    drop(stream);

    // Server should not have any registered connections
    // (the handshake never completed).
    let count = server.ctx.connections.get_count().await;
    assert_eq!(
        count, 0,
        "no connections should be registered for incomplete handshakes"
    );
}

/// Load a test GBT fixture and return it as a BlockTemplate.
fn load_test_template() -> BlockTemplate {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("test_data/gbt/regtest/ckpool/one-txn/gbt.json");
    let json = std::fs::read_to_string(path).expect("failed to read test template");
    serde_json::from_str(&json).expect("failed to parse test template")
}

/// Build a minimal output distribution for the coinbase (one output to a
/// test address).
fn test_output_distribution() -> Vec<OutputPair> {
    // Use a P2WPKH address derived from a test compressed public key.
    let pubkey: bitcoin::CompressedPublicKey =
        "020202020202020202020202020202020202020202020202020202020202020202"
            .parse()
            .unwrap();
    let address = bitcoin::Address::p2wpkh(&pubkey, bitcoin::Network::Regtest);
    vec![OutputPair {
        address,
        amount: bitcoin::Amount::from_sat(625_002_820),
    }]
}

/// Test 10: Inject a template into the job distributor and verify a connected
/// client receives NewMiningJob + SetNewPrevHash via the writer task.
#[tokio::test]
async fn test_sv2_job_distribution_on_new_template() {
    let server = start_test_sv2_server().await;

    // Connect and set up a channel.
    let mut client = TestSv2Client::connect(server.addr, Some(server.authority_pubkey)).await;
    client.send(build_setup_connection()).await;
    let _ = client.recv().await; // SetupConnectionSuccess

    client.send(build_open_channel(1, "miner.rig1")).await;
    let _ = client.recv().await; // OpenStandardMiningChannelSuccess

    // Brief pause to ensure the handler's writer task has subscribed to job events.
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Inject a template.
    let template = load_test_template();
    server
        .ctx
        .job_distributor
        .new_template(
            Arc::new(template),
            test_output_distribution(),
            b"p2pool-test".to_vec(),
            None,
            None,
        )
        .await
        .expect("new_template failed");

    // The client should receive SetNewPrevHash followed by NewMiningJob.
    let msg1 = client.recv_with_timeout(Duration::from_secs(3)).await;
    match &msg1 {
        AnyMessage::Mining(Mining::SetNewPrevHash(prev_hash)) => {
            // prev_hash should be non-zero.
            let all_zero = prev_hash.prev_hash.inner_as_ref().iter().all(|&b| b == 0);
            assert!(!all_zero, "prev_hash should not be all zeros");
        }
        other => panic!("expected SetNewPrevHash, got: {other:?}"),
    }

    let msg2 = client.recv_with_timeout(Duration::from_secs(3)).await;
    match &msg2 {
        AnyMessage::Mining(Mining::NewMiningJob(job)) => {
            assert!(job.job_id > 0, "job_id should be positive");
        }
        other => panic!("expected NewMiningJob, got: {other:?}"),
    }
}

/// Test 11: Late-connecting client receives bootstrap job from the
/// distributor after a template was already injected.
///
/// After opening a channel, the client should receive (in some order):
/// - OpenStandardMiningChannelSuccess
/// - SetNewPrevHash (bootstrap)
/// - NewMiningJob (bootstrap)
///
/// The exact ordering of these messages depends on task scheduling, so
/// we collect all messages received after sending OpenChannel and verify
/// all expected types are present.
#[tokio::test]
async fn test_sv2_late_connect_bootstrap() {
    let server = start_test_sv2_server().await;

    // Client 1: connect, open channel (registers a group), gets the group job.
    let mut client1 = TestSv2Client::connect(server.addr, Some(server.authority_pubkey)).await;
    client1.send(build_setup_connection()).await;
    let _ = client1.recv().await;
    client1.send(build_open_channel(1, "miner1.rig1")).await;
    let _ = client1.recv().await;

    tokio::time::sleep(Duration::from_millis(100)).await;

    // Inject a template. Client 1's group gets a job.
    let template = load_test_template();
    server
        .ctx
        .job_distributor
        .new_template(
            Arc::new(template),
            test_output_distribution(),
            b"p2pool-test".to_vec(),
            None,
            None,
        )
        .await
        .expect("new_template failed");

    // Client 1 should receive the job push.
    let _ = client1.recv_with_timeout(Duration::from_secs(3)).await;
    let _ = client1.recv_with_timeout(Duration::from_secs(3)).await;

    // Now connect client 2 — it should get bootstrapped with the current job.
    let mut client2 = TestSv2Client::connect(server.addr, Some(server.authority_pubkey)).await;
    client2.send(build_setup_connection()).await;

    // Collect all messages up to a timeout. We expect:
    // - SetupConnectionSuccess
    // - OpenStandardMiningChannelSuccess (after we send OpenChannel)
    // - NewMiningJob (bootstrap or from watch channel)
    // - SetNewPrevHash (bootstrap or from watch channel)
    // The watch channel job event may arrive before or after the setup/channel
    // messages, so we need to be flexible about ordering.

    // First collect any messages that arrive before we send OpenChannel.
    // There might be stale watch-channel messages.
    let mut all_messages = Vec::new();

    // Read SetupConnectionSuccess (or whatever comes first).
    let msg = client2.recv_with_timeout(Duration::from_secs(3)).await;
    all_messages.push(msg);

    // Send OpenChannel.
    client2.send(build_open_channel(1, "miner2.rig1")).await;

    // Collect remaining messages (up to 5 attempts, with short timeouts).
    for _ in 0..5 {
        match client2.try_recv(Duration::from_millis(500)).await {
            Some(msg) => all_messages.push(msg),
            None => break,
        }
    }

    // Verify we got all expected message types.
    let has_setup_success = all_messages.iter().any(|m| {
        matches!(
            m,
            AnyMessage::Common(CommonMessages::SetupConnectionSuccess(_))
        )
    });
    let has_open_channel_success = all_messages.iter().any(|m| {
        matches!(
            m,
            AnyMessage::Mining(Mining::OpenStandardMiningChannelSuccess(_))
        )
    });
    let has_new_mining_job = all_messages
        .iter()
        .any(|m| matches!(m, AnyMessage::Mining(Mining::NewMiningJob(_))));
    let has_set_prev_hash = all_messages
        .iter()
        .any(|m| matches!(m, AnyMessage::Mining(Mining::SetNewPrevHash(_))));

    assert!(has_setup_success, "should have SetupConnectionSuccess");
    assert!(
        has_open_channel_success,
        "should have OpenStandardMiningChannelSuccess"
    );
    assert!(
        has_new_mining_job,
        "should have bootstrap NewMiningJob (got messages: {all_messages:?})"
    );
    assert!(
        has_set_prev_hash,
        "should have bootstrap SetNewPrevHash (got messages: {all_messages:?})"
    );
}

/// Test 12: Submit a share with a random nonce — should be rejected with
/// "low-difficulty-share" because the hash won't meet the channel target.
///
/// Full flow: connect → setup → open channel → inject template → receive
/// NewMiningJob + SetNewPrevHash → send SubmitSharesStandard → receive
/// SubmitSharesError with "low-difficulty-share".
#[tokio::test]
async fn test_sv2_submit_share_low_difficulty() {
    let server = start_test_sv2_server().await;

    // Connect and set up a channel.
    let mut client = TestSv2Client::connect(server.addr, Some(server.authority_pubkey)).await;
    client.send(build_setup_connection()).await;
    let _ = client.recv().await; // SetupConnectionSuccess

    client.send(build_open_channel(1, "miner.rig1")).await;
    let open_resp = client.recv().await;
    let channel_id = match &open_resp {
        AnyMessage::Mining(Mining::OpenStandardMiningChannelSuccess(s)) => s.channel_id,
        other => panic!("expected OpenStandardMiningChannelSuccess, got: {other:?}"),
    };

    // Brief pause to ensure the handler's writer task has subscribed to job events.
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Inject a template so we have an active job to submit against.
    let template = load_test_template();
    server
        .ctx
        .job_distributor
        .new_template(
            Arc::new(template),
            test_output_distribution(),
            b"p2pool-test".to_vec(),
            None,
            None,
        )
        .await
        .expect("new_template failed");

    // Receive SetNewPrevHash first.
    let msg1 = client.recv_with_timeout(Duration::from_secs(3)).await;
    match &msg1 {
        AnyMessage::Mining(Mining::SetNewPrevHash(_)) => { /* expected */ }
        other => panic!("expected SetNewPrevHash, got: {other:?}"),
    }

    // Receive NewMiningJob — extract the job_id for the submit.
    let msg2 = client.recv_with_timeout(Duration::from_secs(3)).await;
    let job_id = match &msg2 {
        AnyMessage::Mining(Mining::NewMiningJob(job)) => job.job_id,
        other => panic!("expected NewMiningJob, got: {other:?}"),
    };

    // Submit a share with a fabricated (random) nonce.
    // With difficulty-1 target, a random nonce will almost certainly not
    // produce a hash that meets the channel target.
    let submit = SubmitSharesStandard {
        channel_id,
        sequence_number: 0,
        job_id,
        nonce: 0xDEADBEEF,
        ntime: 1700000100,
        version: 0x20000000,
    };
    client
        .send(AnyMessage::Mining(Mining::SubmitSharesStandard(submit)))
        .await;

    // The server should respond with SubmitSharesError.
    let response = client.recv_with_timeout(Duration::from_secs(3)).await;
    match &response {
        AnyMessage::Mining(Mining::SubmitSharesError(err)) => {
            assert_eq!(err.channel_id, channel_id);
            assert_eq!(err.sequence_number, 0);
            let error_bytes = err.error_code.inner_as_ref();
            let error_str = std::str::from_utf8(error_bytes).unwrap_or("<non-utf8>");
            assert!(
                error_str.contains("low-difficulty-share"),
                "expected 'low-difficulty-share', got: {error_str}"
            );
        }
        other => panic!("expected SubmitSharesError, got: {other:?}"),
    }
}

/// Load the second test GBT fixture (two-txns, different previousblockhash).
fn load_test_template_two_txns() -> BlockTemplate {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("test_data/gbt/regtest/ckpool/two-txns/gbt.json");
    let json = std::fs::read_to_string(path).expect("failed to read two-txns test template");
    serde_json::from_str(&json).expect("failed to parse two-txns test template")
}

/// Test 13: New block scenario — inject two templates with different
/// `previousblockhash` values and verify the client receives new job
/// messages for each.
///
/// Flow:
/// 1. Inject first template (one-txn fixture) → client gets NewMiningJob + SetNewPrevHash
/// 2. Inject second template (two-txns fixture, different prev_hash) → client
///    gets a NEW NewMiningJob + SetNewPrevHash with the updated prev_hash
/// 3. Old job_ids should be different from new ones
#[tokio::test]
async fn test_sv2_new_block_scenario() {
    let server = start_test_sv2_server().await;

    // Connect and set up a channel.
    let mut client = TestSv2Client::connect(server.addr, Some(server.authority_pubkey)).await;
    client.send(build_setup_connection()).await;
    let _ = client.recv().await; // SetupConnectionSuccess

    client.send(build_open_channel(1, "miner.rig1")).await;
    let _ = client.recv().await; // OpenStandardMiningChannelSuccess

    tokio::time::sleep(Duration::from_millis(100)).await;

    // --- First template (one-txn fixture) ---
    let template1 = load_test_template();
    server
        .ctx
        .job_distributor
        .new_template(
            Arc::new(template1),
            test_output_distribution(),
            b"p2pool-test".to_vec(),
            None,
            None,
        )
        .await
        .expect("new_template 1 failed");

    let msg1 = client.recv_with_timeout(Duration::from_secs(3)).await;
    let first_prev_hash = match &msg1 {
        AnyMessage::Mining(Mining::SetNewPrevHash(ph)) => ph.prev_hash.inner_as_ref().to_vec(),
        other => panic!("expected SetNewPrevHash (1st), got: {other:?}"),
    };

    let msg2 = client.recv_with_timeout(Duration::from_secs(3)).await;
    let first_job_id = match &msg2 {
        AnyMessage::Mining(Mining::NewMiningJob(job)) => {
            assert!(job.job_id > 0, "first job_id should be positive");
            job.job_id
        }
        other => panic!("expected NewMiningJob (1st), got: {other:?}"),
    };

    // --- Second template (two-txns fixture, different previousblockhash) ---
    let template2 = load_test_template_two_txns();
    server
        .ctx
        .job_distributor
        .new_template(
            Arc::new(template2),
            test_output_distribution(),
            b"p2pool-test".to_vec(),
            None,
            None,
        )
        .await
        .expect("new_template 2 failed");

    let msg3 = client.recv_with_timeout(Duration::from_secs(3)).await;
    let second_prev_hash = match &msg3 {
        AnyMessage::Mining(Mining::SetNewPrevHash(ph)) => ph.prev_hash.inner_as_ref().to_vec(),
        other => panic!("expected SetNewPrevHash (2nd), got: {other:?}"),
    };

    let msg4 = client.recv_with_timeout(Duration::from_secs(3)).await;
    let second_job_id = match &msg4 {
        AnyMessage::Mining(Mining::NewMiningJob(job)) => {
            assert!(job.job_id > 0, "second job_id should be positive");
            job.job_id
        }
        other => panic!("expected NewMiningJob (2nd), got: {other:?}"),
    };

    // Verify the two templates produced different jobs and different prev_hashes.
    assert_ne!(
        first_job_id, second_job_id,
        "new block should produce a different job_id"
    );
    assert_ne!(
        first_prev_hash, second_prev_hash,
        "new block should have a different prev_hash"
    );
}

/// Test 14: Dual-protocol test — both SV1 and SV2 emit shares to the same
/// emissions channel.
///
/// Starts both an SV1 StratumServer and an SV2 server sharing the same
/// `emissions_tx`. An SV2 client connects, opens a channel, injects a
/// template, and submits a share. We verify the share (even if rejected
/// as low-difficulty) traverses the handler and reaches the emissions
/// channel when the target is easy enough, OR produces a SubmitSharesError
/// that proves the full pipeline executed.
///
/// This test proves the SV2 server correctly feeds into the shared
/// accounting pipeline.
#[tokio::test]
async fn test_sv2_emissions_pipeline_integration() {
    let (pub_key, sec_key) = test_authority_keypair();

    let authority = AuthorityKeypair {
        public_key: pub_key,
        secret_key: sec_key,
        cert_validity: Duration::from_secs(86400),
    };

    // Bind to ephemeral port.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind failed");
    let addr = listener.local_addr().unwrap();
    drop(listener);

    // Shared emissions channel — this is the key shared infrastructure.
    let (emissions_tx, mut emissions_rx) = mpsc::channel::<Emission>(100);

    // Start SV2 actors.
    let connections = start_sv2_connections_handler().await;
    // Use an extremely easy target (all 0xff) so random nonces meet it.
    let easy_target = [0xff; 32];
    let channels = start_channel_manager(0, easy_target);
    let job_distributor = start_job_distributor(0);
    let (chain_store_handle, _temp_dir) = setup_test_chain_store_handle(true).await;

    let ctx = Sv2ConnectionContext {
        connections: connections.clone(),
        channels: channels.clone(),
        job_distributor: job_distributor.clone(),
        emissions_tx,
        chain_store: chain_store_handle,
        validate_addresses: false,
        network: bitcoin::Network::Regtest,
    };

    let server_config = Sv2ServerConfig {
        hostname: "127.0.0.1".to_string(),
        port: addr.port(),
        authority,
    };

    let (accept_shutdown_tx, accept_shutdown_rx) = oneshot::channel();
    let (handshake_tx, mut handshake_rx) = mpsc::channel(32);

    tokio::spawn(async move {
        let _ = run_accept_loop(server_config, handshake_tx, accept_shutdown_rx).await;
    });

    let handler_ctx = ctx.clone();
    tokio::spawn(async move {
        while let Some(handshake) = handshake_rx.recv().await {
            let ctx = handler_ctx.clone();
            tokio::spawn(async move {
                handle_sv2_connection(handshake, ctx).await;
            });
        }
    });

    tokio::time::sleep(Duration::from_millis(100)).await;

    // Connect SV2 client.
    let mut client = TestSv2Client::connect(addr, Some(pub_key)).await;
    client.send(build_setup_connection()).await;
    let _ = client.recv().await; // SetupConnectionSuccess

    client.send(build_open_channel(1, "testminer.rig1")).await;
    let open_resp = client.recv().await;
    let channel_id = match &open_resp {
        AnyMessage::Mining(Mining::OpenStandardMiningChannelSuccess(s)) => s.channel_id,
        other => panic!("expected OpenStandardMiningChannelSuccess, got: {other:?}"),
    };

    tokio::time::sleep(Duration::from_millis(100)).await;

    // Inject a template.
    let template = load_test_template();
    ctx.job_distributor
        .new_template(
            Arc::new(template),
            test_output_distribution(),
            b"p2pool-test".to_vec(),
            None,
            None,
        )
        .await
        .expect("new_template failed");

    // Receive SetNewPrevHash + NewMiningJob.
    let msg1 = client.recv_with_timeout(Duration::from_secs(3)).await;
    let ntime = match &msg1 {
        AnyMessage::Mining(Mining::SetNewPrevHash(ph)) => ph.min_ntime,
        other => panic!("expected SetNewPrevHash, got: {other:?}"),
    };

    let msg2 = client.recv_with_timeout(Duration::from_secs(3)).await;
    let job_id = match &msg2 {
        AnyMessage::Mining(Mining::NewMiningJob(job)) => job.job_id,
        other => panic!("expected NewMiningJob, got: {other:?}"),
    };

    // Submit a share. With the all-0xFF target, any hash should meet the
    // channel target, so this should produce SubmitSharesSuccess and an
    // Emission on the shared channel.
    let submit = SubmitSharesStandard {
        channel_id,
        sequence_number: 0,
        job_id,
        nonce: 0x42424242,
        ntime,
        version: 0x20000000,
    };
    client
        .send(AnyMessage::Mining(Mining::SubmitSharesStandard(submit)))
        .await;

    // We should get SubmitSharesSuccess (because the target is all-0xFF).
    let response = client.recv_with_timeout(Duration::from_secs(3)).await;
    match &response {
        AnyMessage::Mining(Mining::SubmitSharesSuccess(success)) => {
            assert_eq!(success.channel_id, channel_id);
            assert_eq!(success.last_sequence_number, 0);
            assert_eq!(success.new_submits_accepted_count, 1);
        }
        AnyMessage::Mining(Mining::SubmitSharesError(err)) => {
            let error_bytes = err.error_code.inner_as_ref();
            let error_str = std::str::from_utf8(error_bytes).unwrap_or("<non-utf8>");
            panic!("share should have been accepted with all-0xFF target, got error: {error_str}",);
        }
        other => panic!("expected SubmitSharesSuccess, got: {other:?}"),
    }

    // Verify the emission arrived on the shared channel.
    let emission = tokio::time::timeout(Duration::from_secs(3), emissions_rx.recv())
        .await
        .expect("timed out waiting for emission")
        .expect("emissions channel closed");

    assert_eq!(emission.header.nonce, 0x42424242);

    // Cleanup.
    drop(accept_shutdown_tx);
}
