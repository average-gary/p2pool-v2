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

//! Per-connection SV2 message handler.
//!
//! After the Noise NX handshake completes, each SV2 connection is handled by
//! [`handle_sv2_connection`]. This function:
//!
//! 1. Registers the connection in the connection registry
//! 2. Splits the TCP stream and Noise codec state
//! 3. Runs a reader loop that decrypts inbound frames, dispatches messages
//!    (SetupConnection, OpenStandardMiningChannel, SubmitSharesStandard)
//! 4. Spawns a writer task that encrypts outbound frames (server pushes like
//!    NewMiningJob, SetNewPrevHash) and responses routed through the
//!    connection registry
//! 5. Cleans up channels and registry entries on disconnect

use std::sync::Arc;

use stratum_core::codec_sv2::{NoiseEncoder, StandardEitherFrame, StandardNoiseDecoder, State};
use stratum_core::framing_sv2::framing::{Frame, Sv2Frame};
use stratum_core::mining_sv2::{
    NewMiningJob, OpenStandardMiningChannel, SetNewPrevHash, SubmitSharesStandard,
};
use stratum_core::parsers_sv2::{AnyMessage, CommonMessages, IsSv2Message, Mining};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::sync::{mpsc, watch};
use tracing::{debug, info, warn};

/// Type alias for the SV2 frame type returned by the Noise decoder.
type Sv2DecodedFrame = StandardEitherFrame<AnyMessage<'static>>;

use crate::shares::chain::chain_store_handle::ChainStoreHandle;
use crate::stratum::emission::EmissionSender;

use super::channels::{Sv2ChannelHandle, build_open_channel_error, validate_and_register_user};
use super::connection::{DownstreamId, HandshakeResult};
use super::connections::Sv2ConnectionsHandle;
use super::error::Sv2Error;
use super::job_distributor::{JobEvent, Sv2JobDistributorHandle};
use super::setup::{
    build_setup_connection_error, build_setup_connection_success, validate_setup_connection,
};
use super::shares::{build_submit_error, build_submit_success, emit_share, validate_share};
// work module types used by job_distributor lookups

/// Timeout for the initial SetupConnection message (seconds).
const SETUP_CONNECTION_TIMEOUT_SECS: u64 = 30;

/// Inactivity timeout — close connection if no message for this long (seconds).
const INACTIVITY_TIMEOUT_SECS: u64 = 900;

/// Context shared by all per-connection handlers.
///
/// Carries handles to the shared actors and configuration.
#[derive(Clone)]
pub struct Sv2ConnectionContext {
    pub connections: Sv2ConnectionsHandle,
    pub channels: Sv2ChannelHandle,
    pub job_distributor: Sv2JobDistributorHandle,
    pub emissions_tx: EmissionSender,
    pub chain_store: ChainStoreHandle,
    pub validate_addresses: bool,
    pub network: bitcoin::Network,
}

/// Per-connection session state.
struct Sv2Session {
    downstream_id: DownstreamId,
    setup_complete: bool,
    /// Group channel ID (set after first OpenStandardMiningChannel).
    group_channel_id: Option<u32>,
    /// Tracks accepted shares for SubmitSharesSuccess responses.
    accepted_shares: u32,
    shares_sum: u64,
}

// ---------------------------------------------------------------------------
// Public entry point
// ---------------------------------------------------------------------------

/// Handle a fully-handshaked SV2 connection.
///
/// This is the main entry point spawned by the orchestrator for each new
/// connection after the Noise NX handshake completes. It runs until the
/// connection is closed or an unrecoverable error occurs.
pub async fn handle_sv2_connection(handshake: HandshakeResult, ctx: Sv2ConnectionContext) {
    let downstream_id = handshake.downstream_id;
    let addr = handshake.addr;

    info!(
        downstream_id,
        addr = %addr,
        "starting SV2 connection handler"
    );

    // Register in the connection registry.
    // msg_rx receives pre-encoded frames for server-push messages.
    // shutdown_rx signals us to exit.
    let (msg_rx, shutdown_rx) = ctx.connections.add(downstream_id, addr).await;

    // Split the TCP stream.
    let (read_half, write_half) = handshake.stream.into_split();

    // The Noise State must be split for concurrent read/write.
    // Since State contains a NoiseCodec with separate encryptor/decryptor,
    // we need to protect it. We use a single Mutex — the reader and writer
    // tasks coordinate through it. In practice, contention is low because
    // reads and writes alternate.
    let state = Arc::new(tokio::sync::Mutex::new(handshake.state));

    // Subscribe to job events for pushing NewMiningJob/SetNewPrevHash.
    let job_events = ctx.job_distributor.subscribe_job_events();

    let mut session = Sv2Session {
        downstream_id,
        setup_complete: false,
        group_channel_id: None,
        accepted_shares: 0,
        shares_sum: 0,
    };

    // Spawn the writer task.
    let writer_state = Arc::clone(&state);
    let _writer_connections = ctx.connections.clone();
    let writer_handle = tokio::spawn(writer_task(
        write_half,
        writer_state,
        msg_rx,
        shutdown_rx,
        job_events,
        downstream_id,
    ));

    // Run the reader loop.
    let result = reader_loop(read_half, &state, &mut session, &ctx).await;

    if let Err(e) = &result {
        match e {
            Sv2Error::ConnectionClosed => {
                info!(downstream_id, addr = %addr, "SV2 connection closed");
            }
            Sv2Error::Io(io_err) if io_err.kind() == std::io::ErrorKind::UnexpectedEof => {
                info!(downstream_id, addr = %addr, "SV2 connection EOF");
            }
            _ => {
                warn!(downstream_id, addr = %addr, "SV2 connection error: {e}");
            }
        }
    }

    // Cleanup: remove from registries.
    ctx.connections.remove(downstream_id).await;
    let _ = ctx.channels.remove_downstream(downstream_id).await;
    if let Some(group_id) = session.group_channel_id {
        let _ = ctx.job_distributor.unregister_group(group_id).await;
    }

    // The writer task will exit when shutdown_rx fires (triggered by
    // connections.remove) or when msg_rx is dropped.
    let _ = writer_handle.await;

    debug!(
        downstream_id,
        addr = %addr,
        "SV2 connection handler finished"
    );
}

// ---------------------------------------------------------------------------
// Reader loop
// ---------------------------------------------------------------------------

/// Main reader loop: decrypt inbound SV2 frames and dispatch messages.
async fn reader_loop(
    mut reader: OwnedReadHalf,
    state: &Arc<tokio::sync::Mutex<State>>,
    session: &mut Sv2Session,
    ctx: &Sv2ConnectionContext,
) -> Result<(), Sv2Error> {
    // Phase 1: Read SetupConnection.
    let setup_result = tokio::time::timeout(
        std::time::Duration::from_secs(SETUP_CONNECTION_TIMEOUT_SECS),
        read_and_dispatch_setup(&mut reader, state, session, ctx),
    )
    .await
    .map_err(|_| Sv2Error::InvalidMessage("SetupConnection timed out".to_string()))??;

    if !setup_result {
        // SetupConnection failed — error response already sent, close.
        return Err(Sv2Error::SetupConnectionFailed(
            "setup validation failed".to_string(),
        ));
    }

    // Phase 2: Main message loop.
    let mut last_activity = tokio::time::Instant::now();

    loop {
        let timeout_duration = std::time::Duration::from_secs(INACTIVITY_TIMEOUT_SECS);
        let remaining = timeout_duration
            .checked_sub(last_activity.elapsed())
            .unwrap_or_default();

        let frame_result =
            tokio::time::timeout(remaining, read_sv2_frame(&mut reader, state)).await;

        let frame: Sv2DecodedFrame = match frame_result {
            Ok(Ok(f)) => f,
            Ok(Err(e)) => return Err(e),
            Err(_) => {
                info!(
                    downstream_id = session.downstream_id,
                    "SV2 inactivity timeout ({}s)", INACTIVITY_TIMEOUT_SECS
                );
                return Err(Sv2Error::ConnectionClosed);
            }
        };

        last_activity = tokio::time::Instant::now();

        // Parse the frame header and payload.
        let mut sv2_frame: stratum_core::codec_sv2::StandardSv2Frame<AnyMessage<'static>> =
            frame.try_into().map_err(|_| {
                Sv2Error::InvalidMessage("expected Sv2Frame, got HandShake".to_string())
            })?;

        let header = sv2_frame
            .get_header()
            .ok_or_else(|| Sv2Error::InvalidMessage("frame has no header".to_string()))?;

        let payload = sv2_frame.payload();
        let msg_type = header.msg_type();
        let _ext_type = header.ext_type();

        // Parse into AnyMessage.
        let message: AnyMessage<'_> = (header, payload)
            .try_into()
            .map_err(|e| Sv2Error::InvalidMessage(format!("failed to parse message: {e:?}")))?;

        // Dispatch.
        match message {
            AnyMessage::Mining(Mining::OpenStandardMiningChannel(msg)) => {
                handle_open_standard_channel(msg.into_static(), session, ctx, state).await?;
            }
            AnyMessage::Mining(Mining::SubmitSharesStandard(msg)) => {
                handle_submit_shares_standard(msg, session, ctx, state).await?;
            }
            _ => {
                warn!(
                    downstream_id = session.downstream_id,
                    msg_type, "unexpected SV2 message type in main loop"
                );
            }
        }
    }
}

// ---------------------------------------------------------------------------
// SetupConnection handler
// ---------------------------------------------------------------------------

/// Read and handle the initial SetupConnection exchange.
/// Returns true if setup succeeded.
async fn read_and_dispatch_setup(
    reader: &mut OwnedReadHalf,
    state: &Arc<tokio::sync::Mutex<State>>,
    session: &mut Sv2Session,
    ctx: &Sv2ConnectionContext,
) -> Result<bool, Sv2Error> {
    let frame: Sv2DecodedFrame = read_sv2_frame(reader, state).await?;

    let mut sv2_frame: stratum_core::codec_sv2::StandardSv2Frame<AnyMessage<'static>> = frame
        .try_into()
        .map_err(|_| Sv2Error::InvalidMessage("expected Sv2Frame, got HandShake".to_string()))?;

    let header = sv2_frame
        .get_header()
        .ok_or_else(|| Sv2Error::InvalidMessage("frame has no header".to_string()))?;

    let payload = sv2_frame.payload();

    let message: AnyMessage<'_> = (header, payload)
        .try_into()
        .map_err(|e| Sv2Error::InvalidMessage(format!("failed to parse SetupConnection: {e:?}")))?;

    match message {
        AnyMessage::Common(CommonMessages::SetupConnection(setup_msg)) => {
            match validate_setup_connection(&setup_msg) {
                Ok(result) => {
                    let success = build_setup_connection_success(&result);
                    let wrapped = CommonMessages::SetupConnectionSuccess(success);
                    let any = AnyMessage::Common(wrapped);
                    send_message(state, &ctx.connections, session.downstream_id, any).await?;
                    session.setup_complete = true;
                    debug!(
                        downstream_id = session.downstream_id,
                        "SetupConnection succeeded"
                    );
                    Ok(true)
                }
                Err(e) => {
                    let error_resp = build_setup_connection_error(&e);
                    let wrapped = CommonMessages::SetupConnectionError(error_resp);
                    let any = AnyMessage::Common(wrapped);
                    let _ = send_message(state, &ctx.connections, session.downstream_id, any).await;
                    warn!(
                        downstream_id = session.downstream_id,
                        "SetupConnection rejected: {e}"
                    );
                    Ok(false)
                }
            }
        }
        _ => Err(Sv2Error::InvalidMessage(
            "first message must be SetupConnection".to_string(),
        )),
    }
}

// ---------------------------------------------------------------------------
// OpenStandardMiningChannel handler
// ---------------------------------------------------------------------------

async fn handle_open_standard_channel(
    msg: OpenStandardMiningChannel<'static>,
    session: &mut Sv2Session,
    ctx: &Sv2ConnectionContext,
    state: &Arc<tokio::sync::Mutex<State>>,
) -> Result<(), Sv2Error> {
    let request_id = msg.get_request_id_as_u32();

    // Validate and register user.
    let user_result = validate_and_register_user(
        &msg.user_identity,
        ctx.validate_addresses,
        ctx.network,
        &ctx.chain_store,
    )
    .await;

    let (btc_address, worker_name, user_id) = match user_result {
        Ok(v) => v,
        Err(e) => {
            let err_resp = build_open_channel_error(request_id, &e.to_string());
            let any = AnyMessage::Mining(Mining::OpenMiningChannelError(err_resp));
            send_message(state, &ctx.connections, session.downstream_id, any).await?;
            warn!(
                downstream_id = session.downstream_id,
                "OpenStandardMiningChannel rejected: {e}"
            );
            return Ok(());
        }
    };

    // Open the channel.
    let open_result = ctx
        .channels
        .open_standard_channel(
            session.downstream_id,
            msg,
            btc_address,
            worker_name,
            user_id,
        )
        .await;

    let success = match open_result {
        Ok(s) => s,
        Err(e) => {
            let err_resp = build_open_channel_error(request_id, &e.to_string());
            let any = AnyMessage::Mining(Mining::OpenMiningChannelError(err_resp));
            send_message(state, &ctx.connections, session.downstream_id, any).await?;
            return Ok(());
        }
    };

    let group_channel_id = success.channel.group_channel_id;
    let channel_id = success.channel.channel_id;
    let extranonce = success.channel.extranonce_prefix.clone();

    // Send OpenStandardMiningChannelSuccess.
    let any = AnyMessage::Mining(Mining::OpenStandardMiningChannelSuccess(success.response));
    send_message(state, &ctx.connections, session.downstream_id, any).await?;

    // Register the group with the job distributor (if first channel for this
    // downstream, which creates the group).
    if session.group_channel_id.is_none() {
        ctx.job_distributor
            .register_group(group_channel_id, extranonce)
            .await?;
        session.group_channel_id = Some(group_channel_id);
    }

    // Bootstrap: send the current active job to this channel.
    if let Ok(Some(active)) = ctx.job_distributor.get_active_job(group_channel_id).await {
        // Send NewMiningJob.
        let job_msg = NewMiningJob {
            channel_id,
            job_id: active.job_id,
            min_ntime: if active.job_state.is_future {
                stratum_core::binary_sv2::Sv2Option::new(None)
            } else {
                stratum_core::binary_sv2::Sv2Option::new(Some(active.min_ntime))
            },
            version: active.version,
            merkle_root: active
                .merkle_root
                .to_vec()
                .try_into()
                .expect("32 bytes is valid U256"),
        };
        let any = AnyMessage::Mining(Mining::NewMiningJob(job_msg));
        send_message(state, &ctx.connections, session.downstream_id, any).await?;

        // Send SetNewPrevHash if the job is activated (not future).
        if let (Some(prev_hash), Some(nbits)) = (active.prev_hash, active.nbits) {
            let prev_hash_msg = SetNewPrevHash {
                channel_id,
                job_id: active.job_id,
                prev_hash: prev_hash
                    .to_vec()
                    .try_into()
                    .expect("32 bytes is valid U256"),
                min_ntime: active.min_ntime,
                nbits,
            };
            let any = AnyMessage::Mining(Mining::SetNewPrevHash(prev_hash_msg));
            send_message(state, &ctx.connections, session.downstream_id, any).await?;
        }
    }

    info!(
        downstream_id = session.downstream_id,
        channel_id, group_channel_id, "SV2 standard mining channel opened"
    );

    Ok(())
}

// ---------------------------------------------------------------------------
// SubmitSharesStandard handler
// ---------------------------------------------------------------------------

async fn handle_submit_shares_standard(
    submit: SubmitSharesStandard,
    session: &mut Sv2Session,
    ctx: &Sv2ConnectionContext,
    state: &Arc<tokio::sync::Mutex<State>>,
) -> Result<(), Sv2Error> {
    let channel_id = submit.channel_id;
    let job_id = submit.job_id;
    let seq_num = submit.sequence_number;

    // Look up job state.
    let job_state = match ctx.job_distributor.get_job_state(job_id).await? {
        Some(s) => s,
        None => {
            let err_resp = build_submit_error(channel_id, seq_num, "stale-share");
            let any = AnyMessage::Mining(Mining::SubmitSharesError(err_resp));
            send_message(state, &ctx.connections, session.downstream_id, any).await?;
            debug!(
                downstream_id = session.downstream_id,
                job_id, "stale share (unknown job_id)"
            );
            return Ok(());
        }
    };

    // Look up channel.
    let channel = match ctx.channels.get_channel(channel_id).await? {
        Some(c) => c,
        None => {
            let err_resp = build_submit_error(channel_id, seq_num, "unknown-user");
            let any = AnyMessage::Mining(Mining::SubmitSharesError(err_resp));
            send_message(state, &ctx.connections, session.downstream_id, any).await?;
            warn!(
                downstream_id = session.downstream_id,
                channel_id, "unknown channel_id"
            );
            return Ok(());
        }
    };

    // Validate the share.
    match validate_share(&submit, &job_state, &channel) {
        Ok(validation) => {
            if !validation.meets_channel_target {
                let err_resp = build_submit_error(channel_id, seq_num, "low-difficulty-share");
                let any = AnyMessage::Mining(Mining::SubmitSharesError(err_resp));
                send_message(state, &ctx.connections, session.downstream_id, any).await?;
                return Ok(());
            }

            // Emit to accounting pipeline.
            if let Err(e) = emit_share(
                &submit,
                &validation,
                &job_state,
                &channel,
                &ctx.emissions_tx,
            )
            .await
            {
                warn!(
                    downstream_id = session.downstream_id,
                    "failed to emit share: {e}"
                );
            }

            // Send success response.
            session.accepted_shares += 1;
            session.shares_sum += 1; // placeholder difficulty
            let success_resp = build_submit_success(
                channel_id,
                seq_num,
                session.accepted_shares,
                session.shares_sum,
            );
            let any = AnyMessage::Mining(Mining::SubmitSharesSuccess(success_resp));
            send_message(state, &ctx.connections, session.downstream_id, any).await?;
        }
        Err(e) => {
            let reason = match &e {
                Sv2Error::InvalidMessage(msg) if msg.contains("future") => "stale-share",
                _ => "bad-nonce",
            };
            let err_resp = build_submit_error(channel_id, seq_num, reason);
            let any = AnyMessage::Mining(Mining::SubmitSharesError(err_resp));
            send_message(state, &ctx.connections, session.downstream_id, any).await?;
            debug!(
                downstream_id = session.downstream_id,
                "share validation error: {e}"
            );
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Writer task
// ---------------------------------------------------------------------------

/// Writer task: sends pre-encoded frames from msg_rx and pushes job updates.
async fn writer_task(
    mut writer: OwnedWriteHalf,
    state: Arc<tokio::sync::Mutex<State>>,
    mut msg_rx: mpsc::Receiver<Arc<Vec<u8>>>,
    mut shutdown_rx: tokio::sync::oneshot::Receiver<()>,
    mut job_events: watch::Receiver<Option<JobEvent>>,
    downstream_id: DownstreamId,
) {
    loop {
        tokio::select! {
            // Shutdown signal.
            _ = &mut shutdown_rx => {
                debug!(downstream_id, "SV2 writer task shutting down");
                break;
            }
            // Pre-encoded message from the connection registry.
            msg = msg_rx.recv() => {
                match msg {
                    Some(bytes) => {
                        if let Err(e) = writer.write_all(&bytes).await {
                            debug!(downstream_id, "SV2 write failed: {e}");
                            break;
                        }
                    }
                    None => {
                        debug!(downstream_id, "SV2 msg_rx closed");
                        break;
                    }
                }
            }
            // New job event from the distributor.
            result = job_events.changed() => {
                if result.is_err() {
                    // Watch sender dropped — distributor shut down.
                    break;
                }
                let event = job_events.borrow_and_update().clone();
                if let Some(event) = event {
                    // Encode and write NewMiningJob.
                    // The event.group_channel_id tells us which group this is for.
                    // We use channel_id 0 (group broadcast) for group-level messages.
                    let job_msg = NewMiningJob {
                        channel_id: event.group_channel_id,
                        job_id: event.job_id,
                        min_ntime: if event.job_state.is_future {
                            stratum_core::binary_sv2::Sv2Option::new(None)
                        } else {
                            stratum_core::binary_sv2::Sv2Option::new(Some(event.job_state.min_ntime))
                        },
                        version: event.job_state.version,
                        merkle_root: event.job_state.merkle_root
                            .to_vec()
                            .try_into()
                            .expect("32 bytes is valid U256"),
                    };

                    let any_job = AnyMessage::Mining(Mining::NewMiningJob(job_msg));
                    match encode_message(&state, any_job).await {
                        Ok(bytes) => {
                            if let Err(e) = writer.write_all(&bytes).await {
                                debug!(downstream_id, "SV2 write job failed: {e}");
                                break;
                            }
                        }
                        Err(e) => {
                            warn!(downstream_id, "failed to encode NewMiningJob: {e}");
                        }
                    }

                    // If the job is activated (not future), send SetNewPrevHash.
                    if let Some(prev_hash) = event.job_state.prev_hash {
                        let prev_hash_msg = SetNewPrevHash {
                            channel_id: event.group_channel_id,
                            job_id: event.job_id,
                            prev_hash: prev_hash
                                .to_vec()
                                .try_into()
                                .expect("32 bytes is valid U256"),
                            min_ntime: event.job_state.min_ntime,
                            nbits: event.job_state.nbits,
                        };
                        let any_prev = AnyMessage::Mining(Mining::SetNewPrevHash(prev_hash_msg));
                        match encode_message(&state, any_prev).await {
                            Ok(bytes) => {
                                if let Err(e) = writer.write_all(&bytes).await {
                                    debug!(downstream_id, "SV2 write prev_hash failed: {e}");
                                    break;
                                }
                            }
                            Err(e) => {
                                warn!(downstream_id, "failed to encode SetNewPrevHash: {e}");
                            }
                        }
                    }
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Frame I/O helpers
// ---------------------------------------------------------------------------

/// Read a single SV2 frame from the encrypted stream.
///
/// Uses the decoder's `writable()` / `next_frame()` pattern:
/// 1. Get the buffer the decoder wants filled
/// 2. Read exactly that many bytes from the TCP stream
/// 3. Try to decode — if MissingBytes, repeat
async fn read_sv2_frame(
    reader: &mut OwnedReadHalf,
    state: &Arc<tokio::sync::Mutex<State>>,
) -> Result<Sv2DecodedFrame, Sv2Error> {
    let mut decoder = StandardNoiseDecoder::<AnyMessage<'static>>::new();

    loop {
        let writable = decoder.writable();
        reader.read_exact(writable).await.map_err(|e| {
            if e.kind() == std::io::ErrorKind::UnexpectedEof {
                Sv2Error::ConnectionClosed
            } else {
                Sv2Error::Io(e)
            }
        })?;

        let mut state_guard = state.lock().await;
        match decoder.next_frame(&mut state_guard) {
            Ok(frame) => return Ok(frame),
            Err(e) => {
                // Check if it's MissingBytes (need more data).
                let err_str = format!("{e:?}");
                if err_str.contains("MissingBytes") {
                    drop(state_guard);
                    continue;
                }
                return Err(Sv2Error::Codec(format!("frame decode error: {e:?}")));
            }
        }
    }
}

/// Encode a message into Noise-encrypted bytes.
async fn encode_message(
    state: &Arc<tokio::sync::Mutex<State>>,
    message: AnyMessage<'_>,
) -> Result<Vec<u8>, Sv2Error> {
    let msg_type = message.message_type();
    let ext_type = message.extension_type();
    let channel_bit = message.channel_bit();

    let sv2_frame = Sv2Frame::from_message(message, msg_type, ext_type, channel_bit)
        .ok_or_else(|| Sv2Error::Codec("message too large for SV2 frame".to_string()))?;

    let frame: Frame<AnyMessage<'_>, _> = sv2_frame.into();

    let mut encoder = NoiseEncoder::<AnyMessage<'_>>::new();
    let mut state_guard = state.lock().await;
    let encoded = encoder
        .encode(frame, &mut state_guard)
        .map_err(|e| Sv2Error::Codec(format!("encode error: {e:?}")))?;

    Ok(encoded.to_vec())
}

/// Send a message to a specific downstream via the connection registry.
///
/// Encodes the message into Noise-encrypted bytes, then sends through
/// the registry's targeted send.
async fn send_message(
    state: &Arc<tokio::sync::Mutex<State>>,
    connections: &Sv2ConnectionsHandle,
    downstream_id: DownstreamId,
    message: AnyMessage<'_>,
) -> Result<(), Sv2Error> {
    let bytes = encode_message(state, message).await?;
    let ok = connections
        .send_to_downstream(downstream_id, Arc::new(bytes))
        .await;
    if !ok {
        return Err(Sv2Error::ConnectionClosed);
    }
    Ok(())
}
