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

//! SV2 TCP listener and Noise NX handshake acceptor.
//!
//! Accepts incoming TCP connections, performs the Noise NX handshake to
//! establish an encrypted channel, then spawns per-connection reader/writer
//! tasks for framed SV2 message exchange.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use stratum_core::codec_sv2::{HandshakeRole, State};
use stratum_core::noise_sv2::{self, Responder};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, oneshot};
use tracing::{debug, error, info, warn};

use super::error::Sv2Error;

/// Default timeout for the Noise NX handshake (seconds).
const HANDSHAKE_TIMEOUT_SECS: u64 = 10;

/// Unique identifier for a downstream SV2 connection.
pub type DownstreamId = u64;

/// Global counter for assigning unique downstream IDs.
static NEXT_DOWNSTREAM_ID: AtomicU64 = AtomicU64::new(1);

/// Generate a unique downstream ID.
fn next_downstream_id() -> DownstreamId {
    NEXT_DOWNSTREAM_ID.fetch_add(1, Ordering::Relaxed)
}

/// Authority keypair for Noise NX handshake.
#[derive(Clone)]
pub struct AuthorityKeypair {
    pub public_key: [u8; 32],
    pub secret_key: [u8; 32],
    pub cert_validity: Duration,
}

impl AuthorityKeypair {
    /// Parse from hex-encoded config strings.
    pub fn from_config(
        public_key_hex: &str,
        secret_key_hex: &str,
        cert_validity_secs: u64,
    ) -> Result<Self, Sv2Error> {
        let public_key: [u8; 32] = hex::decode(public_key_hex)
            .map_err(|e| Sv2Error::Config(format!("invalid authority public key hex: {e}")))?
            .try_into()
            .map_err(|v: Vec<u8>| {
                Sv2Error::Config(format!(
                    "authority public key must be 32 bytes, got {}",
                    v.len()
                ))
            })?;

        let secret_key: [u8; 32] = hex::decode(secret_key_hex)
            .map_err(|e| Sv2Error::Config(format!("invalid authority secret key hex: {e}")))?
            .try_into()
            .map_err(|v: Vec<u8>| {
                Sv2Error::Config(format!(
                    "authority secret key must be 32 bytes, got {}",
                    v.len()
                ))
            })?;

        Ok(Self {
            public_key,
            secret_key,
            cert_validity: Duration::from_secs(cert_validity_secs),
        })
    }
}

/// Result of a successful Noise handshake: an encrypted codec state
/// plus the split TCP stream halves and downstream identity.
pub struct HandshakeResult {
    pub downstream_id: DownstreamId,
    pub addr: SocketAddr,
    pub state: State,
    pub stream: TcpStream,
}

/// Perform the Noise NX handshake on an accepted TCP connection (server/responder side).
///
/// The NX pattern is two messages:
/// 1. Initiator -> Responder: 64-byte ElligatorSwift ephemeral public key
/// 2. Responder -> Initiator: 170-byte response (ephemeral + encrypted static + signature)
///
/// After step 2, both sides have a shared `NoiseCodec` for symmetric encryption.
pub async fn perform_noise_handshake(
    mut stream: TcpStream,
    addr: SocketAddr,
    authority: &AuthorityKeypair,
) -> Result<HandshakeResult, Sv2Error> {
    let downstream_id = next_downstream_id();

    // Create a Responder from the authority keypair
    let responder = Responder::from_authority_kp(
        &authority.public_key,
        &authority.secret_key,
        authority.cert_validity,
    )
    .map_err(|e| Sv2Error::HandshakeFailed(format!("failed to create Responder: {e:?}")))?;

    // Initialize the codec state machine in HandShake mode
    let mut state = State::initialized(HandshakeRole::Responder(responder));

    // Step 1: Read the initiator's 64-byte ephemeral public key
    let mut initiator_msg = [0u8; noise_sv2::ELLSWIFT_ENCODING_SIZE];
    tokio::time::timeout(
        Duration::from_secs(HANDSHAKE_TIMEOUT_SECS),
        stream.read_exact(&mut initiator_msg),
    )
    .await
    .map_err(|_| Sv2Error::HandshakeTimeout)?
    .map_err(|e| Sv2Error::HandshakeFailed(format!("failed to read initiator message: {e}")))?;

    // Step 2: Compute response and transition to Transport state
    let (response_frame, transport_state) = state
        .step_1(initiator_msg)
        .map_err(|e| Sv2Error::HandshakeFailed(format!("Noise step_1 failed: {e:?}")))?;

    // Send the 170-byte response to the initiator
    let response_bytes = response_frame.get_payload_when_handshaking();
    tokio::time::timeout(
        Duration::from_secs(HANDSHAKE_TIMEOUT_SECS),
        stream.write_all(&response_bytes),
    )
    .await
    .map_err(|_| Sv2Error::HandshakeTimeout)?
    .map_err(|e| Sv2Error::HandshakeFailed(format!("failed to write responder message: {e}")))?;

    debug!(
        downstream_id,
        addr = %addr,
        "SV2 Noise handshake completed"
    );

    Ok(HandshakeResult {
        downstream_id,
        addr,
        state: transport_state,
        stream,
    })
}

/// Configuration for the SV2 TCP server.
pub struct Sv2ServerConfig {
    pub hostname: String,
    pub port: u16,
    pub authority: AuthorityKeypair,
}

/// Accept loop for the SV2 TCP server.
///
/// Binds to the configured address, accepts incoming TCP connections,
/// performs the Noise NX handshake, and sends successful handshake results
/// to the provided channel for further processing.
pub async fn run_accept_loop(
    config: Sv2ServerConfig,
    handshake_tx: mpsc::Sender<HandshakeResult>,
    mut shutdown_rx: oneshot::Receiver<()>,
) -> Result<(), Sv2Error> {
    let bind_addr = format!("{}:{}", config.hostname, config.port);
    let listener = TcpListener::bind(&bind_addr).await?;
    info!("SV2 server listening on {}", bind_addr);

    let authority = Arc::new(config.authority);

    loop {
        tokio::select! {
            _ = &mut shutdown_rx => {
                info!("SV2 accept loop shutting down");
                break;
            }
            accept_result = listener.accept() => {
                match accept_result {
                    Ok((stream, addr)) => {
                        if let Err(e) = stream.set_nodelay(true) {
                            warn!(addr = %addr, "Failed to set TCP_NODELAY: {e}");
                        }
                        let authority = authority.clone();
                        let handshake_tx = handshake_tx.clone();
                        tokio::spawn(async move {
                            match tokio::time::timeout(
                                Duration::from_secs(HANDSHAKE_TIMEOUT_SECS),
                                perform_noise_handshake(stream, addr, &authority),
                            )
                            .await
                            {
                                Ok(Ok(result)) => {
                                    if handshake_tx.send(result).await.is_err() {
                                        debug!("Handshake result channel closed");
                                    }
                                }
                                Ok(Err(e)) => {
                                    debug!(addr = %addr, "Noise handshake failed: {e}");
                                }
                                Err(_) => {
                                    debug!(addr = %addr, "Noise handshake timed out");
                                }
                            }
                        });
                    }
                    Err(e) => {
                        error!("Failed to accept SV2 connection: {e}");
                    }
                }
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_downstream_id_increments() {
        let id1 = next_downstream_id();
        let id2 = next_downstream_id();
        assert!(id2 > id1);
    }

    #[test]
    fn test_authority_keypair_from_config() {
        let pub_hex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let sec_hex = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210";
        let result = AuthorityKeypair::from_config(pub_hex, sec_hex, 86400);
        assert!(result.is_ok());
        let kp = result.unwrap();
        assert_eq!(kp.cert_validity, Duration::from_secs(86400));
    }

    #[test]
    fn test_authority_keypair_invalid_hex() {
        let result = AuthorityKeypair::from_config("not_hex", "also_not_hex", 86400);
        assert!(result.is_err());
    }

    #[test]
    fn test_authority_keypair_wrong_length() {
        let result = AuthorityKeypair::from_config("0123", "4567", 86400);
        assert!(result.is_err());
    }
}
