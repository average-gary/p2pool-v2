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

//! Standard Mining Channel management for SV2.
//!
//! Each SV2 downstream connection can open one or more **standard mining
//! channels**. Standard channels are used by end mining devices for
//! header-only mining (HOM): the pool sends pre-computed `NewMiningJob`
//! messages and the device manipulates nonce, nTime, and version bits.
//!
//! Every standard channel belongs to a **group channel**. All channels on
//! the same downstream connection share a single group channel, enabling
//! efficient job multicast (one `SetNewPrevHash` / `NewMiningJob` per group
//! instead of per channel).
//!
//! # Architecture
//!
//! [`Sv2ChannelManager`] is the central coordinator, implemented as a
//! tokio actor. It owns all channel state and processes commands via an
//! mpsc channel. External code interacts through the cheaply-cloneable
//! [`Sv2ChannelHandle`].

use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, Ordering};

use stratum_core::binary_sv2::{B032, Str0255, U256};
use stratum_core::mining_sv2::{
    OpenMiningChannelError, OpenStandardMiningChannel, OpenStandardMiningChannelSuccess,
};
use tokio::sync::{mpsc, oneshot};
use tracing::debug;

use super::connection::DownstreamId;
use super::error::Sv2Error;

// ---------------------------------------------------------------------------
// Channel ID allocation
// ---------------------------------------------------------------------------

/// Global counter for unique channel IDs (across all connections).
static NEXT_CHANNEL_ID: AtomicU32 = AtomicU32::new(1);

/// Global counter for unique group channel IDs.
static NEXT_GROUP_CHANNEL_ID: AtomicU32 = AtomicU32::new(1);

/// Allocate a new unique channel ID.
fn next_channel_id() -> u32 {
    NEXT_CHANNEL_ID.fetch_add(1, Ordering::Relaxed)
}

/// Allocate a new unique group channel ID.
fn next_group_channel_id() -> u32 {
    NEXT_GROUP_CHANNEL_ID.fetch_add(1, Ordering::Relaxed)
}

// ---------------------------------------------------------------------------
// Extranonce prefix generation
// ---------------------------------------------------------------------------

/// Build a unique extranonce prefix for a standard channel.
///
/// The prefix is 6 bytes: `[server_id_hi, server_id_lo, ch_id_b3, ch_id_b2, ch_id_b1, ch_id_b0]`.
/// This ensures uniqueness across server instances (via `server_id`) and
/// across channels within a single instance (via `channel_id`).
///
/// The downstream device appends its own nonce bytes to complete the
/// extranonce for the coinbase transaction.
fn build_extranonce_prefix(server_id: u16, channel_id: u32) -> Vec<u8> {
    let mut prefix = Vec::with_capacity(6);
    prefix.extend_from_slice(&server_id.to_be_bytes());
    prefix.extend_from_slice(&channel_id.to_be_bytes());
    prefix
}

// ---------------------------------------------------------------------------
// Per-channel state
// ---------------------------------------------------------------------------

/// State for a single open standard mining channel.
#[derive(Debug, Clone)]
pub struct StandardChannel {
    /// Unique channel identifier (assigned by pool).
    pub channel_id: u32,
    /// Group channel this standard channel belongs to.
    pub group_channel_id: u32,
    /// The downstream connection that owns this channel.
    pub downstream_id: DownstreamId,
    /// Validated Bitcoin address from `user_identity`.
    pub btc_address: String,
    /// Optional worker name (from `user_identity` after the dot).
    pub worker_name: Option<String>,
    /// User ID from the share chain store.
    pub user_id: u64,
    /// Nominal hash rate reported by the device (h/s).
    pub nominal_hash_rate: f32,
    /// The extranonce prefix assigned to this channel.
    pub extranonce_prefix: Vec<u8>,
    /// Current mining target for this channel.
    pub target: [u8; 32],
}

// ---------------------------------------------------------------------------
// Per-downstream group state
// ---------------------------------------------------------------------------

/// Tracks the group channel and all standard channels for one downstream.
#[derive(Debug)]
struct DownstreamGroup {
    /// The group channel ID assigned to this downstream.
    group_channel_id: u32,
    /// Channel IDs of standard channels opened on this downstream.
    channel_ids: Vec<u32>,
}

// ---------------------------------------------------------------------------
// Actor commands
// ---------------------------------------------------------------------------

/// Result of a successful channel open, carrying the response message
/// and the internal channel state.
pub struct ChannelOpenSuccess {
    pub response: OpenStandardMiningChannelSuccess<'static>,
    pub channel: StandardChannel,
}

/// Commands sent to the channel manager actor.
enum ChannelCmd {
    /// Open a new standard mining channel.
    Open {
        downstream_id: DownstreamId,
        msg: OpenStandardMiningChannel<'static>,
        /// Validated Bitcoin address string (caller already validated).
        btc_address: String,
        /// Optional worker name parsed from user_identity.
        worker_name: Option<String>,
        /// User ID from ChainStoreHandle::add_user.
        user_id: u64,
        reply: oneshot::Sender<Result<ChannelOpenSuccess, OpenMiningChannelError<'static>>>,
    },
    /// Get all channel IDs for a downstream.
    GetChannelsForDownstream {
        downstream_id: DownstreamId,
        reply: oneshot::Sender<Vec<u32>>,
    },
    /// Get a channel by its ID.
    GetChannel {
        channel_id: u32,
        reply: oneshot::Sender<Option<StandardChannel>>,
    },
    /// Remove all channels for a disconnected downstream.
    RemoveDownstream { downstream_id: DownstreamId },
    /// Get total channel count (for metrics/testing).
    GetCount { reply: oneshot::Sender<usize> },
    /// Get the group channel ID for a downstream (if any).
    GetGroupChannelId {
        downstream_id: DownstreamId,
        reply: oneshot::Sender<Option<u32>>,
    },
    /// Update the mining target for a specific channel.
    UpdateTarget {
        channel_id: u32,
        new_target: [u8; 32],
        reply: oneshot::Sender<bool>,
    },
}

// ---------------------------------------------------------------------------
// Channel manager actor (internal)
// ---------------------------------------------------------------------------

/// Internal actor state for managing all SV2 mining channels.
struct Sv2ChannelManager {
    /// All open standard channels, keyed by channel_id.
    channels: HashMap<u32, StandardChannel>,
    /// Per-downstream group tracking.
    downstream_groups: HashMap<DownstreamId, DownstreamGroup>,
    /// Server ID for extranonce prefix generation.
    server_id: u16,
    /// Default initial target for new channels (32 bytes, big-endian).
    default_target: [u8; 32],
}

impl Sv2ChannelManager {
    fn new(server_id: u16, default_target: [u8; 32]) -> Self {
        Self {
            channels: HashMap::new(),
            downstream_groups: HashMap::new(),
            server_id,
            default_target,
        }
    }

    /// Handle a channel open request.
    ///
    /// The caller has already validated the Bitcoin address and registered
    /// the user; we just need to allocate IDs and build the response.
    fn handle_open(
        &mut self,
        downstream_id: DownstreamId,
        msg: &OpenStandardMiningChannel<'static>,
        btc_address: String,
        worker_name: Option<String>,
        user_id: u64,
    ) -> Result<ChannelOpenSuccess, OpenMiningChannelError<'static>> {
        let channel_id = next_channel_id();

        // Get or create the group for this downstream
        let group = self
            .downstream_groups
            .entry(downstream_id)
            .or_insert_with(|| {
                let gid = next_group_channel_id();
                debug!(
                    downstream_id,
                    group_channel_id = gid,
                    "created new group channel for downstream"
                );
                DownstreamGroup {
                    group_channel_id: gid,
                    channel_ids: Vec::new(),
                }
            });

        let group_channel_id = group.group_channel_id;
        group.channel_ids.push(channel_id);

        // Build extranonce prefix
        let extranonce_prefix = build_extranonce_prefix(self.server_id, channel_id);

        let channel = StandardChannel {
            channel_id,
            group_channel_id,
            downstream_id,
            btc_address,
            worker_name,
            user_id,
            nominal_hash_rate: msg.nominal_hash_rate,
            extranonce_prefix: extranonce_prefix.clone(),
            target: self.default_target,
        };

        // Build the success response
        let target_bytes: U256<'static> = self
            .default_target
            .to_vec()
            .try_into()
            .expect("32-byte target is always valid U256");

        let extranonce_b032: B032<'static> = extranonce_prefix
            .try_into()
            .expect("6-byte extranonce prefix fits in B032");

        let request_id = msg.get_request_id_as_u32();

        let response = OpenStandardMiningChannelSuccess {
            request_id: request_id
                .to_le_bytes()
                .to_vec()
                .try_into()
                .expect("4-byte u32 is valid U32AsRef"),
            channel_id,
            target: target_bytes,
            extranonce_prefix: extranonce_b032,
            group_channel_id,
        };

        debug!(
            channel_id,
            group_channel_id,
            downstream_id,
            user_id,
            nominal_hash_rate = msg.nominal_hash_rate,
            "opened standard mining channel"
        );

        self.channels.insert(channel_id, channel.clone());

        Ok(ChannelOpenSuccess { response, channel })
    }

    fn handle_get_channels_for_downstream(&self, downstream_id: DownstreamId) -> Vec<u32> {
        self.downstream_groups
            .get(&downstream_id)
            .map(|g| g.channel_ids.clone())
            .unwrap_or_default()
    }

    fn handle_get_channel(&self, channel_id: u32) -> Option<StandardChannel> {
        self.channels.get(&channel_id).cloned()
    }

    fn handle_remove_downstream(&mut self, downstream_id: DownstreamId) {
        if let Some(group) = self.downstream_groups.remove(&downstream_id) {
            for ch_id in &group.channel_ids {
                self.channels.remove(ch_id);
            }
            debug!(
                downstream_id,
                removed = group.channel_ids.len(),
                "removed all channels for disconnected downstream"
            );
        }
    }

    fn handle_get_group_channel_id(&self, downstream_id: DownstreamId) -> Option<u32> {
        self.downstream_groups
            .get(&downstream_id)
            .map(|g| g.group_channel_id)
    }

    fn handle_update_target(&mut self, channel_id: u32, new_target: [u8; 32]) -> bool {
        if let Some(channel) = self.channels.get_mut(&channel_id) {
            channel.target = new_target;
            debug!(channel_id, "updated channel target");
            true
        } else {
            false
        }
    }

    /// Run the actor event loop.
    async fn run(mut self, mut cmd_rx: mpsc::Receiver<ChannelCmd>) {
        while let Some(cmd) = cmd_rx.recv().await {
            match cmd {
                ChannelCmd::Open {
                    downstream_id,
                    msg,
                    btc_address,
                    worker_name,
                    user_id,
                    reply,
                } => {
                    let result =
                        self.handle_open(downstream_id, &msg, btc_address, worker_name, user_id);
                    let _ = reply.send(result);
                }
                ChannelCmd::GetChannelsForDownstream {
                    downstream_id,
                    reply,
                } => {
                    let _ = reply.send(self.handle_get_channels_for_downstream(downstream_id));
                }
                ChannelCmd::GetChannel { channel_id, reply } => {
                    let _ = reply.send(self.handle_get_channel(channel_id));
                }
                ChannelCmd::RemoveDownstream { downstream_id } => {
                    self.handle_remove_downstream(downstream_id);
                }
                ChannelCmd::GetCount { reply } => {
                    let _ = reply.send(self.channels.len());
                }
                ChannelCmd::GetGroupChannelId {
                    downstream_id,
                    reply,
                } => {
                    let _ = reply.send(self.handle_get_group_channel_id(downstream_id));
                }
                ChannelCmd::UpdateTarget {
                    channel_id,
                    new_target,
                    reply,
                } => {
                    let _ = reply.send(self.handle_update_target(channel_id, new_target));
                }
            }
        }
        debug!("channel manager actor shutting down");
    }
}

// ---------------------------------------------------------------------------
// Public handle
// ---------------------------------------------------------------------------

const CHANNEL_CMD_BUFFER: usize = 256;

/// Cheaply-cloneable handle for interacting with the channel manager actor.
#[derive(Clone)]
pub struct Sv2ChannelHandle {
    cmd_tx: mpsc::Sender<ChannelCmd>,
}

/// Start the channel manager actor and return a handle.
///
/// # Arguments
///
/// * `server_id` - Unique server instance ID for extranonce prefix generation
/// * `default_target` - Initial mining target for new channels (32 bytes, big-endian)
pub fn start_channel_manager(server_id: u16, default_target: [u8; 32]) -> Sv2ChannelHandle {
    let (cmd_tx, cmd_rx) = mpsc::channel(CHANNEL_CMD_BUFFER);
    let manager = Sv2ChannelManager::new(server_id, default_target);
    tokio::spawn(manager.run(cmd_rx));
    Sv2ChannelHandle { cmd_tx }
}

impl Sv2ChannelHandle {
    /// Open a new standard mining channel.
    ///
    /// The caller must have already:
    /// 1. Validated the Bitcoin address via `validate_username`
    /// 2. Registered the user via `ChainStoreHandle::add_user`
    ///
    /// This method allocates the channel ID, group channel, and extranonce
    /// prefix, then returns the SV2 success response message along with the
    /// internal channel state.
    pub async fn open_standard_channel(
        &self,
        downstream_id: DownstreamId,
        msg: OpenStandardMiningChannel<'static>,
        btc_address: String,
        worker_name: Option<String>,
        user_id: u64,
    ) -> Result<ChannelOpenSuccess, Sv2Error> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.cmd_tx
            .send(ChannelCmd::Open {
                downstream_id,
                msg,
                btc_address,
                worker_name,
                user_id,
                reply: reply_tx,
            })
            .await
            .map_err(|_| Sv2Error::ChannelError("channel manager actor stopped".to_string()))?;

        reply_rx
            .await
            .map_err(|_| Sv2Error::ChannelError("channel manager reply dropped".to_string()))?
            .map_err(|e| {
                Sv2Error::InvalidMessage(format!("channel open rejected: {:?}", e.error_code))
            })
    }

    /// Get all channel IDs for a given downstream connection.
    pub async fn get_channels_for_downstream(
        &self,
        downstream_id: DownstreamId,
    ) -> Result<Vec<u32>, Sv2Error> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.cmd_tx
            .send(ChannelCmd::GetChannelsForDownstream {
                downstream_id,
                reply: reply_tx,
            })
            .await
            .map_err(|_| Sv2Error::ChannelError("channel manager actor stopped".to_string()))?;

        reply_rx
            .await
            .map_err(|_| Sv2Error::ChannelError("channel manager reply dropped".to_string()))
    }

    /// Look up a channel by its ID.
    pub async fn get_channel(&self, channel_id: u32) -> Result<Option<StandardChannel>, Sv2Error> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.cmd_tx
            .send(ChannelCmd::GetChannel {
                channel_id,
                reply: reply_tx,
            })
            .await
            .map_err(|_| Sv2Error::ChannelError("channel manager actor stopped".to_string()))?;

        reply_rx
            .await
            .map_err(|_| Sv2Error::ChannelError("channel manager reply dropped".to_string()))
    }

    /// Remove all channels for a disconnected downstream.
    pub async fn remove_downstream(&self, downstream_id: DownstreamId) -> Result<(), Sv2Error> {
        self.cmd_tx
            .send(ChannelCmd::RemoveDownstream { downstream_id })
            .await
            .map_err(|_| Sv2Error::ChannelError("channel manager actor stopped".to_string()))
    }

    /// Get total number of open channels (for metrics/testing).
    pub async fn get_count(&self) -> Result<usize, Sv2Error> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.cmd_tx
            .send(ChannelCmd::GetCount { reply: reply_tx })
            .await
            .map_err(|_| Sv2Error::ChannelError("channel manager actor stopped".to_string()))?;

        reply_rx
            .await
            .map_err(|_| Sv2Error::ChannelError("channel manager reply dropped".to_string()))
    }

    /// Update the mining target for a specific channel.
    ///
    /// Called by the per-connection handler when the difficulty adjuster
    /// determines a new target. Returns `true` if the channel was found
    /// and updated, `false` if the channel ID is unknown.
    pub async fn update_target(
        &self,
        channel_id: u32,
        new_target: [u8; 32],
    ) -> Result<bool, Sv2Error> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.cmd_tx
            .send(ChannelCmd::UpdateTarget {
                channel_id,
                new_target,
                reply: reply_tx,
            })
            .await
            .map_err(|_| Sv2Error::ChannelError("channel manager actor stopped".to_string()))?;

        reply_rx
            .await
            .map_err(|_| Sv2Error::ChannelError("channel manager reply dropped".to_string()))
    }

    /// Get the group channel ID for a downstream, if it has one.
    pub async fn get_group_channel_id(
        &self,
        downstream_id: DownstreamId,
    ) -> Result<Option<u32>, Sv2Error> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.cmd_tx
            .send(ChannelCmd::GetGroupChannelId {
                downstream_id,
                reply: reply_tx,
            })
            .await
            .map_err(|_| Sv2Error::ChannelError("channel manager actor stopped".to_string()))?;

        reply_rx
            .await
            .map_err(|_| Sv2Error::ChannelError("channel manager reply dropped".to_string()))
    }
}

// ---------------------------------------------------------------------------
// Helper: validate user_identity and register user
// ---------------------------------------------------------------------------

/// Validate the `user_identity` field from an `OpenStandardMiningChannel`
/// message and register the user in the share chain store.
///
/// This mirrors the SV1 `mining.authorize` flow:
/// 1. Parse `user_identity` as UTF-8
/// 2. Validate as `<btc_address>[.<worker_name>]` via `validate_username`
/// 3. Register via `ChainStoreHandle::add_user`
///
/// Returns `(btc_address, worker_name, user_id)` on success.
pub async fn validate_and_register_user(
    user_identity: &Str0255<'_>,
    validate_addresses: bool,
    network: bitcoin::Network,
    chain_store: &crate::shares::chain::chain_store_handle::ChainStoreHandle,
) -> Result<(String, Option<String>, u64), Sv2Error> {
    // Decode user_identity as UTF-8
    let identity_bytes: &[u8] = user_identity.as_ref();
    let identity_str = std::str::from_utf8(identity_bytes)
        .map_err(|e| Sv2Error::InvalidMessage(format!("user_identity is not valid UTF-8: {e}")))?;

    // Validate using the same logic as SV1
    let (btc_address, worker_name) =
        crate::stratum::validate_username::validate(identity_str, validate_addresses, network)
            .map_err(|e| Sv2Error::InvalidMessage(format!("invalid user_identity: {e}")))?;

    // Register user in the share chain store
    let user_id = chain_store
        .add_user(btc_address.to_string())
        .await
        .map_err(|e| Sv2Error::InvalidMessage(format!("failed to register user: {e}")))?;

    debug!(
        btc_address,
        worker_name = worker_name.unwrap_or("<none>"),
        user_id,
        "SV2 user validated and registered"
    );

    Ok((
        btc_address.to_string(),
        worker_name.map(|s| s.to_string()),
        user_id,
    ))
}

/// Build an `OpenMiningChannelError` response for an invalid user identity.
pub fn build_open_channel_error(request_id: u32, reason: &str) -> OpenMiningChannelError<'static> {
    // The SV2 spec defines error codes: 'unknown-user', 'max-target-out-of-range'
    // For address validation failures, 'unknown-user' is the closest match.
    let error_code = if reason.contains("target") {
        "max-target-out-of-range"
    } else {
        "unknown-user"
    };

    OpenMiningChannelError {
        request_id,
        error_code: error_code
            .to_string()
            .try_into()
            .expect("static error code"),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: create a default target (difficulty 1 = all 0xff except first 4 bytes).
    fn default_test_target() -> [u8; 32] {
        let mut target = [0xff; 32];
        // Set a reasonable initial target (not actual difficulty 1, just for testing)
        target[0..4].copy_from_slice(&[0x00, 0x00, 0xff, 0xff]);
        target
    }

    fn make_open_channel_msg(
        request_id: u32,
        user_identity: &str,
        nominal_hash_rate: f32,
    ) -> OpenStandardMiningChannel<'static> {
        let max_target: U256<'static> = [0xff; 32]
            .to_vec()
            .try_into()
            .expect("32 bytes is valid U256");

        OpenStandardMiningChannel {
            request_id: request_id
                .to_le_bytes()
                .to_vec()
                .try_into()
                .expect("4-byte u32"),
            user_identity: user_identity.to_string().try_into().expect("valid Str0255"),
            nominal_hash_rate,
            max_target,
        }
    }

    #[tokio::test]
    async fn test_open_standard_channel() {
        let handle = start_channel_manager(0, default_test_target());

        let msg = make_open_channel_msg(1, "tb1qtest.worker1", 1_000_000.0);
        let result = handle
            .open_standard_channel(
                100,
                msg,
                "tb1qtest".to_string(),
                Some("worker1".to_string()),
                42,
            )
            .await;

        assert!(result.is_ok());
        let success = result.unwrap();
        assert_eq!(success.channel.btc_address, "tb1qtest");
        assert_eq!(success.channel.worker_name, Some("worker1".to_string()));
        assert_eq!(success.channel.user_id, 42);
        assert_eq!(success.channel.downstream_id, 100);
        assert_eq!(success.response.channel_id, success.channel.channel_id);
        assert_eq!(
            success.response.group_channel_id,
            success.channel.group_channel_id
        );
    }

    #[tokio::test]
    async fn test_multiple_channels_same_downstream() {
        let handle = start_channel_manager(0, default_test_target());
        let downstream_id: DownstreamId = 200;

        // Open two channels on the same downstream
        let msg1 = make_open_channel_msg(1, "tb1qaddr1.w1", 500_000.0);
        let r1 = handle
            .open_standard_channel(
                downstream_id,
                msg1,
                "tb1qaddr1".to_string(),
                Some("w1".to_string()),
                10,
            )
            .await
            .unwrap();

        let msg2 = make_open_channel_msg(2, "tb1qaddr2.w2", 750_000.0);
        let r2 = handle
            .open_standard_channel(
                downstream_id,
                msg2,
                "tb1qaddr2".to_string(),
                Some("w2".to_string()),
                11,
            )
            .await
            .unwrap();

        // Different channel IDs
        assert_ne!(r1.channel.channel_id, r2.channel.channel_id);
        // Same group channel (same downstream)
        assert_eq!(r1.channel.group_channel_id, r2.channel.group_channel_id);
        // Different extranonce prefixes
        assert_ne!(r1.channel.extranonce_prefix, r2.channel.extranonce_prefix);

        // Should report 2 channels for this downstream
        let channels = handle
            .get_channels_for_downstream(downstream_id)
            .await
            .unwrap();
        assert_eq!(channels.len(), 2);
        assert!(channels.contains(&r1.channel.channel_id));
        assert!(channels.contains(&r2.channel.channel_id));
    }

    #[tokio::test]
    async fn test_different_downstreams_get_different_groups() {
        let handle = start_channel_manager(0, default_test_target());

        let msg1 = make_open_channel_msg(1, "tb1qa.w1", 100.0);
        let r1 = handle
            .open_standard_channel(300, msg1, "tb1qa".to_string(), Some("w1".to_string()), 1)
            .await
            .unwrap();

        let msg2 = make_open_channel_msg(1, "tb1qb.w2", 200.0);
        let r2 = handle
            .open_standard_channel(301, msg2, "tb1qb".to_string(), Some("w2".to_string()), 2)
            .await
            .unwrap();

        // Different downstreams -> different group channels
        assert_ne!(r1.channel.group_channel_id, r2.channel.group_channel_id);
    }

    #[tokio::test]
    async fn test_remove_downstream_cleans_up_channels() {
        let handle = start_channel_manager(0, default_test_target());
        let downstream_id: DownstreamId = 400;

        let msg1 = make_open_channel_msg(1, "tb1q1", 100.0);
        let r1 = handle
            .open_standard_channel(downstream_id, msg1, "tb1q1".to_string(), None, 1)
            .await
            .unwrap();

        let msg2 = make_open_channel_msg(2, "tb1q2", 200.0);
        handle
            .open_standard_channel(downstream_id, msg2, "tb1q2".to_string(), None, 2)
            .await
            .unwrap();

        assert_eq!(handle.get_count().await.unwrap(), 2);

        // Remove the downstream
        handle.remove_downstream(downstream_id).await.unwrap();

        // All channels should be gone
        assert_eq!(handle.get_count().await.unwrap(), 0);
        assert!(
            handle
                .get_channel(r1.channel.channel_id)
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            handle
                .get_channels_for_downstream(downstream_id)
                .await
                .unwrap()
                .is_empty()
        );
    }

    #[tokio::test]
    async fn test_get_channel_by_id() {
        let handle = start_channel_manager(0, default_test_target());

        let msg = make_open_channel_msg(1, "tb1qfoo", 50_000.0);
        let result = handle
            .open_standard_channel(500, msg, "tb1qfoo".to_string(), None, 99)
            .await
            .unwrap();

        let ch = handle.get_channel(result.channel.channel_id).await.unwrap();
        assert!(ch.is_some());
        let ch = ch.unwrap();
        assert_eq!(ch.user_id, 99);
        assert_eq!(ch.btc_address, "tb1qfoo");

        // Unknown channel ID
        let missing = handle.get_channel(999_999).await.unwrap();
        assert!(missing.is_none());
    }

    #[tokio::test]
    async fn test_group_channel_id_lookup() {
        let handle = start_channel_manager(0, default_test_target());
        let downstream_id: DownstreamId = 600;

        // No group yet
        assert!(
            handle
                .get_group_channel_id(downstream_id)
                .await
                .unwrap()
                .is_none()
        );

        let msg = make_open_channel_msg(1, "tb1q", 100.0);
        let result = handle
            .open_standard_channel(downstream_id, msg, "tb1q".to_string(), None, 1)
            .await
            .unwrap();

        let gid = handle.get_group_channel_id(downstream_id).await.unwrap();
        assert_eq!(gid, Some(result.channel.group_channel_id));
    }

    #[tokio::test]
    async fn test_extranonce_prefix_uniqueness() {
        let handle = start_channel_manager(42, default_test_target());

        let mut prefixes = Vec::new();
        for i in 0..10 {
            let msg = make_open_channel_msg(i, &format!("tb1q{i}"), 100.0);
            let result = handle
                .open_standard_channel(700 + i as u64, msg, format!("tb1q{i}"), None, i as u64)
                .await
                .unwrap();
            prefixes.push(result.channel.extranonce_prefix.clone());
        }

        // All prefixes should be unique
        let unique_count = {
            let mut sorted = prefixes.clone();
            sorted.sort();
            sorted.dedup();
            sorted.len()
        };
        assert_eq!(unique_count, prefixes.len());

        // All prefixes should start with server_id = 42
        for prefix in &prefixes {
            assert_eq!(prefix.len(), 6);
            assert_eq!(&prefix[0..2], &42u16.to_be_bytes());
        }
    }

    #[test]
    fn test_build_extranonce_prefix_format() {
        let prefix = build_extranonce_prefix(0x0001, 0x00000042);
        assert_eq!(prefix.len(), 6);
        assert_eq!(prefix, vec![0x00, 0x01, 0x00, 0x00, 0x00, 0x42]);
    }

    #[test]
    fn test_build_open_channel_error_unknown_user() {
        let err = build_open_channel_error(5, "invalid address");
        assert_eq!(err.request_id, 5);
    }

    #[test]
    fn test_build_open_channel_error_target() {
        let err = build_open_channel_error(7, "max target out of range");
        assert_eq!(err.request_id, 7);
    }
}
