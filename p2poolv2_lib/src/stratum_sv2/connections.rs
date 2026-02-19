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

//! SV2 connection registry actor.
//!
//! Tracks all active SV2 downstream connections and provides methods for
//! broadcasting messages and targeted sends. Mirrors the pattern used by
//! the SV1 [`crate::stratum::client_connections::ClientConnectionsHandle`]
//! but sends binary SV2 frames instead of JSON strings.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;

use tokio::sync::{mpsc, oneshot};
use tracing::{debug, trace, warn};

use super::connection::DownstreamId;

/// Size of the per-connection outbound message buffer.
const CONNECTION_MSG_BUFFER: usize = 128;

/// A connected SV2 downstream.
pub struct Sv2Downstream {
    /// Channel to send encoded binary frames to this connection's writer task.
    pub message_tx: mpsc::Sender<Arc<Vec<u8>>>,
    /// Signal to shut down this connection.
    pub shutdown_tx: oneshot::Sender<()>,
    /// Remote socket address.
    pub addr: SocketAddr,
    /// When the connection was established.
    pub connected_at: Instant,
    /// Whether SetupConnection has been completed.
    pub setup_complete: bool,
}

/// Commands sent to the connection registry actor.
enum RegistryCmd {
    Add {
        downstream_id: DownstreamId,
        downstream: Sv2Downstream,
    },
    Remove {
        downstream_id: DownstreamId,
    },
    SendToAll {
        message: Arc<Vec<u8>>,
    },
    SendToDownstream {
        downstream_id: DownstreamId,
        message: Arc<Vec<u8>>,
        reply: oneshot::Sender<bool>,
    },
    GetCount {
        reply: oneshot::Sender<usize>,
    },
}

/// Clonable handle to the SV2 connection registry actor.
#[derive(Clone)]
pub struct Sv2ConnectionsHandle {
    cmd_tx: mpsc::Sender<RegistryCmd>,
}

impl Sv2ConnectionsHandle {
    /// Register a new SV2 downstream connection.
    /// Returns a receiver for outbound messages and a shutdown receiver.
    pub async fn add(
        &self,
        downstream_id: DownstreamId,
        addr: SocketAddr,
    ) -> (mpsc::Receiver<Arc<Vec<u8>>>, oneshot::Receiver<()>) {
        let (message_tx, message_rx) = mpsc::channel(CONNECTION_MSG_BUFFER);
        let (shutdown_tx, shutdown_rx) = oneshot::channel();

        let downstream = Sv2Downstream {
            message_tx,
            shutdown_tx,
            addr,
            connected_at: Instant::now(),
            setup_complete: false,
        };

        let _ = self
            .cmd_tx
            .send(RegistryCmd::Add {
                downstream_id,
                downstream,
            })
            .await;

        (message_rx, shutdown_rx)
    }

    /// Remove a downstream connection from the registry.
    pub async fn remove(&self, downstream_id: DownstreamId) {
        let _ = self
            .cmd_tx
            .send(RegistryCmd::Remove { downstream_id })
            .await;
    }

    /// Broadcast a binary message to all connected downstreams.
    /// Non-blocking: connections that can't accept the message are auto-removed.
    pub async fn send_to_all(&self, message: Arc<Vec<u8>>) {
        let _ = self.cmd_tx.send(RegistryCmd::SendToAll { message }).await;
    }

    /// Send a binary message to a specific downstream.
    /// Returns true if the message was queued, false if the connection was not found or full.
    pub async fn send_to_downstream(
        &self,
        downstream_id: DownstreamId,
        message: Arc<Vec<u8>>,
    ) -> bool {
        let (reply_tx, reply_rx) = oneshot::channel();
        let _ = self
            .cmd_tx
            .send(RegistryCmd::SendToDownstream {
                downstream_id,
                message,
                reply: reply_tx,
            })
            .await;
        reply_rx.await.unwrap_or(false)
    }

    /// Get the number of active connections.
    pub async fn get_count(&self) -> usize {
        let (reply_tx, reply_rx) = oneshot::channel();
        let _ = self
            .cmd_tx
            .send(RegistryCmd::GetCount { reply: reply_tx })
            .await;
        reply_rx.await.unwrap_or(0)
    }
}

/// Internal state of the connection registry actor.
struct Sv2Connections {
    connections: HashMap<DownstreamId, Sv2Downstream>,
}

impl Sv2Connections {
    fn new() -> Self {
        Self {
            connections: HashMap::new(),
        }
    }

    fn add(&mut self, downstream_id: DownstreamId, downstream: Sv2Downstream) {
        debug!(
            downstream_id,
            addr = %downstream.addr,
            "SV2 downstream registered"
        );
        self.connections.insert(downstream_id, downstream);
    }

    fn remove(&mut self, downstream_id: DownstreamId) {
        if let Some(downstream) = self.connections.remove(&downstream_id) {
            debug!(
                downstream_id,
                addr = %downstream.addr,
                "SV2 downstream removed"
            );
            // Signal the connection's writer task to shut down
            let _ = downstream.shutdown_tx.send(());
        }
    }

    fn send_to_all(&mut self, message: Arc<Vec<u8>>) {
        let mut failed = Vec::new();
        for (&id, downstream) in &self.connections {
            if downstream.message_tx.try_send(message.clone()).is_err() {
                failed.push(id);
            }
        }
        for id in failed {
            warn!(downstream_id = id, "SV2 downstream send failed, removing");
            self.remove(id);
        }
    }

    fn send_to_downstream(&mut self, downstream_id: DownstreamId, message: Arc<Vec<u8>>) -> bool {
        if let Some(downstream) = self.connections.get(&downstream_id) {
            match downstream.message_tx.try_send(message) {
                Ok(()) => true,
                Err(_) => {
                    warn!(downstream_id, "SV2 downstream send failed, removing");
                    self.remove(downstream_id);
                    false
                }
            }
        } else {
            trace!(downstream_id, "SV2 downstream not found for targeted send");
            false
        }
    }

    fn count(&self) -> usize {
        self.connections.len()
    }
}

/// Start the SV2 connections registry actor.
///
/// Returns a clonable handle for interacting with the registry.
pub async fn start_sv2_connections_handler() -> Sv2ConnectionsHandle {
    let (cmd_tx, mut cmd_rx) = mpsc::channel::<RegistryCmd>(256);

    tokio::spawn(async move {
        let mut registry = Sv2Connections::new();

        while let Some(cmd) = cmd_rx.recv().await {
            match cmd {
                RegistryCmd::Add {
                    downstream_id,
                    downstream,
                } => {
                    registry.add(downstream_id, downstream);
                }
                RegistryCmd::Remove { downstream_id } => {
                    registry.remove(downstream_id);
                }
                RegistryCmd::SendToAll { message } => {
                    registry.send_to_all(message);
                }
                RegistryCmd::SendToDownstream {
                    downstream_id,
                    message,
                    reply,
                } => {
                    let ok = registry.send_to_downstream(downstream_id, message);
                    let _ = reply.send(ok);
                }
                RegistryCmd::GetCount { reply } => {
                    let _ = reply.send(registry.count());
                }
            }
        }
    });

    Sv2ConnectionsHandle { cmd_tx }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_registry_add_and_count() {
        let handle = start_sv2_connections_handler().await;
        let addr: SocketAddr = "127.0.0.1:12345".parse().unwrap();

        let (_msg_rx, _shutdown_rx) = handle.add(1, addr).await;
        assert_eq!(handle.get_count().await, 1);

        let (_msg_rx2, _shutdown_rx2) = handle.add(2, addr).await;
        assert_eq!(handle.get_count().await, 2);
    }

    #[tokio::test]
    async fn test_registry_remove() {
        let handle = start_sv2_connections_handler().await;
        let addr: SocketAddr = "127.0.0.1:12345".parse().unwrap();

        let (_msg_rx, _shutdown_rx) = handle.add(1, addr).await;
        assert_eq!(handle.get_count().await, 1);

        handle.remove(1).await;
        assert_eq!(handle.get_count().await, 0);
    }

    #[tokio::test]
    async fn test_registry_send_to_downstream() {
        let handle = start_sv2_connections_handler().await;
        let addr: SocketAddr = "127.0.0.1:12345".parse().unwrap();

        let (mut msg_rx, _shutdown_rx) = handle.add(1, addr).await;

        let msg = Arc::new(vec![1, 2, 3]);
        let ok = handle.send_to_downstream(1, msg.clone()).await;
        assert!(ok);

        let received = msg_rx.recv().await.unwrap();
        assert_eq!(&*received, &[1, 2, 3]);
    }

    #[tokio::test]
    async fn test_registry_send_to_unknown_downstream() {
        let handle = start_sv2_connections_handler().await;
        let msg = Arc::new(vec![1, 2, 3]);
        let ok = handle.send_to_downstream(999, msg).await;
        assert!(!ok);
    }

    #[tokio::test]
    async fn test_registry_send_to_all() {
        let handle = start_sv2_connections_handler().await;
        let addr: SocketAddr = "127.0.0.1:12345".parse().unwrap();

        let (mut msg_rx1, _s1) = handle.add(1, addr).await;
        let (mut msg_rx2, _s2) = handle.add(2, addr).await;

        let msg = Arc::new(vec![4, 5, 6]);
        handle.send_to_all(msg).await;

        let r1 = msg_rx1.recv().await.unwrap();
        let r2 = msg_rx2.recv().await.unwrap();
        assert_eq!(&*r1, &[4, 5, 6]);
        assert_eq!(&*r2, &[4, 5, 6]);
    }

    #[tokio::test]
    async fn test_registry_auto_remove_on_failed_send() {
        let handle = start_sv2_connections_handler().await;
        let addr: SocketAddr = "127.0.0.1:12345".parse().unwrap();

        let (msg_rx, _s) = handle.add(1, addr).await;
        // Drop the receiver to simulate a disconnected client
        drop(msg_rx);

        // Give the actor a moment to process
        tokio::task::yield_now().await;

        let msg = Arc::new(vec![7, 8, 9]);
        handle.send_to_all(msg).await;

        // The failed send should have auto-removed the connection
        // Give the actor time to process
        tokio::task::yield_now().await;
        assert_eq!(handle.get_count().await, 0);
    }
}
