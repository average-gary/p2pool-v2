// Copyright (C) 2024-2026 P2Poolv2 Developers (see AUTHORS)
//
// This file is part of P2Poolv2
//
// P2Poolv2 is free software: you can redistribute it and/or modify it under
// the terms of the GNU Affero General Public License as published by the Free
// Software Foundation, either version 3 of the License, or (at your option)
// any later version.
//
// P2Poolv2 is distributed in the hope that it will be useful, but WITHOUT ANY
// WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
// FOR A PARTICULAR PURPOSE. See the GNU Affero General Public License for more
// details.
//
// You should have received a copy of the GNU Affero General Public License
// along with P2Poolv2. If not, see <https://www.gnu.org/licenses/>.

//! Cap'n Proto IPC server exposing the p2poolv2 [`ShareChain`] interface.
//!
//! This crate is the server-side counterpart of [`p2poolv2-capnp-types`]
//! (which carries the schema). It listens on a Unix socket and wires
//! incoming Cap'n Proto RPC calls to a [`ShareChain`] implementation.
//!
//! # Status: partial real wiring
//!
//! - `submit_solution` performs a real shareHash↔block_hash consistency
//!   check; mismatches are rejected.
//! - `subscribe_chain_tip` fans out tip changes from a
//!   `tokio::sync::watch` receiver injected via
//!   [`spawn_ipc_server_with_tip_source`]. With no receiver wired
//!   (default), it preserves the original stub behaviour: subscriptions
//!   are accepted but never fire.
//! - `validate_template` is still a placeholder stub.
//!
//! See ADR 0010 in the sv2-p2pool repo for the rollout plan.
//!
//! [`p2poolv2-capnp-types`]: ../p2poolv2_capnp_types/index.html
//! [`ShareChain`]: p2poolv2_capnp_types::p2poolv2_capnp::share_chain

pub mod server;

pub use server::{
    ChainReadBackend, ShareChainStub, ShareHeaderOutcome, run_ipc_server, run_ipc_server_with,
    spawn_ipc_server, spawn_ipc_server_full, spawn_ipc_server_with_tip_source,
};

/// Errors emitted by the IPC server.
#[derive(Debug, thiserror::Error)]
pub enum IpcError {
    /// The configured Unix socket path could not be bound.
    #[error("failed to bind Unix socket {path:?}: {source}")]
    BindFailed {
        path: std::path::PathBuf,
        #[source]
        source: std::io::Error,
    },
    /// An accept loop I/O error.
    #[error("accept loop I/O error: {0}")]
    Io(#[from] std::io::Error),
    /// A Cap'n Proto RPC error.
    #[error("capnp error: {0}")]
    Capnp(#[from] capnp::Error),
}
