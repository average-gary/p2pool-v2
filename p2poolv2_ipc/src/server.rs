// Copyright (C) 2024-2026 P2Poolv2 Developers (see AUTHORS)
//
// This file is part of P2Poolv2 and licensed under AGPL-3.0-or-later.
// See ../Cargo.toml and the workspace `LICENSE` file for details.

//! Cap'n Proto RPC server actor for the [`ShareChain`] interface.
//!
//! Phase-2 stub. Each method returns a placeholder response so that
//! external clients (notably the sv2-p2pool integration crate) can be
//! developed against a real Unix-socket endpoint while the share-chain
//! wiring is implemented in a follow-up PR.

use std::path::{Path, PathBuf};
use std::rc::Rc;

use capnp::capability::Promise;
use capnp_rpc::{RpcSystem, rpc_twoparty_capnp, twoparty};
use p2poolv2_capnp_types::p2poolv2_capnp::{share_chain, validation_result};
use tokio::net::UnixListener;
use tokio_util::compat::{TokioAsyncReadCompatExt, TokioAsyncWriteCompatExt};
use tracing::{debug, error, info, warn};

use crate::IpcError;

/// Stub implementation of the [`share_chain::Server`] capnp interface.
///
/// All methods return placeholder responses. Real wiring to
/// `p2poolv2_lib::shares::chain` is intentionally deferred — see the
/// crate-level docs and the sv2-p2pool integration plan §4.4.
#[derive(Clone, Default)]
pub struct ShareChainStub;

impl ShareChainStub {
    /// Construct a new stub.
    pub fn new() -> Self {
        Self
    }
}

impl share_chain::Server for ShareChainStub {
    // The capnp-rpc generated trait now uses `impl Future` return types
    // on nightly-ish toolchains; we keep the stable `Promise` shape on
    // purpose because it round-trips through `Promise::ok` cleanly.
    #[allow(refining_impl_trait)]
    fn validate_template(
        self: Rc<Self>,
        _params: share_chain::ValidateTemplateParams,
        mut results: share_chain::ValidateTemplateResults,
    ) -> Promise<(), capnp::Error> {
        debug!("ShareChainStub::validate_template called (stub)");
        // Stub: always report `ok`. Real implementation will validate
        // coinbase prefix/suffix against the share-chain tip and the
        // wtxid commitment, returning structured failure variants.
        let mut result: validation_result::Builder = results.get().init_result();
        result.set_ok(());
        Promise::ok(())
    }

    #[allow(refining_impl_trait)]
    fn submit_solution(
        self: Rc<Self>,
        _params: share_chain::SubmitSolutionParams,
        mut results: share_chain::SubmitSolutionResults,
    ) -> Promise<(), capnp::Error> {
        debug!("ShareChainStub::submit_solution called (stub)");
        // Stub: always report `accepted = true`. Real implementation
        // will deserialize the raw block, run share validation, and
        // either route to the bitcoind submitblock path or reject.
        results.get().set_accepted(true);
        Promise::ok(())
    }

    #[allow(refining_impl_trait)]
    fn subscribe_chain_tip(
        self: Rc<Self>,
        _params: share_chain::SubscribeChainTipParams,
        _results: share_chain::SubscribeChainTipResults,
    ) -> Promise<(), capnp::Error> {
        debug!("ShareChainStub::subscribe_chain_tip called (stub)");
        // Stub: accept the subscription and drop the callback. Real
        // implementation will retain the callback and invoke
        // `on_new_tip` whenever the share-chain tip advances.
        Promise::ok(())
    }
}

/// Bind a Unix socket at `path` and run the IPC server until the socket
/// errors or the future is cancelled.
///
/// The server bootstraps a [`ShareChainStub`] for every accepted
/// connection. This is a Phase-2 stub; future revisions will accept a
/// real handle to the running share-chain actor.
///
/// **Note:** must be polled inside a `tokio::task::LocalSet` because
/// `capnp-rpc::RpcSystem` is `!Send`. Use [`spawn_ipc_server`] for the
/// usual case where the host runtime is multi-threaded.
pub async fn run_ipc_server(path: impl AsRef<Path>) -> Result<(), IpcError> {
    let path = path.as_ref();
    // Best-effort cleanup of any stale socket from a prior crash.
    let _ = std::fs::remove_file(path);

    let listener = UnixListener::bind(path).map_err(|source| IpcError::BindFailed {
        path: path.to_path_buf(),
        source,
    })?;
    info!(socket = %path.display(), "p2poolv2 IPC server listening (stub)");

    loop {
        let (stream, _addr) = match listener.accept().await {
            Ok(pair) => pair,
            Err(e) => {
                error!("IPC accept failed: {e}");
                return Err(IpcError::Io(e));
            }
        };
        debug!("Accepted IPC client connection");

        let stub = ShareChainStub::new();
        let client: share_chain::Client = capnp_rpc::new_client(stub);

        // capnp-rpc requires a single-threaded runtime; spawn each
        // connection on the current LocalSet.
        tokio::task::spawn_local(async move {
            if let Err(e) = serve_connection(stream, client).await {
                warn!("IPC connection ended with error: {e}");
            }
        });
    }
}

async fn serve_connection(
    stream: tokio::net::UnixStream,
    bootstrap: share_chain::Client,
) -> Result<(), capnp::Error> {
    let (reader, writer) = stream.into_split();
    let reader = reader.compat();
    let writer = writer.compat_write();

    let network = twoparty::VatNetwork::new(
        reader,
        writer,
        rpc_twoparty_capnp::Side::Server,
        Default::default(),
    );
    let rpc_system = RpcSystem::new(Box::new(network), Some(bootstrap.client));
    rpc_system.await
}

/// Convenience wrapper that spawns [`run_ipc_server`] inside a
/// `tokio::task::LocalSet` on its own dedicated thread.
///
/// This is the simplest way to mount the IPC server inside a node that
/// is otherwise multi-threaded — `capnp-rpc`'s `RpcSystem` is `!Send`
/// and must run on a `LocalSet`.
pub fn spawn_ipc_server(path: impl Into<PathBuf>) -> std::thread::JoinHandle<()> {
    let path = path.into();
    std::thread::Builder::new()
        .name("p2poolv2-ipc".into())
        .spawn(move || {
            let rt = match tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            {
                Ok(rt) => rt,
                Err(e) => {
                    error!("failed to build IPC runtime: {e}");
                    return;
                }
            };
            let local = tokio::task::LocalSet::new();
            local.block_on(&rt, async move {
                if let Err(e) = run_ipc_server(&path).await {
                    error!("IPC server exited: {e}");
                }
            });
        })
        .expect("spawning p2poolv2-ipc thread")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stub_constructs() {
        let _stub = ShareChainStub::new();
    }
}
