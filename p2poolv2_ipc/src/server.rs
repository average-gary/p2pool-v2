// Copyright (C) 2024-2026 P2Poolv2 Developers (see AUTHORS)
//
// This file is part of P2Poolv2 and licensed under AGPL-3.0-or-later.
// See ../Cargo.toml and the workspace `LICENSE` file for details.

//! Cap'n Proto RPC server actor for the [`ShareChain`] interface.
//!
//! `validate_template` and `subscribe_chain_tip` are still placeholder
//! stubs (they need a real `ChainStoreHandle` plumbed in, plus —
//! for tip subscription — a tip-change broadcast channel inside
//! `p2poolv2_lib::shares::chain` that does not yet exist). They will
//! be wired in follow-up PRs.
//!
//! `submit_solution` performs a real consistency check: it
//! deserialises the raw block, recomputes its `block_hash()`, and
//! verifies that matches the `shareHash` the client sent. A mismatch
//! is a client bug (the share hash is the block hash, by the wire
//! contract) and the call is rejected. Full share-chain admission
//! (PoW threshold, ancestry walk, payout-script validation) still
//! belongs to the eventual `ShareChain` actor.

use std::path::{Path, PathBuf};
use std::rc::Rc;

use capnp::capability::Promise;
use capnp_rpc::{RpcSystem, rpc_twoparty_capnp, twoparty};
use p2poolv2_capnp_types::p2poolv2_capnp::{share_chain, validation_result};
use tokio::net::UnixListener;
use tokio_util::compat::{TokioAsyncReadCompatExt, TokioAsyncWriteCompatExt};
use tracing::{debug, error, info, warn};

use crate::IpcError;

/// Server-side actor for the [`share_chain::Server`] capnp interface.
///
/// `submit_solution` performs a real shareHash↔block_hash consistency
/// check. `validate_template` and `subscribe_chain_tip` remain stubs —
/// see the module-level docs.
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
        params: share_chain::SubmitSolutionParams,
        mut results: share_chain::SubmitSolutionResults,
    ) -> Promise<(), capnp::Error> {
        // Real consistency check: deserialize rawBlock, compute its
        // block_hash, and verify it matches shareHash. A mismatch
        // indicates a buggy client (the share hash MUST be the block
        // hash; that's the wire contract).
        //
        // Full share-chain admission (PoW threshold, ancestry, payout
        // script) still belongs to the eventual real ShareChain actor;
        // this method shifts from "always accept" to "accept iff the
        // client's claim matches the bytes they sent."
        let reader = match params.get() {
            Ok(r) => r,
            Err(e) => {
                warn!("submit_solution: invalid params: {e}");
                results.get().set_accepted(false);
                return Promise::ok(());
            }
        };
        let raw_block = match reader.get_raw_block() {
            Ok(d) => d,
            Err(e) => {
                warn!("submit_solution: missing rawBlock: {e}");
                results.get().set_accepted(false);
                return Promise::ok(());
            }
        };
        let claimed_share_hash = match reader.get_share_hash() {
            Ok(d) => d,
            Err(e) => {
                warn!("submit_solution: missing shareHash: {e}");
                results.get().set_accepted(false);
                return Promise::ok(());
            }
        };
        let block: bitcoin::Block = match bitcoin::consensus::deserialize(raw_block) {
            Ok(b) => b,
            Err(e) => {
                warn!("submit_solution: rawBlock deserialize failed: {e}");
                results.get().set_accepted(false);
                return Promise::ok(());
            }
        };
        use bitcoin::hashes::Hash as _;
        let computed = *block.block_hash().as_raw_hash().as_byte_array();
        if claimed_share_hash != computed {
            warn!(
                "submit_solution: shareHash {:x?} does not match block_hash {:x?}; rejecting",
                claimed_share_hash, computed,
            );
            results.get().set_accepted(false);
            return Promise::ok(());
        }
        debug!(
            block_hash = %block.block_hash(),
            txdata_len = block.txdata.len(),
            "submit_solution: shareHash == block_hash; accepted",
        );
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

    /// End-to-end of the submit_solution check: drive a stub directly
    /// through the capnp RPC layer locally (no UDS), feed it a known
    /// block + matching shareHash, assert accepted=true; then a known
    /// block + WRONG shareHash, assert accepted=false.
    #[tokio::test(flavor = "current_thread")]
    async fn submit_solution_accepts_when_share_hash_matches_block_hash() {
        use bitcoin::hashes::Hash as _;
        let block = bitcoin::Block {
            header: bitcoin::blockdata::block::Header {
                version: bitcoin::blockdata::block::Version::from_consensus(1),
                prev_blockhash: bitcoin::BlockHash::from_raw_hash(
                    bitcoin::hashes::Hash::all_zeros(),
                ),
                merkle_root: bitcoin::TxMerkleNode::from_raw_hash(
                    bitcoin::hashes::Hash::all_zeros(),
                ),
                time: 1_700_000_000,
                bits: bitcoin::CompactTarget::from_consensus(0x207fffff),
                nonce: 42,
            },
            txdata: vec![],
        };
        let raw = bitcoin::consensus::serialize(&block);
        let block_hash = *block.block_hash().as_raw_hash().as_byte_array();

        let stub: share_chain::Client = capnp_rpc::new_client(ShareChainStub::new());

        // Matching shareHash → accepted.
        let mut req = stub.submit_solution_request();
        {
            let mut params = req.get();
            params.set_raw_block(&raw);
            params.set_share_hash(&block_hash);
        }
        let reply = req.send().promise.await.expect("rpc ok");
        assert!(reply.get().expect("reader").get_accepted());

        // Wrong shareHash → rejected.
        let mut bad_share = block_hash;
        bad_share[0] ^= 0xff;
        let mut req2 = stub.submit_solution_request();
        {
            let mut params = req2.get();
            params.set_raw_block(&raw);
            params.set_share_hash(&bad_share);
        }
        let reply2 = req2.send().promise.await.expect("rpc ok");
        assert!(!reply2.get().expect("reader").get_accepted());
    }

    /// Garbage rawBlock bytes → rejected (deserialize failure).
    #[tokio::test(flavor = "current_thread")]
    async fn submit_solution_rejects_unparseable_raw_block() {
        let stub: share_chain::Client = capnp_rpc::new_client(ShareChainStub::new());
        let mut req = stub.submit_solution_request();
        {
            let mut params = req.get();
            params.set_raw_block(b"not a block");
            params.set_share_hash(&[0u8; 32]);
        }
        let reply = req.send().promise.await.expect("rpc ok");
        assert!(!reply.get().expect("reader").get_accepted());
    }
}
