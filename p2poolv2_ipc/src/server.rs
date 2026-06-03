// Copyright (C) 2024-2026 P2Poolv2 Developers (see AUTHORS)
//
// This file is part of P2Poolv2 and licensed under AGPL-3.0-or-later.
// See ../Cargo.toml and the workspace `LICENSE` file for details.

//! Cap'n Proto RPC server actor for the [`ShareChain`] interface.
//!
//! Method status:
//!
//! - `validate_template` — still a placeholder stub. Needs a real
//!   `ChainStoreHandle` plumbed in plus coinbase-prefix/suffix
//!   reconstruction + wtxid-commitment validation.
//! - `submit_solution` — real `shareHash == block_hash()` consistency
//!   check. Deserialises rawBlock, recomputes the hash, rejects on
//!   mismatch. Full share-chain admission (PoW, ancestry, payout
//!   script) belongs to the eventual real ShareChain actor.
//! - `subscribe_chain_tip` — real fan-out path *if* the server is
//!   constructed with a `tokio::sync::watch::Receiver<BlockHash>`.
//!   The receiver is the integration point: the daemon publishes tip
//!   changes on the sender side; the server forwards each new value
//!   to every active callback. Without an injected receiver (e.g. in
//!   unit tests), the call is accepted and the callback is held but
//!   never fires — preserving the original stub semantics.

use std::path::{Path, PathBuf};
use std::rc::Rc;

use capnp::capability::Promise;
use capnp_rpc::{RpcSystem, rpc_twoparty_capnp, twoparty};
use p2poolv2_capnp_types::p2poolv2_capnp::{chain_tip_callback, share_chain, validation_result};
use tokio::net::UnixListener;
use tokio::sync::watch;
use tokio_util::compat::{TokioAsyncReadCompatExt, TokioAsyncWriteCompatExt};
use tracing::{debug, error, info, warn};

use crate::IpcError;

/// Server-side actor for the [`share_chain::Server`] capnp interface.
///
/// `submit_solution` performs a real shareHash↔block_hash consistency
/// check. `subscribe_chain_tip` fans out from an injected
/// `watch::Receiver<BlockHash>` when present. `validate_template`
/// remains a stub — see the module-level docs.
#[derive(Clone, Default)]
pub struct ShareChainStub {
    /// Optional tip-watch receiver. When `Some`, `subscribe_chain_tip`
    /// spawns a per-subscriber task that forwards every new value to
    /// the client-supplied callback. When `None`, the callback is
    /// accepted and held but never fires.
    tip_rx: Option<watch::Receiver<bitcoin::BlockHash>>,
}

impl ShareChainStub {
    /// Construct a new stub with no tip source. `subscribe_chain_tip`
    /// callbacks will be accepted but never fire.
    pub fn new() -> Self {
        Self::default()
    }

    /// Construct a stub that fans tip changes from `tip_rx` to every
    /// subscribed `chain_tip_callback`.
    pub fn with_tip_source(tip_rx: watch::Receiver<bitcoin::BlockHash>) -> Self {
        Self {
            tip_rx: Some(tip_rx),
        }
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
        params: share_chain::SubscribeChainTipParams,
        _results: share_chain::SubscribeChainTipResults,
    ) -> Promise<(), capnp::Error> {
        let reader = match params.get() {
            Ok(r) => r,
            Err(e) => return Promise::err(e),
        };
        let callback: chain_tip_callback::Client = match reader.get_callback() {
            Ok(c) => c,
            Err(e) => return Promise::err(e),
        };

        let Some(mut tip_rx) = self.tip_rx.clone() else {
            // No tip source wired — preserve original stub semantics:
            // accept the subscription, hold the callback for the
            // lifetime of this RPC call (it'll be dropped immediately
            // after), and never fire on_new_tip.
            debug!("ShareChainStub::subscribe_chain_tip: no tip source; accepting without firing");
            drop(callback);
            return Promise::ok(());
        };

        debug!("ShareChainStub::subscribe_chain_tip: spawning fan-out task");
        // Mark the current value as seen so we only fire on FUTURE
        // changes — exactly the "tip advanced since you subscribed"
        // semantics the engine wants. (If the engine wants the
        // current value too, it can read get_chain_tip_header
        // separately; mixing the two adds a corner case we don't
        // need.)
        tip_rx.borrow_and_update();

        // capnp-rpc::RpcSystem requires a LocalSet, which this server
        // already runs in (see run_ipc_server). spawn_local is the
        // correct fit for the !Send fan-out task.
        tokio::task::spawn_local(async move {
            // Hold the callback Client capability inside the loop so
            // it stays alive for the lifetime of the watch.
            loop {
                if tip_rx.changed().await.is_err() {
                    debug!("subscribe_chain_tip: watch sender dropped; ending fan-out");
                    return;
                }
                use bitcoin::hashes::Hash as _;
                let new_tip = *tip_rx.borrow();
                let new_tip_bytes = *new_tip.as_raw_hash().as_byte_array();
                let mut req = callback.on_new_tip_request();
                req.get().set_new_tip_hash(&new_tip_bytes);
                if let Err(e) = req.send().promise.await {
                    warn!(
                        error = %e,
                        "subscribe_chain_tip: callback errored; ending fan-out"
                    );
                    return;
                }
            }
        });

        Promise::ok(())
    }
}

/// Bind a Unix socket at `path` and run the IPC server until the socket
/// errors or the future is cancelled.
///
/// The server bootstraps a [`ShareChainStub`] for every accepted
/// connection. Pass `tip_rx = None` for the no-tip-source mode (current
/// stub semantics: subscribe_chain_tip accepts the callback but never
/// fires); pass `Some(rx)` once the daemon has a tip-broadcast wired up.
///
/// **Note:** must be polled inside a `tokio::task::LocalSet` because
/// `capnp-rpc::RpcSystem` is `!Send`. Use [`spawn_ipc_server`] for the
/// usual case where the host runtime is multi-threaded.
pub async fn run_ipc_server(
    path: impl AsRef<Path>,
    tip_rx: Option<watch::Receiver<bitcoin::BlockHash>>,
) -> Result<(), IpcError> {
    let path = path.as_ref();
    // Best-effort cleanup of any stale socket from a prior crash.
    let _ = std::fs::remove_file(path);

    let listener = UnixListener::bind(path).map_err(|source| IpcError::BindFailed {
        path: path.to_path_buf(),
        source,
    })?;
    info!(
        socket = %path.display(),
        tip_source = tip_rx.is_some(),
        "p2poolv2 IPC server listening"
    );

    loop {
        let (stream, _addr) = match listener.accept().await {
            Ok(pair) => pair,
            Err(e) => {
                error!("IPC accept failed: {e}");
                return Err(IpcError::Io(e));
            }
        };
        debug!("Accepted IPC client connection");

        let stub = match tip_rx.clone() {
            Some(rx) => ShareChainStub::with_tip_source(rx),
            None => ShareChainStub::new(),
        };
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
    spawn_ipc_server_with_tip_source(path, None)
}

/// Variant of [`spawn_ipc_server`] that wires a tip-watch receiver
/// into every accepted connection. The daemon publishes tip changes
/// on the sender side; subscribed clients receive `on_new_tip`
/// callbacks for each new value.
pub fn spawn_ipc_server_with_tip_source(
    path: impl Into<PathBuf>,
    tip_rx: Option<watch::Receiver<bitcoin::BlockHash>>,
) -> std::thread::JoinHandle<()> {
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
                if let Err(e) = run_ipc_server(&path, tip_rx).await {
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

    /// subscribe_chain_tip with an injected tip source: a watch::send()
    /// must result in the client-side callback firing with the new
    /// hash. The whole fan-out path runs inside a LocalSet (capnp-rpc
    /// is !Send).
    #[test]
    fn subscribe_chain_tip_fans_out_watch_changes_to_callback() {
        use std::cell::RefCell;
        use std::time::Duration;

        use bitcoin::hashes::Hash as _;

        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("rt");
        let local = tokio::task::LocalSet::new();

        local.block_on(&rt, async {
            let initial = bitcoin::BlockHash::from_raw_hash(bitcoin::hashes::Hash::all_zeros());
            let (tip_tx, tip_rx) = watch::channel(initial);
            let stub: share_chain::Client =
                capnp_rpc::new_client(ShareChainStub::with_tip_source(tip_rx));

            let received: Rc<RefCell<Vec<[u8; 32]>>> = Rc::new(RefCell::new(Vec::new()));
            struct RecordingCallback {
                received: Rc<RefCell<Vec<[u8; 32]>>>,
            }
            impl chain_tip_callback::Server for RecordingCallback {
                #[allow(refining_impl_trait)]
                fn on_new_tip(
                    self: Rc<Self>,
                    params: chain_tip_callback::OnNewTipParams,
                    _results: chain_tip_callback::OnNewTipResults,
                ) -> Promise<(), capnp::Error> {
                    let reader = match params.get() {
                        Ok(r) => r,
                        Err(e) => return Promise::err(e),
                    };
                    let bytes = match reader.get_new_tip_hash() {
                        Ok(b) => b,
                        Err(e) => return Promise::err(e),
                    };
                    if bytes.len() != 32 {
                        return Promise::err(capnp::Error::failed("hash length".into()));
                    }
                    let mut arr = [0u8; 32];
                    arr.copy_from_slice(bytes);
                    self.received.borrow_mut().push(arr);
                    Promise::ok(())
                }
            }
            let cb_client: chain_tip_callback::Client = capnp_rpc::new_client(RecordingCallback {
                received: Rc::clone(&received),
            });

            let mut req = stub.subscribe_chain_tip_request();
            req.get().set_callback(cb_client);
            req.send().promise.await.expect("subscribe ok");

            let mk_tip = |last: u8| {
                let mut h = [0u8; 32];
                h[31] = last;
                bitcoin::BlockHash::from_raw_hash(bitcoin::hashes::sha256d::Hash::from_byte_array(
                    h,
                ))
            };
            let tip_a = mk_tip(0xaa);
            let tip_b = mk_tip(0xbb);
            let want_a = *tip_a.as_raw_hash().as_byte_array();
            let want_b = *tip_b.as_raw_hash().as_byte_array();

            // Push tip_a, then drive the runtime until the fan-out
            // task has observed and dispatched it. tokio::sync::watch
            // collapses unread updates, so without the wait the
            // receiver may only see tip_b.
            tip_tx.send(tip_a).expect("send a");
            let mut got_a = false;
            for _ in 0..200 {
                tokio::task::yield_now().await;
                if received.borrow().contains(&want_a) {
                    got_a = true;
                    break;
                }
                tokio::time::sleep(Duration::from_millis(2)).await;
            }
            assert!(got_a, "tip_a never delivered; got {:x?}", received.borrow());

            tip_tx.send(tip_b).expect("send b");
            let mut got_b = false;
            for _ in 0..200 {
                tokio::task::yield_now().await;
                if received.borrow().contains(&want_b) {
                    got_b = true;
                    break;
                }
                tokio::time::sleep(Duration::from_millis(2)).await;
            }
            assert!(got_b, "tip_b never delivered; got {:x?}", received.borrow());
        });
    }
}
