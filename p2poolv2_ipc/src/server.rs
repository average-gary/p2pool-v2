// Copyright (C) 2024-2026 P2Poolv2 Developers (see AUTHORS)
//
// This file is part of P2Poolv2 and licensed under AGPL-3.0-or-later.
// See ../Cargo.toml and the workspace `LICENSE` file for details.

//! Cap'n Proto RPC server actor for the [`ShareChain`] interface.
//!
//! Method status:
//!
//! - `validate_template` — structural pre-check only. Glues
//!   prefix+suffix and confirms the coinbase parses as a
//!   `bitcoin::Transaction`; on parse failure returns
//!   `InvalidCoinbase(<reason>)`, otherwise returns `Ok`. Full
//!   share-chain admission (coinbase value, wtxid commitment against
//!   the share-chain tip) still needs a `ChainStoreHandle` plumbed in.
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
use std::sync::Arc;

use capnp::capability::Promise;
use capnp_rpc::{RpcSystem, rpc_twoparty_capnp, twoparty};
use p2poolv2_capnp_types::p2poolv2_capnp::{
    chain_tip_callback, chain_tip_result, network_result, share_chain, share_header_result,
    tip_height_result, validation_result,
};
use tokio::net::UnixListener;
use tokio::sync::watch;
use tokio_util::compat::{TokioAsyncReadCompatExt, TokioAsyncWriteCompatExt};
use tracing::{debug, error, info, warn};

use crate::IpcError;

/// Outcome of a `get_share_header` lookup on the daemon side.
///
/// Mirrors the discriminated union in the capnp schema so the
/// server can return "found", "missing", or the all-zeros genesis
/// sentinel without overloading `capnp::Error`.
#[derive(Debug, Clone)]
pub enum ShareHeaderOutcome {
    /// Header was found; carries the minimal subset the engine reads.
    Found {
        /// 32-byte previous share blockhash.
        prev_share_blockhash: [u8; 32],
    },
    /// No header for the requested share hash.
    NotFound,
    /// The requested hash is the all-zeros genesis sentinel.
    Genesis,
}

/// Server-side adapter for chain-state reads.
///
/// The IPC crate is intentionally light on dependencies: the
/// p2poolv2 daemon owns the real `ChainStoreHandle` (which lives
/// in `p2poolv2_lib`) and implements this trait for it. Tests in
/// this crate use a small in-memory fake.
///
/// All methods are sync because `ChainStoreHandle` itself is sync;
/// the capnp server runs them inline on its current-thread runtime.
/// Errors are reported as a `String` reason which is mapped to
/// `capnp::Error::failed` at the wire layer.
pub trait ChainReadBackend: Send + Sync {
    /// Return the confirmed-chain tip blockhash, or `None` when no
    /// genesis is set up yet.
    fn get_chain_tip(&self) -> Result<Option<[u8; 32]>, String>;

    /// Return the share-header lookup outcome for `share_hash`.
    fn get_share_header(&self, share_hash: &[u8; 32]) -> Result<ShareHeaderOutcome, String>;

    /// Return the confirmed-chain tip height, or `None` when no
    /// genesis is set up yet.
    fn get_tip_height(&self) -> Result<Option<u32>, String>;

    /// Return the bitcoin network the daemon was configured with.
    fn network(&self) -> bitcoin::Network;
}

/// Server-side actor for the [`share_chain::Server`] capnp interface.
///
/// - `validate_template` — structural pre-check (coinbase parses).
/// - `submit_solution` — real `shareHash == block_hash()` consistency
///   check.
/// - `subscribe_chain_tip` — fans out from an injected
///   `watch::Receiver<BlockHash>` when present.
///
/// See the module-level docs for the gap between this and a full
/// share-chain admission implementation.
#[derive(Clone, Default)]
pub struct ShareChainStub {
    /// Optional tip-watch receiver. When `Some`, `subscribe_chain_tip`
    /// spawns a per-subscriber task that forwards every new value to
    /// the client-supplied callback. When `None`, the callback is
    /// accepted and held but never fires.
    tip_rx: Option<watch::Receiver<bitcoin::BlockHash>>,
    /// Optional chain-read backend. When `Some`, the chain-read
    /// methods (`get_chain_tip`, `get_share_header`, `get_tip_height`,
    /// `get_network`) delegate to this backend. When `None`, those
    /// methods return `capnp::Error::unimplemented`. The daemon wires
    /// in a real backend backed by `ChainStoreHandle`; tests that
    /// don't exercise the chain reads can leave it `None`.
    chain: Option<Arc<dyn ChainReadBackend>>,
}

impl ShareChainStub {
    /// Construct a new stub with no tip source and no chain backend.
    /// `subscribe_chain_tip` callbacks will be accepted but never
    /// fire and the chain-read methods will return `unimplemented`.
    pub fn new() -> Self {
        Self::default()
    }

    /// Construct a stub that fans tip changes from `tip_rx` to every
    /// subscribed `chain_tip_callback`.
    pub fn with_tip_source(tip_rx: watch::Receiver<bitcoin::BlockHash>) -> Self {
        Self {
            tip_rx: Some(tip_rx),
            chain: None,
        }
    }

    /// Builder: attach a chain-read backend so `get_chain_tip`,
    /// `get_share_header`, `get_tip_height`, and `get_network` can
    /// serve real data.
    pub fn with_chain_backend(mut self, chain: Arc<dyn ChainReadBackend>) -> Self {
        self.chain = Some(chain);
        self
    }
}

impl share_chain::Server for ShareChainStub {
    // The capnp-rpc generated trait now uses `impl Future` return types
    // on nightly-ish toolchains; we keep the stable `Promise` shape on
    // purpose because it round-trips through `Promise::ok` cleanly.
    #[allow(refining_impl_trait)]
    fn validate_template(
        self: Rc<Self>,
        params: share_chain::ValidateTemplateParams,
        mut results: share_chain::ValidateTemplateResults,
    ) -> Promise<(), capnp::Error> {
        // Structural pre-check: glue prefix+suffix and confirm the
        // result is a parseable bitcoin::Transaction. A real
        // share-chain admission decision (coinbase value, wtxid
        // commitment against the share-chain tip, etc.) still
        // requires a ChainStoreHandle plumbed in — see the module
        // docs. Until that lands, we filter the obviously-bad
        // (garbage prefix/suffix bytes) and accept everything else.
        let reader = match params.get() {
            Ok(r) => r,
            Err(e) => return Promise::err(e),
        };
        let prefix = match reader.get_coinbase_prefix() {
            Ok(d) => d,
            Err(e) => return Promise::err(e),
        };
        let suffix = match reader.get_coinbase_suffix() {
            Ok(d) => d,
            Err(e) => return Promise::err(e),
        };

        let mut buf = Vec::with_capacity(prefix.len() + suffix.len());
        buf.extend_from_slice(prefix);
        buf.extend_from_slice(suffix);

        let mut result: validation_result::Builder = results.get().init_result();
        match bitcoin::consensus::deserialize::<bitcoin::Transaction>(&buf) {
            Ok(_) => {
                debug!(
                    prefix_len = prefix.len(),
                    suffix_len = suffix.len(),
                    "validate_template: coinbase parses; structural check passed"
                );
                result.set_ok(());
            }
            Err(e) => {
                let reason = format!("coinbase prefix+suffix did not parse: {e}");
                warn!("validate_template: {reason}");
                result.set_invalid_coinbase(reason.as_str());
            }
        }
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

    #[allow(refining_impl_trait)]
    fn get_chain_tip(
        self: Rc<Self>,
        _params: share_chain::GetChainTipParams,
        mut results: share_chain::GetChainTipResults,
    ) -> Promise<(), capnp::Error> {
        let Some(chain) = self.chain.clone() else {
            return Promise::err(capnp::Error::unimplemented(
                "getChainTip: server has no chain-read backend wired".into(),
            ));
        };
        let mut result: chain_tip_result::Builder = results.get().init_result();
        match chain.get_chain_tip() {
            Ok(Some(hash)) => {
                result.set_tip(&hash);
            }
            Ok(None) => {
                result.set_uninitialised(());
            }
            Err(e) => {
                return Promise::err(capnp::Error::failed(format!("getChainTip: {e}")));
            }
        }
        Promise::ok(())
    }

    #[allow(refining_impl_trait)]
    fn get_share_header(
        self: Rc<Self>,
        params: share_chain::GetShareHeaderParams,
        mut results: share_chain::GetShareHeaderResults,
    ) -> Promise<(), capnp::Error> {
        let Some(chain) = self.chain.clone() else {
            return Promise::err(capnp::Error::unimplemented(
                "getShareHeader: server has no chain-read backend wired".into(),
            ));
        };
        let reader = match params.get() {
            Ok(r) => r,
            Err(e) => return Promise::err(e),
        };
        let raw = match reader.get_share_hash() {
            Ok(d) => d,
            Err(e) => return Promise::err(e),
        };
        if raw.len() != 32 {
            return Promise::err(capnp::Error::failed(format!(
                "getShareHeader: shareHash must be 32 bytes, got {}",
                raw.len()
            )));
        }
        let mut share_hash = [0u8; 32];
        share_hash.copy_from_slice(raw);

        let mut result: share_header_result::Builder = results.get().init_result();
        match chain.get_share_header(&share_hash) {
            Ok(ShareHeaderOutcome::Found {
                prev_share_blockhash,
            }) => {
                let mut found = result.init_found();
                found.set_prev_share_blockhash(&prev_share_blockhash);
            }
            Ok(ShareHeaderOutcome::NotFound) => {
                result.set_not_found(());
            }
            Ok(ShareHeaderOutcome::Genesis) => {
                result.set_genesis(());
            }
            Err(e) => {
                return Promise::err(capnp::Error::failed(format!("getShareHeader: {e}")));
            }
        }
        Promise::ok(())
    }

    #[allow(refining_impl_trait)]
    fn get_tip_height(
        self: Rc<Self>,
        _params: share_chain::GetTipHeightParams,
        mut results: share_chain::GetTipHeightResults,
    ) -> Promise<(), capnp::Error> {
        let Some(chain) = self.chain.clone() else {
            return Promise::err(capnp::Error::unimplemented(
                "getTipHeight: server has no chain-read backend wired".into(),
            ));
        };
        let mut result: tip_height_result::Builder = results.get().init_result();
        match chain.get_tip_height() {
            Ok(Some(h)) => result.set_height(h),
            Ok(None) => result.set_uninitialised(()),
            Err(e) => {
                return Promise::err(capnp::Error::failed(format!("getTipHeight: {e}")));
            }
        }
        Promise::ok(())
    }

    #[allow(refining_impl_trait)]
    fn get_network(
        self: Rc<Self>,
        _params: share_chain::GetNetworkParams,
        mut results: share_chain::GetNetworkResults,
    ) -> Promise<(), capnp::Error> {
        let Some(chain) = self.chain.clone() else {
            return Promise::err(capnp::Error::unimplemented(
                "getNetwork: server has no chain-read backend wired".into(),
            ));
        };
        let mut result: network_result::Builder = results.get().init_result();
        // bitcoin::Network is `#[non_exhaustive]` in some versions
        // and exhaustive in others; the wildcard arm is required for
        // the former and harmless (just unreachable) for the latter.
        // The schema reserves an `unknown` variant for forward-compat
        // with future bitcoin networks the schema crate doesn't yet
        // enumerate.
        #[allow(unreachable_patterns)]
        match chain.network() {
            bitcoin::Network::Bitcoin => result.set_mainnet(()),
            bitcoin::Network::Testnet => result.set_testnet(()),
            bitcoin::Network::Testnet4 => result.set_testnet4(()),
            bitcoin::Network::Regtest => result.set_regtest(()),
            bitcoin::Network::Signet => result.set_signet(()),
            _ => result.set_unknown(()),
        }
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
    run_ipc_server_with(path, tip_rx, None).await
}

/// Variant of [`run_ipc_server`] that also wires a chain-read backend
/// into every accepted connection. The chain-read methods
/// (`get_chain_tip`, `get_share_header`, `get_tip_height`,
/// `get_network`) require this backend; without it they return
/// `capnp::Error::unimplemented`.
pub async fn run_ipc_server_with(
    path: impl AsRef<Path>,
    tip_rx: Option<watch::Receiver<bitcoin::BlockHash>>,
    chain: Option<Arc<dyn ChainReadBackend>>,
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
        chain_backend = chain.is_some(),
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

        let mut stub = match tip_rx.clone() {
            Some(rx) => ShareChainStub::with_tip_source(rx),
            None => ShareChainStub::new(),
        };
        if let Some(c) = chain.clone() {
            stub = stub.with_chain_backend(c);
        }
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
    spawn_ipc_server_full(path, tip_rx, None)
}

/// Variant of [`spawn_ipc_server`] that wires both a tip-watch
/// receiver and a chain-read backend into every accepted connection.
/// The chain-read backend is required to serve the read methods
/// added in the `getChainTip` / `getShareHeader` / `getTipHeight` /
/// `getNetwork` schema additions.
pub fn spawn_ipc_server_full(
    path: impl Into<PathBuf>,
    tip_rx: Option<watch::Receiver<bitcoin::BlockHash>>,
    chain: Option<Arc<dyn ChainReadBackend>>,
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
                if let Err(e) = run_ipc_server_with(&path, tip_rx, chain).await {
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

    /// Build a real coinbase tx, split it at a chosen byte offset, and
    /// drive validate_template through the capnp client. Result must
    /// be Ok (the structural check passes a real coinbase).
    #[tokio::test(flavor = "current_thread")]
    async fn validate_template_accepts_parseable_coinbase() {
        use p2poolv2_capnp_types::p2poolv2_capnp::validation_result;

        let coinbase = bitcoin::Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![bitcoin::TxIn {
                previous_output: bitcoin::OutPoint::null(),
                script_sig: bitcoin::ScriptBuf::from_bytes(vec![0u8; 16]),
                sequence: bitcoin::Sequence::MAX,
                witness: bitcoin::Witness::new(),
            }],
            output: vec![bitcoin::TxOut {
                value: bitcoin::Amount::from_sat(50_0000_0000),
                script_pubkey: bitcoin::ScriptBuf::new(),
            }],
        };
        let serialized = bitcoin::consensus::serialize(&coinbase);
        let split = serialized.len() / 2;
        let prefix = &serialized[..split];
        let suffix = &serialized[split..];

        let stub: share_chain::Client = capnp_rpc::new_client(ShareChainStub::new());
        let mut req = stub.validate_template_request();
        {
            let mut params = req.get();
            params.set_coinbase_prefix(prefix);
            params.set_coinbase_suffix(suffix);
            params.reborrow().init_wtxid_list(0);
            params.init_missing_txs(0);
        }
        let reply = req.send().promise.await.expect("rpc ok");
        let result = reply.get().expect("reader").get_result().expect("result");
        match result.which().expect("variant known") {
            validation_result::Which::Ok(()) => {} // expected
            _ => panic!("expected Ok variant"),
        }
    }

    /// Garbage prefix+suffix bytes that cannot deserialize as a
    /// transaction. Must produce InvalidCoinbase, not Ok.
    #[tokio::test(flavor = "current_thread")]
    async fn validate_template_rejects_unparseable_coinbase() {
        use p2poolv2_capnp_types::p2poolv2_capnp::validation_result;

        let stub: share_chain::Client = capnp_rpc::new_client(ShareChainStub::new());
        let mut req = stub.validate_template_request();
        {
            let mut params = req.get();
            params.set_coinbase_prefix(b"not a");
            params.set_coinbase_suffix(b" transaction");
            params.reborrow().init_wtxid_list(0);
            params.init_missing_txs(0);
        }
        let reply = req.send().promise.await.expect("rpc ok");
        let result = reply.get().expect("reader").get_result().expect("result");
        match result.which().expect("variant known") {
            validation_result::Which::InvalidCoinbase(reader) => {
                let s = reader.expect("text").to_str().expect("utf-8");
                assert!(
                    s.contains("did not parse"),
                    "expected reason text to mention parse failure; got {s}"
                );
            }
            _ => panic!("expected InvalidCoinbase variant"),
        }
    }

    /// In-memory `ChainReadBackend` used to drive the new chain-read
    /// methods through the capnp RPC layer without standing up a real
    /// `ChainStoreHandle`.
    struct FakeChain {
        tip: Option<[u8; 32]>,
        height: Option<u32>,
        network: bitcoin::Network,
        // Map from share-hash -> prev-share-hash for known headers.
        headers: std::collections::HashMap<[u8; 32], [u8; 32]>,
    }

    impl ChainReadBackend for FakeChain {
        fn get_chain_tip(&self) -> Result<Option<[u8; 32]>, String> {
            Ok(self.tip)
        }
        fn get_share_header(&self, share_hash: &[u8; 32]) -> Result<ShareHeaderOutcome, String> {
            if share_hash.iter().all(|b| *b == 0) {
                return Ok(ShareHeaderOutcome::Genesis);
            }
            match self.headers.get(share_hash) {
                Some(prev) => Ok(ShareHeaderOutcome::Found {
                    prev_share_blockhash: *prev,
                }),
                None => Ok(ShareHeaderOutcome::NotFound),
            }
        }
        fn get_tip_height(&self) -> Result<Option<u32>, String> {
            Ok(self.height)
        }
        fn network(&self) -> bitcoin::Network {
            self.network
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn get_chain_tip_returns_tip_when_present() {
        let mut tip = [0u8; 32];
        tip[31] = 0xab;
        let chain = Arc::new(FakeChain {
            tip: Some(tip),
            height: Some(42),
            network: bitcoin::Network::Regtest,
            headers: Default::default(),
        });
        let stub: share_chain::Client =
            capnp_rpc::new_client(ShareChainStub::new().with_chain_backend(chain));

        let req = stub.get_chain_tip_request();
        let reply = req.send().promise.await.expect("rpc ok");
        let result = reply.get().expect("reader").get_result().expect("result");
        match result.which().expect("known variant") {
            chain_tip_result::Which::Tip(bytes) => {
                let bytes = bytes.expect("bytes");
                assert_eq!(bytes, &tip[..]);
            }
            _ => panic!("expected Tip variant"),
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn get_chain_tip_uninitialised_when_no_tip() {
        let chain = Arc::new(FakeChain {
            tip: None,
            height: None,
            network: bitcoin::Network::Regtest,
            headers: Default::default(),
        });
        let stub: share_chain::Client =
            capnp_rpc::new_client(ShareChainStub::new().with_chain_backend(chain));
        let reply = stub
            .get_chain_tip_request()
            .send()
            .promise
            .await
            .expect("rpc ok");
        let result = reply.get().expect("reader").get_result().expect("result");
        assert!(matches!(
            result.which().expect("known"),
            chain_tip_result::Which::Uninitialised(())
        ));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn get_share_header_genesis_for_zero_hash() {
        let chain = Arc::new(FakeChain {
            tip: None,
            height: None,
            network: bitcoin::Network::Regtest,
            headers: Default::default(),
        });
        let stub: share_chain::Client =
            capnp_rpc::new_client(ShareChainStub::new().with_chain_backend(chain));
        let mut req = stub.get_share_header_request();
        req.get().set_share_hash(&[0u8; 32]);
        let reply = req.send().promise.await.expect("rpc ok");
        let result = reply.get().expect("reader").get_result().expect("result");
        assert!(matches!(
            result.which().expect("known"),
            share_header_result::Which::Genesis(())
        ));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn get_share_header_found_returns_prev() {
        let mut h = [0u8; 32];
        h[31] = 0x11;
        let mut prev = [0u8; 32];
        prev[31] = 0x22;
        let mut headers = std::collections::HashMap::new();
        headers.insert(h, prev);
        let chain = Arc::new(FakeChain {
            tip: None,
            height: None,
            network: bitcoin::Network::Regtest,
            headers,
        });
        let stub: share_chain::Client =
            capnp_rpc::new_client(ShareChainStub::new().with_chain_backend(chain));
        let mut req = stub.get_share_header_request();
        req.get().set_share_hash(&h);
        let reply = req.send().promise.await.expect("rpc ok");
        let result = reply.get().expect("reader").get_result().expect("result");
        match result.which().expect("known") {
            share_header_result::Which::Found(reader) => {
                let r = reader.expect("found");
                let prev_bytes = r.get_prev_share_blockhash().expect("prev bytes");
                assert_eq!(prev_bytes, &prev[..]);
            }
            _ => panic!("expected Found"),
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn get_share_header_not_found_for_unknown_hash() {
        let chain = Arc::new(FakeChain {
            tip: None,
            height: None,
            network: bitcoin::Network::Regtest,
            headers: Default::default(),
        });
        let stub: share_chain::Client =
            capnp_rpc::new_client(ShareChainStub::new().with_chain_backend(chain));
        let mut req = stub.get_share_header_request();
        let mut h = [0u8; 32];
        h[0] = 0x99;
        req.get().set_share_hash(&h);
        let reply = req.send().promise.await.expect("rpc ok");
        let result = reply.get().expect("reader").get_result().expect("result");
        assert!(matches!(
            result.which().expect("known"),
            share_header_result::Which::NotFound(())
        ));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn get_tip_height_round_trips() {
        let chain = Arc::new(FakeChain {
            tip: None,
            height: Some(99),
            network: bitcoin::Network::Regtest,
            headers: Default::default(),
        });
        let stub: share_chain::Client =
            capnp_rpc::new_client(ShareChainStub::new().with_chain_backend(chain));
        let reply = stub
            .get_tip_height_request()
            .send()
            .promise
            .await
            .expect("rpc ok");
        let result = reply.get().expect("reader").get_result().expect("result");
        match result.which().expect("known") {
            tip_height_result::Which::Height(h) => assert_eq!(h, 99),
            _ => panic!("expected Height"),
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn get_network_round_trips() {
        let chain = Arc::new(FakeChain {
            tip: None,
            height: None,
            network: bitcoin::Network::Regtest,
            headers: Default::default(),
        });
        let stub: share_chain::Client =
            capnp_rpc::new_client(ShareChainStub::new().with_chain_backend(chain));
        let reply = stub
            .get_network_request()
            .send()
            .promise
            .await
            .expect("rpc ok");
        let result = reply.get().expect("reader").get_result().expect("result");
        assert!(matches!(
            result.which().expect("known"),
            network_result::Which::Regtest(())
        ));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn chain_methods_unimplemented_without_backend() {
        let stub: share_chain::Client = capnp_rpc::new_client(ShareChainStub::new());
        let err = stub.get_chain_tip_request().send().promise.await;
        assert!(err.is_err(), "expected unimplemented when no backend wired");
    }
}
