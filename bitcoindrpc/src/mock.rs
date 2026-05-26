// Copyright (C) 2024-2026 P2Poolv2 Developers (see AUTHORS)
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

//! In-process mock implementation of [`BitcoindLike`] for unit tests.
//!
//! Unlike [`crate::test_utils`] which spins up a `wiremock` HTTP server,
//! `MockBitcoind` is a pure-Rust struct that holds canned responses behind a
//! mutex. This is enough for the majority of `p2poolv2_lib` tests and for
//! downstream consumers (e.g. `sv2-p2pool-engine`) that just need a stand-in
//! for the real `BitcoindRpcClient`.
//!
//! Available under `#[cfg(test)]` and via the `test-utils` feature.

use crate::{BitcoindLike, BitcoindRpcError, GetBlockchainInfo};
use async_trait::async_trait;
use std::sync::Mutex;

/// A scripted in-memory mock of [`BitcoindLike`].
///
/// Each method either returns the stored canned response or, if none has been
/// set, a [`BitcoindRpcError::Other`] noting that the test forgot to script it.
/// `submit_block` and `decoderawtransaction` additionally record the inputs they
/// were called with so tests can assert behavior.
#[derive(Default)]
pub struct MockBitcoind {
    inner: Mutex<Inner>,
}

#[derive(Default)]
struct Inner {
    difficulty: Option<Result<f64, BitcoindRpcError>>,
    blockchain_info: Option<Result<GetBlockchainInfo, BitcoindRpcError>>,
    block_template: Option<Result<String, BitcoindRpcError>>,
    decoded_tx: Option<Result<bitcoin::Transaction, BitcoindRpcError>>,
    submit_block_response: Option<Result<String, BitcoindRpcError>>,
    proposal_response: Option<Result<bool, BitcoindRpcError>>,
    submitted_blocks: Vec<bitcoin::Block>,
    decoded_txs: Vec<bitcoin::Transaction>,
}

impl MockBitcoind {
    /// Create an empty mock with no canned responses yet.
    pub fn new() -> Self {
        Self::default()
    }

    /// Script the next [`BitcoindLike::get_difficulty`] response.
    pub fn with_difficulty(self, value: f64) -> Self {
        self.inner.lock().unwrap().difficulty = Some(Ok(value));
        self
    }

    /// Script the next [`BitcoindLike::getblockchaininfo`] response.
    pub fn with_blockchain_info(self, info: GetBlockchainInfo) -> Self {
        self.inner.lock().unwrap().blockchain_info = Some(Ok(info));
        self
    }

    /// Script the next [`BitcoindLike::getblocktemplate`] response.
    pub fn with_block_template(self, template_json: String) -> Self {
        self.inner.lock().unwrap().block_template = Some(Ok(template_json));
        self
    }

    /// Script the next [`BitcoindLike::decoderawtransaction`] response.
    pub fn with_decoded_tx(self, tx: bitcoin::Transaction) -> Self {
        self.inner.lock().unwrap().decoded_tx = Some(Ok(tx));
        self
    }

    /// Script the next [`BitcoindLike::submit_block`] response.
    pub fn with_submit_block_response(self, response: String) -> Self {
        self.inner.lock().unwrap().submit_block_response = Some(Ok(response));
        self
    }

    /// Script the next [`BitcoindLike::validate_block_proposal`] response.
    pub fn with_proposal_response(self, accepted_as_duplicate: bool) -> Self {
        self.inner.lock().unwrap().proposal_response = Some(Ok(accepted_as_duplicate));
        self
    }

    /// Snapshot of blocks observed by [`BitcoindLike::submit_block`].
    pub fn submitted_blocks(&self) -> Vec<bitcoin::Block> {
        self.inner.lock().unwrap().submitted_blocks.clone()
    }

    /// Snapshot of transactions observed by [`BitcoindLike::decoderawtransaction`].
    pub fn decoded_txs(&self) -> Vec<bitcoin::Transaction> {
        self.inner.lock().unwrap().decoded_txs.clone()
    }
}

fn unscripted(method: &str) -> BitcoindRpcError {
    BitcoindRpcError::Other(format!(
        "MockBitcoind::{method} called without a canned response"
    ))
}

#[async_trait]
impl BitcoindLike for MockBitcoind {
    async fn get_difficulty(&self) -> Result<f64, BitcoindRpcError> {
        self.inner
            .lock()
            .unwrap()
            .difficulty
            .as_ref()
            .map(|r| match r {
                Ok(v) => Ok(*v),
                Err(e) => Err(BitcoindRpcError::Other(e.to_string())),
            })
            .unwrap_or_else(|| Err(unscripted("get_difficulty")))
    }

    async fn getblockchaininfo(&self) -> Result<GetBlockchainInfo, BitcoindRpcError> {
        // GetBlockchainInfo isn't Clone; return a fresh value each time by
        // cloning the underlying `bool`.
        let guard = self.inner.lock().unwrap();
        match guard.blockchain_info.as_ref() {
            Some(Ok(info)) => Ok(GetBlockchainInfo {
                initial_block_download: info.initial_block_download,
            }),
            Some(Err(e)) => Err(BitcoindRpcError::Other(e.to_string())),
            None => Err(unscripted("getblockchaininfo")),
        }
    }

    async fn getblocktemplate(
        &self,
        _network: bitcoin::Network,
    ) -> Result<String, BitcoindRpcError> {
        self.inner
            .lock()
            .unwrap()
            .block_template
            .as_ref()
            .map(|r| match r {
                Ok(v) => Ok(v.clone()),
                Err(e) => Err(BitcoindRpcError::Other(e.to_string())),
            })
            .unwrap_or_else(|| Err(unscripted("getblocktemplate")))
    }

    async fn decoderawtransaction(
        &self,
        tx: &bitcoin::Transaction,
    ) -> Result<bitcoin::Transaction, BitcoindRpcError> {
        let mut guard = self.inner.lock().unwrap();
        guard.decoded_txs.push(tx.clone());
        match guard.decoded_tx.as_ref() {
            Some(Ok(decoded)) => Ok(decoded.clone()),
            Some(Err(e)) => Err(BitcoindRpcError::Other(e.to_string())),
            None => Ok(tx.clone()),
        }
    }

    async fn submit_block(&self, block: &bitcoin::Block) -> Result<String, BitcoindRpcError> {
        let mut guard = self.inner.lock().unwrap();
        guard.submitted_blocks.push(block.clone());
        match guard.submit_block_response.as_ref() {
            Some(Ok(v)) => Ok(v.clone()),
            Some(Err(e)) => Err(BitcoindRpcError::Other(e.to_string())),
            None => Ok("null".to_string()),
        }
    }

    async fn validate_block_proposal(
        &self,
        _block: &bitcoin::Block,
    ) -> Result<bool, BitcoindRpcError> {
        self.inner
            .lock()
            .unwrap()
            .proposal_response
            .as_ref()
            .map(|r| match r {
                Ok(v) => Ok(*v),
                Err(e) => Err(BitcoindRpcError::Other(e.to_string())),
            })
            .unwrap_or_else(|| Err(unscripted("validate_block_proposal")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[tokio::test]
    async fn dyn_compatible_via_arc() {
        let mock: Arc<dyn BitcoindLike> = Arc::new(MockBitcoind::new().with_difficulty(42.0));
        assert_eq!(mock.get_difficulty().await.unwrap(), 42.0);
    }

    #[tokio::test]
    async fn submitted_blocks_are_recorded() {
        let mock = MockBitcoind::new();
        let block = bitcoin::Block {
            header: bitcoin::blockdata::block::Header {
                version: bitcoin::blockdata::block::Version::from_consensus(1),
                prev_blockhash: bitcoin::BlockHash::from_raw_hash(
                    bitcoin::hashes::Hash::all_zeros(),
                ),
                merkle_root: bitcoin::TxMerkleNode::from_raw_hash(
                    bitcoin::hashes::Hash::all_zeros(),
                ),
                time: 1,
                bits: bitcoin::CompactTarget::from_consensus(0),
                nonce: 0,
            },
            txdata: vec![],
        };
        let _ = mock.submit_block(&block).await.unwrap();
        assert_eq!(mock.submitted_blocks().len(), 1);
    }

    #[tokio::test]
    async fn unscripted_method_errors_clearly() {
        let mock = MockBitcoind::new();
        let err = mock.get_difficulty().await.unwrap_err();
        assert!(matches!(err, BitcoindRpcError::Other(_)));
    }
}
