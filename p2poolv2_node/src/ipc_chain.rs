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

//! Server-side adapter wiring `ChainStoreHandle` into the IPC
//! `ChainReadBackend` trait.
//!
//! The IPC crate intentionally does not depend on `p2poolv2_lib`
//! (see ADR 0010 in the sv2-p2pool repo and the crate-level docs in
//! `p2poolv2_ipc`). The daemon owns the handle and provides this
//! adapter so the IPC server can serve `getChainTip`,
//! `getShareHeader`, `getTipHeight`, and `getNetwork` from the real
//! share-chain store.

use bitcoin::BlockHash;
use bitcoin::hashes::Hash as _;
use p2poolv2_ipc::{ChainReadBackend, ShareHeaderOutcome};
use p2poolv2_lib::shares::chain::chain_store_handle::ChainStoreHandle;
use p2poolv2_lib::store::writer::StoreError;

/// `ChainReadBackend` implementation backed by a real
/// `ChainStoreHandle`. Cheap to clone (the underlying handle is
/// internally `Arc`-shared).
pub struct ChainReadAdapter {
    chain: ChainStoreHandle,
}

impl ChainReadAdapter {
    pub fn new(chain: ChainStoreHandle) -> Self {
        Self { chain }
    }
}

impl ChainReadBackend for ChainReadAdapter {
    fn get_chain_tip(&self) -> Result<Option<[u8; 32]>, String> {
        match self.chain.get_chain_tip() {
            Ok(tip) => Ok(Some(*tip.as_raw_hash().as_byte_array())),
            // No genesis yet → treat as uninitialised.
            Err(StoreError::NotFound(_)) => Ok(None),
            Err(e) => Err(format!("{e}")),
        }
    }

    fn get_share_header(&self, share_hash: &[u8; 32]) -> Result<ShareHeaderOutcome, String> {
        // Engine-side encodes the genesis predecessor as the
        // all-zeros sentinel; surface it as a discrete variant so
        // the engine's existing "stop at genesis" check can be
        // expressed without reaching into the byte representation.
        if share_hash.iter().all(|b| *b == 0) {
            return Ok(ShareHeaderOutcome::Genesis);
        }
        let block_hash = BlockHash::from_raw_hash(
            bitcoin::hashes::sha256d::Hash::from_byte_array(*share_hash),
        );
        match self.chain.get_share_header(&block_hash) {
            Ok(header) => Ok(ShareHeaderOutcome::Found {
                prev_share_blockhash: *header
                    .prev_share_blockhash
                    .as_raw_hash()
                    .as_byte_array(),
            }),
            Err(StoreError::NotFound(_)) => Ok(ShareHeaderOutcome::NotFound),
            Err(e) => Err(format!("{e}")),
        }
    }

    fn get_tip_height(&self) -> Result<Option<u32>, String> {
        self.chain.get_tip_height().map_err(|e| format!("{e}"))
    }

    fn network(&self) -> bitcoin::Network {
        self.chain.network()
    }
}
