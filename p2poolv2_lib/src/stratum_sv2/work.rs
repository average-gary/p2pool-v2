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

//! SV2 job construction from GBT block templates.
//!
//! Converts existing [`BlockTemplate`] data into SV2 mining messages:
//! - [`NewMiningJob`] for standard channels (pre-computed merkle root)
//! - [`SetNewPrevHash`] to activate jobs on new blocks
//!
//! # Standard Channel Jobs
//!
//! For standard channels the pool controls the entire coinbase: it builds
//! the coinbase transaction, computes the full merkle root, and sends
//! `NewMiningJob { merkle_root }`. The miner only manipulates nonce,
//! nTime, and version bits (BIP320).
//!
//! # Future Job Pattern
//!
//! SV2 uses a "future job" workflow to minimize latency:
//! 1. Pool creates a `NewMiningJob` with `min_ntime = None` (future job)
//! 2. When a new block arrives, pool sends `SetNewPrevHash` referencing
//!    the future job's `job_id` — this activates the job
//! 3. The miner immediately starts mining with the new prevhash
//!
//! When no new block has arrived but the template updates (e.g., new
//! transactions), the pool sends a `NewMiningJob` with
//! `min_ntime = Some(curtime)` — the miner can start immediately using
//! the current prevhash.

use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};

use bitcoin::consensus::serialize;
use stratum_core::binary_sv2::{Sv2Option, U256};
use stratum_core::mining_sv2::{NewMiningJob, SetNewPrevHash};
use tracing::debug;

use crate::stratum::work::block_template::BlockTemplate;
use crate::stratum::work::coinbase::build_coinbase_transaction;
use crate::stratum::work::notify::parse_flags;

use super::error::Sv2Error;

// ---------------------------------------------------------------------------
// Job ID allocation
// ---------------------------------------------------------------------------

/// Global atomic counter for SV2 job IDs.
///
/// Separate from the SV1 `JobTracker` to avoid ID collisions and keep
/// the SV2 job namespace clean.
static NEXT_SV2_JOB_ID: AtomicU32 = AtomicU32::new(1);

/// Allocate the next unique SV2 job ID.
pub fn next_job_id() -> u32 {
    NEXT_SV2_JOB_ID.fetch_add(1, Ordering::Relaxed)
}

// ---------------------------------------------------------------------------
// Job state
// ---------------------------------------------------------------------------

/// All the data needed to reconstruct a block header from a submitted share.
///
/// Stored per job so that share validation can rebuild the header without
/// re-fetching the template.
#[derive(Debug, Clone)]
pub struct Sv2JobState {
    /// The SV2 job ID.
    pub job_id: u32,
    /// The block template this job was derived from.
    pub template: Arc<BlockTemplate>,
    /// The fully-constructed coinbase transaction (with fixed extranonce).
    pub coinbase: bitcoin::Transaction,
    /// The computed merkle root (32 bytes, internal byte order).
    pub merkle_root: [u8; 32],
    /// Block version from the template.
    pub version: u32,
    /// Whether this is a future job (waiting for SetNewPrevHash to activate).
    pub is_future: bool,
    /// The prev_hash this job is valid for (None if future job).
    pub prev_hash: Option<[u8; 32]>,
    /// nbits from the template.
    pub nbits: u32,
    /// curtime from the template.
    pub min_ntime: u32,
}

// ---------------------------------------------------------------------------
// Core conversion: BlockTemplate -> SV2 job
// ---------------------------------------------------------------------------

/// Parameters for building an SV2 job from a block template.
pub struct Sv2JobParams {
    /// PPLNS payout outputs for the coinbase transaction.
    pub output_distribution: Vec<crate::accounting::OutputPair>,
    /// Pool signature bytes for the coinbase script_sig.
    pub pool_signature: Vec<u8>,
    /// Optional share commitment hash for the coinbase script_sig.
    pub commitment_hash: Option<bitcoin::hashes::sha256::Hash>,
    /// Whether this is a future job (new template, same prevhash not yet received).
    pub is_future: bool,
}

/// Build an SV2 `NewMiningJob` and associated state from a block template.
///
/// For standard channels: computes the full coinbase transaction and merkle
/// root. The miner only manipulates nonce, nTime, and version bits.
///
/// # Arguments
///
/// * `template` - The GBT block template
/// * `channel_id` - The SV2 channel ID (or group channel ID for broadcast)
/// * `extranonce` - The fixed extranonce bytes for this channel/group
/// * `params` - Additional parameters (outputs, signature, future flag)
///
/// # Returns
///
/// A tuple of `(NewMiningJob, Sv2JobState)` — the message to send to the
/// miner and the internal state for later share validation.
pub fn build_new_mining_job(
    template: &Arc<BlockTemplate>,
    channel_id: u32,
    extranonce: &[u8],
    params: &Sv2JobParams,
) -> Result<(NewMiningJob<'static>, Sv2JobState), Sv2Error> {
    let job_id = next_job_id();

    // Build the coinbase transaction.
    // For SV2 standard channels, the pool fully controls the coinbase.
    // We embed the extranonce directly into the script_sig via the
    // commitment_hash slot (the existing coinbase builder places a
    // fixed-size separator that we replace in the serialized bytes).
    let coinbase = build_coinbase_transaction(
        bitcoin::transaction::Version::TWO,
        &params.output_distribution,
        template.height as i64,
        parse_flags(template.coinbaseaux.get("flags").cloned()),
        template.default_witness_commitment.clone(),
        &params.pool_signature,
        params.commitment_hash,
    )
    .map_err(|e| Sv2Error::InvalidMessage(format!("failed to build coinbase: {e}")))?;

    // Serialize the coinbase and replace the extranonce separator with
    // the actual extranonce bytes. The separator is 12 bytes of 0x01.
    let mut coinbase_bytes = serialize(&coinbase);
    let separator = [0x01u8; 12];
    if let Some(pos) = coinbase_bytes
        .windows(separator.len())
        .position(|w| w == separator)
    {
        // Write the extranonce into the separator position.
        // Pad or truncate to exactly 12 bytes.
        let mut enonce = [0u8; 12];
        let copy_len = extranonce.len().min(12);
        enonce[..copy_len].copy_from_slice(&extranonce[..copy_len]);
        coinbase_bytes[pos..pos + 12].copy_from_slice(&enonce);
    }

    // Re-deserialize the modified coinbase to get the correct txid.
    let coinbase: bitcoin::Transaction = bitcoin::consensus::deserialize(&coinbase_bytes)
        .map_err(|e| Sv2Error::InvalidMessage(format!("failed to re-deserialize coinbase: {e}")))?;

    // Compute the full merkle root: coinbase txid + template txids.
    let coinbase_txid = coinbase.compute_txid();
    let template_txids: Vec<bitcoin::Txid> = template
        .transactions
        .iter()
        .map(|tx| tx.txid.parse().expect("valid txid in template"))
        .collect();

    let mut all_txids = vec![coinbase_txid];
    all_txids.extend(template_txids);

    let hashes = all_txids.iter().map(|txid| txid.to_raw_hash());
    let merkle_root_node: bitcoin::TxMerkleNode = bitcoin::merkle_tree::calculate_root(hashes)
        .map(|h| h.into())
        .expect("at least one txid (coinbase)");

    let merkle_root_bytes: [u8; 32] = *merkle_root_node.as_ref();

    // Parse prev_hash from template (hex -> 32 bytes)
    let prev_hash_bytes: [u8; 32] = hex::decode(&template.previousblockhash)
        .map_err(|e| Sv2Error::InvalidMessage(format!("bad previousblockhash: {e}")))?
        .try_into()
        .map_err(|_| Sv2Error::InvalidMessage("previousblockhash not 32 bytes".to_string()))?;

    // Parse nbits
    let nbits = u32::from_str_radix(&template.bits, 16)
        .map_err(|e| Sv2Error::InvalidMessage(format!("bad nbits: {e}")))?;

    // Build the SV2 NewMiningJob message
    let min_ntime: Sv2Option<'static, u32> = if params.is_future {
        Sv2Option::new(None)
    } else {
        Sv2Option::new(Some(template.curtime))
    };

    let merkle_root_u256: U256<'static> = merkle_root_bytes
        .to_vec()
        .try_into()
        .expect("32 bytes is valid U256");

    let mining_job = NewMiningJob {
        channel_id,
        job_id,
        min_ntime,
        version: template.version as u32,
        merkle_root: merkle_root_u256,
    };

    let job_state = Sv2JobState {
        job_id,
        template: Arc::clone(template),
        coinbase,
        merkle_root: merkle_root_bytes,
        version: template.version as u32,
        is_future: params.is_future,
        prev_hash: if params.is_future {
            None
        } else {
            Some(prev_hash_bytes)
        },
        nbits,
        min_ntime: template.curtime,
    };

    debug!(
        job_id,
        channel_id,
        is_future = params.is_future,
        height = template.height,
        "built SV2 NewMiningJob"
    );

    Ok((mining_job, job_state))
}

// ---------------------------------------------------------------------------
// SetNewPrevHash construction
// ---------------------------------------------------------------------------

/// Build a `SetNewPrevHash` message for a given channel/group and template.
///
/// This message activates a future job (identified by `job_id`) by telling
/// the miner which prev_hash and nbits to use.
pub fn build_set_new_prev_hash(
    channel_id: u32,
    job_id: u32,
    template: &BlockTemplate,
) -> Result<SetNewPrevHash<'static>, Sv2Error> {
    let prev_hash_bytes: [u8; 32] = hex::decode(&template.previousblockhash)
        .map_err(|e| Sv2Error::InvalidMessage(format!("bad previousblockhash: {e}")))?
        .try_into()
        .map_err(|_| Sv2Error::InvalidMessage("previousblockhash not 32 bytes".to_string()))?;

    let prev_hash_u256: U256<'static> = prev_hash_bytes
        .to_vec()
        .try_into()
        .expect("32 bytes is valid U256");

    let nbits = u32::from_str_radix(&template.bits, 16)
        .map_err(|e| Sv2Error::InvalidMessage(format!("bad nbits: {e}")))?;

    Ok(SetNewPrevHash {
        channel_id,
        job_id,
        prev_hash: prev_hash_u256,
        min_ntime: template.curtime,
        nbits,
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::accounting::OutputPair;
    use crate::stratum::work::block_template::{BlockTemplate, TemplateTransaction};
    use bitcoin::Address;
    use std::collections::HashMap;
    use std::str::FromStr;

    /// Create a minimal block template for testing.
    fn test_template() -> BlockTemplate {
        BlockTemplate {
            version: 0x20000000,
            rules: vec!["segwit".to_string()],
            vbavailable: HashMap::new(),
            vbrequired: 0,
            previousblockhash: "000000000000000000034b3f4f4d3e3b2c1a0f0e0d0c0b0a0908070605040302"
                .to_string(),
            transactions: vec![],
            coinbaseaux: HashMap::new(),
            coinbasevalue: 625_000_000, // 6.25 BTC
            longpollid: "test".to_string(),
            target: "00000000ffff0000000000000000000000000000000000000000000000000000".to_string(),
            mintime: 1700000000,
            mutable: vec!["time".to_string()],
            noncerange: "00000000ffffffff".to_string(),
            sigoplimit: 80000,
            sizelimit: 4000000,
            weightlimit: 4000000,
            curtime: 1700000100,
            bits: "1d00ffff".to_string(),
            height: 850000,
            default_witness_commitment: Some(
                "6a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf9"
                    .to_string(),
            ),
        }
    }

    fn test_output_distribution() -> Vec<OutputPair> {
        vec![OutputPair {
            address: Address::from_str("tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx")
                .unwrap()
                .assume_checked(),
            amount: bitcoin::Amount::from_sat(625_000_000),
        }]
    }

    #[test]
    fn test_build_new_mining_job_basic() {
        let template = Arc::new(test_template());
        let params = Sv2JobParams {
            output_distribution: test_output_distribution(),
            pool_signature: b"P2Pool".to_vec(),
            commitment_hash: None,
            is_future: false,
        };

        let result = build_new_mining_job(&template, 1, &[0x00; 6], &params);
        assert!(
            result.is_ok(),
            "build_new_mining_job failed: {:?}",
            result.err()
        );

        let (job, state) = result.unwrap();
        assert_eq!(job.channel_id, 1);
        assert_eq!(job.version, 0x20000000);
        assert!(!job.is_future());
        assert!(!state.is_future);
        assert!(state.prev_hash.is_some());
        assert_eq!(state.template.height, 850000);
    }

    #[test]
    fn test_build_new_mining_job_future() {
        let template = Arc::new(test_template());
        let params = Sv2JobParams {
            output_distribution: test_output_distribution(),
            pool_signature: b"P2Pool".to_vec(),
            commitment_hash: None,
            is_future: true,
        };

        let result = build_new_mining_job(&template, 5, &[0xAB; 6], &params);
        assert!(result.is_ok());

        let (job, state) = result.unwrap();
        assert_eq!(job.channel_id, 5);
        assert!(job.is_future());
        assert!(state.is_future);
        assert!(state.prev_hash.is_none());
    }

    #[test]
    fn test_different_extranonces_produce_different_merkle_roots() {
        let template = Arc::new(test_template());
        let params = Sv2JobParams {
            output_distribution: test_output_distribution(),
            pool_signature: b"P2Pool".to_vec(),
            commitment_hash: None,
            is_future: false,
        };

        let (_, state1) = build_new_mining_job(&template, 1, &[0x00; 6], &params).unwrap();
        let (_, state2) = build_new_mining_job(&template, 1, &[0x01; 6], &params).unwrap();

        // Different extranonces -> different coinbase txids -> different merkle roots
        assert_ne!(state1.merkle_root, state2.merkle_root);
    }

    #[test]
    fn test_build_set_new_prev_hash() {
        let template = test_template();
        let result = build_set_new_prev_hash(10, 42, &template);
        assert!(result.is_ok());

        let msg = result.unwrap();
        assert_eq!(msg.channel_id, 10);
        assert_eq!(msg.job_id, 42);
        assert_eq!(msg.min_ntime, 1700000100);
        assert_eq!(msg.nbits, 0x1d00ffff);
    }

    #[test]
    fn test_job_ids_increment() {
        let id1 = next_job_id();
        let id2 = next_job_id();
        assert!(id2 > id1);
    }

    #[test]
    fn test_build_new_mining_job_with_transactions() {
        // Template with one transaction
        let mut template = test_template();
        template.transactions.push(TemplateTransaction {
            data: "02000000000101a3e61c5c44d5e87f8a6ed69c3f3583987c68d29aff4c6d2b38ab9d8b4e4d0a5a0000000000feffffff0200ca9a3b000000001600148d7a0a3461e3891723e5fcc8c7b2d3c3d6a4e5f60000000000000000076a05706f6f6c00024730440220796f64ef30d78c62edd9ef75e8e8ef08789c7e2b96fee5c5f4f4c4c6e3a8d2cf022057f08c92a7c4e24ade66f96c80e3c8e4c2e6ca92d2f4c8e6d8c2a4b6f8e0c2a401210279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f8179800000000".to_string(),
            txid: "a3e61c5c44d5e87f8a6ed69c3f3583987c68d29aff4c6d2b38ab9d8b4e4d0a5a".to_string(),
            hash: "a3e61c5c44d5e87f8a6ed69c3f3583987c68d29aff4c6d2b38ab9d8b4e4d0a5a".to_string(),
            depends: vec![],
            fee: 1000,
            sigops: 1,
            weight: 400,
        });

        let template = Arc::new(template);
        let params = Sv2JobParams {
            output_distribution: test_output_distribution(),
            pool_signature: b"P2Pool".to_vec(),
            commitment_hash: None,
            is_future: false,
        };

        let result = build_new_mining_job(&template, 1, &[0x00; 6], &params);
        assert!(result.is_ok());

        let (_, state) = result.unwrap();
        // Merkle root should incorporate both coinbase and the template transaction
        assert_ne!(state.merkle_root, [0u8; 32]);
    }
}
