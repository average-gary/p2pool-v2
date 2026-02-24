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
use stratum_core::binary_sv2::{B064K, Seq0255, Sv2Option, U256};
use stratum_core::mining_sv2::{NewExtendedMiningJob, NewMiningJob, SetNewPrevHash};
use tracing::debug;

use crate::shares::share_commitment::ShareCommitment;
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
    /// Share commitment for the sharechain (if available).
    pub share_commitment: Option<ShareCommitment>,
}

/// State for an extended mining job.
///
/// Unlike standard jobs where the pool pre-computes the merkle root, extended
/// jobs send the coinbase split and merkle path to the proxy. The proxy
/// inserts its extranonce, computes the coinbase txid, walks the merkle path
/// to derive the merkle root, and builds the block header.
///
/// This state is stored per job so that share validation can reconstruct the
/// coinbase and verify the proxy's submitted extranonce + PoW.
#[derive(Debug, Clone)]
pub struct Sv2ExtendedJobState {
    /// The SV2 job ID.
    pub job_id: u32,
    /// The block template this job was derived from.
    pub template: Arc<BlockTemplate>,
    /// Serialized coinbase bytes *before* the extranonce slot.
    ///
    /// Full coinbase = `coinbase_tx_prefix + extranonce_prefix + proxy_extranonce + coinbase_tx_suffix`
    pub coinbase_tx_prefix: Vec<u8>,
    /// Serialized coinbase bytes *after* the extranonce slot.
    pub coinbase_tx_suffix: Vec<u8>,
    /// Merkle path: sibling hashes from the coinbase leaf to the root.
    ///
    /// The proxy computes `H(coinbase_txid || path[0])`, then
    /// `H(result || path[1])`, etc. to derive the merkle root.
    pub merkle_path: Vec<[u8; 32]>,
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
    /// Share commitment for the sharechain (if available).
    pub share_commitment: Option<ShareCommitment>,
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
    /// Full share commitment struct (if available), stored in job state
    /// so that SV2 shares emitted to the accounting pipeline include it.
    pub share_commitment: Option<ShareCommitment>,
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
        share_commitment: params.share_commitment.clone(),
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
// Extended channel job construction
// ---------------------------------------------------------------------------

/// Build an SV2 `NewExtendedMiningJob` and associated state from a block template.
///
/// For extended channels: splits the coinbase at the extranonce boundary,
/// computes the merkle path (sibling hashes), and sends these to the proxy.
/// The proxy inserts its extranonce, computes the coinbase txid, walks the
/// merkle path to derive the merkle root, and builds the block header.
///
/// # Arguments
///
/// * `template` - The GBT block template
/// * `channel_id` - The SV2 extended channel ID
/// * `params` - Additional parameters (outputs, signature, future flag)
///
/// # Returns
///
/// A tuple of `(NewExtendedMiningJob, Sv2ExtendedJobState)`.
pub fn build_new_extended_mining_job(
    template: &Arc<BlockTemplate>,
    channel_id: u32,
    params: &Sv2JobParams,
) -> Result<(NewExtendedMiningJob<'static>, Sv2ExtendedJobState), Sv2Error> {
    let job_id = next_job_id();

    // Build the coinbase transaction with the placeholder extranonce.
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

    // Serialize and find the extranonce separator position.
    let coinbase_bytes = serialize(&coinbase);
    let separator = [0x01u8; 12];
    let separator_pos = coinbase_bytes
        .windows(separator.len())
        .position(|w| w == separator)
        .ok_or_else(|| {
            Sv2Error::InvalidMessage("extranonce separator not found in coinbase".to_string())
        })?;

    // Split coinbase at the separator boundary.
    // coinbase_tx_prefix = everything before the 12-byte extranonce data
    // coinbase_tx_suffix = everything after the 12-byte extranonce data
    //
    // The proxy reconstructs: prefix + extranonce_prefix + proxy_extranonce + suffix
    let coinbase_tx_prefix = coinbase_bytes[..separator_pos].to_vec();
    let coinbase_tx_suffix = coinbase_bytes[separator_pos + 12..].to_vec();

    // Compute the merkle path from the template transaction IDs.
    let template_txids: Vec<[u8; 32]> = template
        .transactions
        .iter()
        .map(|tx| {
            let mut bytes = [0u8; 32];
            let decoded = hex::decode(&tx.txid).expect("valid hex txid in template");
            bytes.copy_from_slice(&decoded);
            bytes
        })
        .collect();
    let merkle_path = compute_merkle_path(&template_txids);

    // Parse prev_hash from template
    let prev_hash_bytes: [u8; 32] = hex::decode(&template.previousblockhash)
        .map_err(|e| Sv2Error::InvalidMessage(format!("bad previousblockhash: {e}")))?
        .try_into()
        .map_err(|_| Sv2Error::InvalidMessage("previousblockhash not 32 bytes".to_string()))?;

    // Parse nbits
    let nbits = u32::from_str_radix(&template.bits, 16)
        .map_err(|e| Sv2Error::InvalidMessage(format!("bad nbits: {e}")))?;

    // Build the SV2 NewExtendedMiningJob message
    let min_ntime: Sv2Option<'static, u32> = if params.is_future {
        Sv2Option::new(None)
    } else {
        Sv2Option::new(Some(template.curtime))
    };

    // Convert merkle path to Seq0255<U256>
    let path_u256s: Vec<U256<'static>> = merkle_path
        .iter()
        .map(|h| h.to_vec().try_into().expect("32 bytes is valid U256"))
        .collect();
    let merkle_path_seq: Seq0255<'static, U256<'static>> = path_u256s.into();

    // Convert coinbase prefix/suffix to B064K
    let prefix_b064k: B064K<'static> = coinbase_tx_prefix
        .clone()
        .try_into()
        .map_err(|_| Sv2Error::InvalidMessage("coinbase prefix too large for B064K".to_string()))?;
    let suffix_b064k: B064K<'static> = coinbase_tx_suffix
        .clone()
        .try_into()
        .map_err(|_| Sv2Error::InvalidMessage("coinbase suffix too large for B064K".to_string()))?;

    let mining_job = NewExtendedMiningJob {
        channel_id,
        job_id,
        min_ntime,
        version: template.version as u32,
        version_rolling_allowed: true,
        merkle_path: merkle_path_seq,
        coinbase_tx_prefix: prefix_b064k,
        coinbase_tx_suffix: suffix_b064k,
    };

    let job_state = Sv2ExtendedJobState {
        job_id,
        template: Arc::clone(template),
        coinbase_tx_prefix,
        coinbase_tx_suffix,
        merkle_path: merkle_path.clone(),
        version: template.version as u32,
        is_future: params.is_future,
        prev_hash: if params.is_future {
            None
        } else {
            Some(prev_hash_bytes)
        },
        nbits,
        min_ntime: template.curtime,
        share_commitment: params.share_commitment.clone(),
    };

    debug!(
        job_id,
        channel_id,
        is_future = params.is_future,
        height = template.height,
        merkle_path_len = merkle_path.len(),
        coinbase_prefix_len = job_state.coinbase_tx_prefix.len(),
        coinbase_suffix_len = job_state.coinbase_tx_suffix.len(),
        "built SV2 NewExtendedMiningJob"
    );

    Ok((mining_job, job_state))
}

/// Compute the merkle path (sibling hashes) for the coinbase transaction.
///
/// Given the list of non-coinbase transaction IDs (txids), computes the
/// sibling hashes that a miner/proxy needs to walk from the coinbase leaf
/// up to the merkle root.
///
/// The path is ordered from the deepest level (closest to the coinbase)
/// up to the root. At each level, the coinbase is always at index 0, so
/// its sibling is the hash at index 1 (or a duplicate of index 0 if odd count).
///
/// # Arguments
///
/// * `txids` - Transaction IDs excluding the coinbase, in template order.
///   Each txid is 32 bytes in internal byte order.
///
/// # Returns
///
/// A vector of 32-byte sibling hashes forming the merkle path.
pub fn compute_merkle_path(txids: &[[u8; 32]]) -> Vec<[u8; 32]> {
    if txids.is_empty() {
        // No transactions besides coinbase — no path needed.
        // The merkle root IS the coinbase txid.
        return Vec::new();
    }

    // Start with all transaction hashes (excluding coinbase).
    // The coinbase is at index 0 in the full tree, so these are indices 1..N.
    // At level 0, the sibling of the coinbase is txids[0].
    let mut path = Vec::new();

    // Level 0: sibling of coinbase is txids[0]
    path.push(txids[0]);

    // Build remaining levels by pairing up the non-coinbase transactions
    // The coinbase side reduces to a single "running hash" at each level,
    // so we only need to track the other side of the tree.
    let mut current_level: Vec<[u8; 32]> = txids[1..].to_vec();

    // If there's only one tx besides coinbase, we're done (path = [txids[0]])
    if current_level.is_empty() {
        return path;
    }

    loop {
        // Pair up hashes at this level
        let mut next_level = Vec::new();

        let mut i = 0;
        while i < current_level.len() {
            let left = current_level[i];
            let right = if i + 1 < current_level.len() {
                current_level[i + 1]
            } else {
                // Odd number of nodes: duplicate the last one
                left
            };

            let combined = double_sha256_pair(&left, &right);
            next_level.push(combined);
            i += 2;
        }

        // The first element of next_level is the sibling at this tree level
        path.push(next_level[0]);

        // Move to next level, dropping the first element (it's now in the path)
        current_level = next_level[1..].to_vec();

        if current_level.is_empty() {
            break;
        }
    }

    path
}

/// Reconstruct the merkle root from a coinbase txid and a merkle path.
///
/// This is the inverse of `compute_merkle_path`: starting from the coinbase
/// txid, hash it with each path element to walk up to the root.
///
/// At each level, the coinbase (or its running hash) is always the LEFT
/// child, and the path element is the RIGHT sibling.
pub fn reconstruct_merkle_root(coinbase_txid: &[u8; 32], merkle_path: &[[u8; 32]]) -> [u8; 32] {
    if merkle_path.is_empty() {
        return *coinbase_txid;
    }

    let mut current = *coinbase_txid;
    for sibling in merkle_path {
        current = double_sha256_pair(&current, sibling);
    }
    current
}

/// Double-SHA256 of two 32-byte hashes concatenated.
fn double_sha256_pair(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    use bitcoin::hashes::{Hash, HashEngine, sha256d};

    let mut engine = sha256d::Hash::engine();
    engine.input(left);
    engine.input(right);
    let hash = sha256d::Hash::from_engine(engine);
    let mut result = [0u8; 32];
    result.copy_from_slice(hash.as_ref());
    result
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
            share_commitment: None,
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
            share_commitment: None,
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
            share_commitment: None,
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
    fn test_build_new_extended_mining_job_basic() {
        let template = Arc::new(test_template());
        let params = Sv2JobParams {
            output_distribution: test_output_distribution(),
            pool_signature: b"P2Pool".to_vec(),
            commitment_hash: None,
            share_commitment: None,
            is_future: false,
        };

        let result = build_new_extended_mining_job(&template, 1, &params);
        assert!(
            result.is_ok(),
            "build_new_extended_mining_job failed: {:?}",
            result.err()
        );

        let (job, state) = result.unwrap();
        assert_eq!(job.channel_id, 1);
        assert_eq!(job.version, 0x20000000);
        assert!(job.version_rolling_allowed);
        assert!(!job.is_future());
        assert!(!state.is_future);
        assert!(state.prev_hash.is_some());
        assert!(!state.coinbase_tx_prefix.is_empty());
        assert!(!state.coinbase_tx_suffix.is_empty());
        // No extra txns -> empty merkle path
        assert!(state.merkle_path.is_empty());
    }

    #[test]
    fn test_build_new_extended_mining_job_future() {
        let template = Arc::new(test_template());
        let params = Sv2JobParams {
            output_distribution: test_output_distribution(),
            pool_signature: b"P2Pool".to_vec(),
            commitment_hash: None,
            share_commitment: None,
            is_future: true,
        };

        let result = build_new_extended_mining_job(&template, 5, &params);
        assert!(result.is_ok());

        let (job, state) = result.unwrap();
        assert_eq!(job.channel_id, 5);
        assert!(job.is_future());
        assert!(state.is_future);
        assert!(state.prev_hash.is_none());
    }

    #[test]
    fn test_extended_job_with_transactions_has_merkle_path() {
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
            share_commitment: None,
            is_future: false,
        };

        let (_, state) = build_new_extended_mining_job(&template, 1, &params).unwrap();
        // One extra tx -> merkle path has one entry (the sibling of coinbase)
        assert_eq!(state.merkle_path.len(), 1);
    }

    #[test]
    fn test_coinbase_prefix_suffix_reconstruct() {
        // Verify that prefix + 12-byte extranonce + suffix = original coinbase bytes
        let template = Arc::new(test_template());
        let params = Sv2JobParams {
            output_distribution: test_output_distribution(),
            pool_signature: b"P2Pool".to_vec(),
            commitment_hash: None,
            share_commitment: None,
            is_future: false,
        };

        let (_, state) = build_new_extended_mining_job(&template, 1, &params).unwrap();

        // Reconstruct with a specific extranonce (12 bytes)
        let extranonce = [0xAA; 12];
        let mut reconstructed = state.coinbase_tx_prefix.clone();
        reconstructed.extend_from_slice(&extranonce);
        reconstructed.extend_from_slice(&state.coinbase_tx_suffix);

        // Should be a valid transaction
        let tx: bitcoin::Transaction =
            bitcoin::consensus::deserialize(&reconstructed).expect("valid transaction");
        assert!(tx.is_coinbase());
    }

    #[test]
    fn test_merkle_path_reconstruction_matches_standard() {
        // For the same template, the merkle root computed via the standard
        // path (build_new_mining_job) should match the one reconstructed
        // from the extended path (merkle_path + coinbase txid).
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

        let extranonce = [0x00, 0x01, 0x00, 0x00, 0x00, 0x01]; // 6-byte prefix

        // Standard job: pre-computes merkle root
        let std_params = Sv2JobParams {
            output_distribution: test_output_distribution(),
            pool_signature: b"P2Pool".to_vec(),
            commitment_hash: None,
            share_commitment: None,
            is_future: false,
        };
        let (_, std_state) = build_new_mining_job(&template, 1, &extranonce, &std_params).unwrap();

        // Extended job: provides merkle path + coinbase split
        let ext_params = Sv2JobParams {
            output_distribution: test_output_distribution(),
            pool_signature: b"P2Pool".to_vec(),
            commitment_hash: None,
            share_commitment: None,
            is_future: false,
        };
        let (_, ext_state) = build_new_extended_mining_job(&template, 1, &ext_params).unwrap();

        // Reconstruct coinbase with the same extranonce (padded to 12 bytes)
        let mut full_extranonce = [0u8; 12];
        full_extranonce[..extranonce.len()].copy_from_slice(&extranonce);

        let mut coinbase_bytes = ext_state.coinbase_tx_prefix.clone();
        coinbase_bytes.extend_from_slice(&full_extranonce);
        coinbase_bytes.extend_from_slice(&ext_state.coinbase_tx_suffix);

        let coinbase: bitcoin::Transaction =
            bitcoin::consensus::deserialize(&coinbase_bytes).unwrap();
        let coinbase_txid = coinbase.compute_txid();
        let txid_bytes: [u8; 32] = *coinbase_txid.as_ref();

        // Walk the merkle path to get the root
        let reconstructed_root = reconstruct_merkle_root(&txid_bytes, &ext_state.merkle_path);

        // Should match the standard job's pre-computed merkle root
        assert_eq!(
            reconstructed_root, std_state.merkle_root,
            "merkle root mismatch: extended path reconstruction doesn't match standard"
        );
    }

    #[test]
    fn test_compute_merkle_path_empty() {
        let path = compute_merkle_path(&[]);
        assert!(path.is_empty());
    }

    #[test]
    fn test_compute_merkle_path_one_tx() {
        let txid = [0xAA; 32];
        let path = compute_merkle_path(&[txid]);
        assert_eq!(path.len(), 1);
        assert_eq!(path[0], txid);
    }

    #[test]
    fn test_reconstruct_merkle_root_no_path() {
        let coinbase_txid = [0xBB; 32];
        let root = reconstruct_merkle_root(&coinbase_txid, &[]);
        assert_eq!(root, coinbase_txid);
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
            share_commitment: None,
            is_future: false,
        };

        let result = build_new_mining_job(&template, 1, &[0x00; 6], &params);
        assert!(result.is_ok());

        let (_, state) = result.unwrap();
        // Merkle root should incorporate both coinbase and the template transaction
        assert_ne!(state.merkle_root, [0u8; 32]);
    }
}
