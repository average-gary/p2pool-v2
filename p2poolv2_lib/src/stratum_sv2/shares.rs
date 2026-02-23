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

//! SV2 share submission handler.
//!
//! Validates `SubmitSharesStandard` messages, checks proof-of-work,
//! converts valid shares to [`Emission`] structs, and sends them into
//! the same pipeline as SV1 shares.

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use bitcoin::blockdata::block::Header;
use bitcoin::hashes::Hash;
use stratum_core::mining_sv2::{SubmitSharesError, SubmitSharesStandard, SubmitSharesSuccess};
use tracing::{debug, info};

use crate::accounting::simple_pplns::SimplePplnsShare;
use crate::stratum::emission::{Emission, EmissionSender};

use super::channels::StandardChannel;
use super::error::Sv2Error;
use super::work::Sv2JobState;

/// Result of validating a submitted share.
#[derive(Debug)]
pub struct ShareValidationResult {
    /// The reconstructed block header.
    pub header: Header,
    /// Whether the share meets the Bitcoin network difficulty.
    pub meets_network_difficulty: bool,
    /// Whether the share meets the channel's target.
    pub meets_channel_target: bool,
}

/// Validate a `SubmitSharesStandard` against the stored job state.
///
/// Reconstructs the block header from:
/// - `job_state`: coinbase, merkle_root, template (prev_hash, nbits)
/// - `submit`: nonce, ntime, version (from miner)
///
/// Then checks PoW against both the channel target and the network target.
pub fn validate_share(
    submit: &SubmitSharesStandard,
    job_state: &Sv2JobState,
    channel: &StandardChannel,
) -> Result<ShareValidationResult, Sv2Error> {
    // The prev_hash must be set (job must be activated, not future)
    let prev_hash_bytes = job_state.prev_hash.ok_or_else(|| {
        Sv2Error::InvalidMessage("share submitted against a future (unactivated) job".to_string())
    })?;

    let prev_blockhash = bitcoin::BlockHash::from_byte_array(prev_hash_bytes);

    let merkle_root = bitcoin::TxMerkleNode::from_byte_array(job_state.merkle_root);

    let compact_target = bitcoin::CompactTarget::from_consensus(job_state.nbits);

    let header = Header {
        version: bitcoin::block::Version::from_consensus(submit.version as i32),
        prev_blockhash,
        merkle_root,
        time: submit.ntime,
        bits: compact_target,
        nonce: submit.nonce,
    };

    // Check against Bitcoin network target
    let network_target = bitcoin::Target::from_compact(compact_target);
    let meets_network_difficulty = header.validate_pow(network_target).is_ok();

    if meets_network_difficulty {
        info!(
            channel_id = submit.channel_id,
            job_id = submit.job_id,
            block_hash = %header.block_hash(),
            "share meets Bitcoin network difficulty!"
        );
    }

    // Check against channel target
    let block_hash = header.block_hash();
    let hash_bytes = block_hash.as_ref();
    let meets_channel_target = hash_le_target(hash_bytes, &channel.target);

    debug!(
        channel_id = submit.channel_id,
        job_id = submit.job_id,
        nonce = submit.nonce,
        meets_network = meets_network_difficulty,
        meets_channel = meets_channel_target,
        "validated SV2 share"
    );

    Ok(ShareValidationResult {
        header,
        meets_network_difficulty,
        meets_channel_target,
    })
}

/// Compare a hash against a target (both as 32-byte little-endian arrays).
/// Returns true if hash <= target.
fn hash_le_target(hash: &[u8], target: &[u8; 32]) -> bool {
    // Compare from most-significant byte (end of array for LE)
    for i in (0..32).rev() {
        let h = if i < hash.len() { hash[i] } else { 0 };
        let t = target[i];
        if h < t {
            return true;
        }
        if h > t {
            return false;
        }
    }
    true // equal
}

/// Convert a validated SV2 share into an [`Emission`] and send it
/// through the shared emissions pipeline.
///
/// This produces an `Emission` struct identical to what SV1 produces,
/// so all downstream accounting (PPLNS, share chain, block submission)
/// works unchanged.
pub async fn emit_share(
    submit: &SubmitSharesStandard,
    validation: &ShareValidationResult,
    job_state: &Sv2JobState,
    channel: &StandardChannel,
    emissions_tx: &EmissionSender,
) -> Result<(), Sv2Error> {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    // Map SV2 fields to SimplePplnsShare fields.
    // For SV2: extranonce is embedded in the coinbase (not a separate field),
    // so we store the channel's extranonce prefix as the "extranonce2" equivalent.
    let pplns = SimplePplnsShare::new(
        channel.user_id,
        1, // difficulty placeholder — will be refined with vardiff (issue #9)
        channel.btc_address.clone(),
        channel.worker_name.clone().unwrap_or_default(),
        timestamp,
        format!("{:08x}", submit.job_id),
        hex::encode(&channel.extranonce_prefix),
        format!("{:08x}", submit.nonce),
    );

    let emission = Emission {
        pplns,
        header: validation.header,
        coinbase: job_state.coinbase.clone(),
        blocktemplate: Arc::clone(&job_state.template),
        share_commitment: job_state.share_commitment.clone(),
    };

    emissions_tx
        .send(emission)
        .await
        .map_err(|_| Sv2Error::ChannelError("emissions pipeline closed".to_string()))?;

    debug!(
        channel_id = submit.channel_id,
        job_id = submit.job_id,
        user_id = channel.user_id,
        "emitted SV2 share to accounting pipeline"
    );

    Ok(())
}

/// Build a `SubmitSharesSuccess` response for a batch of accepted shares.
pub fn build_submit_success(
    channel_id: u32,
    last_sequence_number: u32,
    accepted_count: u32,
    shares_sum: u64,
) -> SubmitSharesSuccess {
    SubmitSharesSuccess {
        channel_id,
        last_sequence_number,
        new_submits_accepted_count: accepted_count,
        new_shares_sum: shares_sum,
    }
}

/// Build a `SubmitSharesError` response.
pub fn build_submit_error(
    channel_id: u32,
    sequence_number: u32,
    reason: &str,
) -> SubmitSharesError<'static> {
    SubmitSharesError {
        channel_id,
        sequence_number,
        error_code: reason.to_string().try_into().expect("static error code"),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stratum::work::block_template::BlockTemplate;
    use std::collections::HashMap;

    fn test_channel() -> StandardChannel {
        StandardChannel {
            channel_id: 1,
            group_channel_id: 1,
            downstream_id: 100,
            btc_address: "tb1qtest".to_string(),
            worker_name: Some("worker1".to_string()),
            user_id: 42,
            nominal_hash_rate: 1_000_000.0,
            extranonce_prefix: vec![0x00; 6],
            target: [0xff; 32], // easiest possible target
        }
    }

    fn test_template() -> BlockTemplate {
        BlockTemplate {
            version: 0x20000000,
            rules: vec![],
            vbavailable: HashMap::new(),
            vbrequired: 0,
            previousblockhash: "000000000000000000034b3f4f4d3e3b2c1a0f0e0d0c0b0a0908070605040302"
                .to_string(),
            transactions: vec![],
            coinbaseaux: HashMap::new(),
            coinbasevalue: 625_000_000,
            longpollid: "test".to_string(),
            target: "00000000ffff0000000000000000000000000000000000000000000000000000".to_string(),
            mintime: 1700000000,
            mutable: vec![],
            noncerange: "00000000ffffffff".to_string(),
            sigoplimit: 80000,
            sizelimit: 4000000,
            weightlimit: 4000000,
            curtime: 1700000100,
            bits: "1d00ffff".to_string(),
            height: 850000,
            default_witness_commitment: None,
        }
    }

    fn test_job_state() -> Sv2JobState {
        // Use a fixed merkle root and coinbase for testing
        let prev_hash: [u8; 32] =
            hex::decode("000000000000000000034b3f4f4d3e3b2c1a0f0e0d0c0b0a0908070605040302")
                .unwrap()
                .try_into()
                .unwrap();

        Sv2JobState {
            job_id: 1,
            template: Arc::new(test_template()),
            coinbase: bitcoin::Transaction {
                version: bitcoin::transaction::Version::TWO,
                lock_time: bitcoin::absolute::LockTime::ZERO,
                input: vec![],
                output: vec![],
            },
            merkle_root: [0xaa; 32],
            version: 0x20000000,
            is_future: false,
            prev_hash: Some(prev_hash),
            nbits: 0x1d00ffff,
            min_ntime: 1700000100,
            share_commitment: None,
        }
    }

    #[test]
    fn test_validate_share_basic() {
        let channel = test_channel();
        let job_state = test_job_state();
        let submit = SubmitSharesStandard {
            channel_id: 1,
            sequence_number: 0,
            job_id: 1,
            nonce: 0x12345678,
            ntime: 1700000100,
            version: 0x20000000,
        };

        let result = validate_share(&submit, &job_state, &channel);
        assert!(result.is_ok());
        let result = result.unwrap();
        // With an all-0xff target, any hash should meet the channel target
        assert!(result.meets_channel_target);
        // Unlikely to meet network difficulty with a random nonce
        // (but we don't assert on this since it depends on the hash)
    }

    #[test]
    fn test_validate_share_rejects_future_job() {
        let channel = test_channel();
        let mut job_state = test_job_state();
        job_state.prev_hash = None; // Future job

        let submit = SubmitSharesStandard {
            channel_id: 1,
            sequence_number: 0,
            job_id: 1,
            nonce: 0,
            ntime: 1700000100,
            version: 0x20000000,
        };

        let result = validate_share(&submit, &job_state, &channel);
        assert!(result.is_err());
    }

    #[test]
    fn test_hash_le_target() {
        let low_hash = [0u8; 32];
        let high_target = [0xff; 32];
        assert!(hash_le_target(&low_hash, &high_target));

        let high_hash = [0xff; 32];
        let low_target = [0u8; 32];
        assert!(!hash_le_target(&high_hash, &low_target));

        let equal = [0x42; 32];
        assert!(hash_le_target(&equal, &equal));
    }

    #[test]
    fn test_build_submit_success() {
        let msg = build_submit_success(1, 5, 3, 1000);
        assert_eq!(msg.channel_id, 1);
        assert_eq!(msg.last_sequence_number, 5);
        assert_eq!(msg.new_submits_accepted_count, 3);
        assert_eq!(msg.new_shares_sum, 1000);
    }

    #[test]
    fn test_build_submit_error() {
        let msg = build_submit_error(1, 3, "stale-share");
        assert_eq!(msg.channel_id, 1);
        assert_eq!(msg.sequence_number, 3);
    }

    #[tokio::test]
    async fn test_emit_share() {
        let channel = test_channel();
        let job_state = test_job_state();
        let submit = SubmitSharesStandard {
            channel_id: 1,
            sequence_number: 0,
            job_id: 1,
            nonce: 0x12345678,
            ntime: 1700000100,
            version: 0x20000000,
        };

        let validation = validate_share(&submit, &job_state, &channel).unwrap();

        let (emissions_tx, mut emissions_rx) = tokio::sync::mpsc::channel(10);
        let result = emit_share(&submit, &validation, &job_state, &channel, &emissions_tx).await;
        assert!(result.is_ok());

        let emission = emissions_rx.recv().await.unwrap();
        assert_eq!(emission.pplns.user_id, 42);
        assert_eq!(emission.pplns.btcaddress, Some("tb1qtest".to_string()));
        assert_eq!(emission.pplns.workername, Some("worker1".to_string()));
        assert_eq!(emission.header.nonce, 0x12345678);
    }
}
