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

//! SV2 job distribution to mining channels.
//!
//! Subscribes to the block template pipeline and distributes SV2 mining jobs
//! (`NewMiningJob`, `SetNewPrevHash`) to all connected SV2 downstream miners.
//!
//! # Architecture
//!
//! The [`Sv2JobDistributor`] is a tokio actor that:
//! 1. Receives new block templates via an mpsc channel
//! 2. Builds `NewMiningJob` messages per group channel
//! 3. Tracks the active job per group for bootstrapping new channels
//! 4. Detects new-block events (changed prev_hash) and sends `SetNewPrevHash`
//!
//! External code interacts through [`Sv2JobDistributorHandle`].
//!
//! # Job Distribution Flow
//!
//! ```text
//! GBT poller -> template_tx -> Sv2JobDistributor
//!   |-> for each group channel:
//!       |-> build_new_mining_job(template, group_extranonce)
//!       |-> store Sv2JobState (for share validation)
//!       |-> send (NewMiningJob, SetNewPrevHash) to downstream via notify callback
//! ```

use std::collections::HashMap;
use std::sync::Arc;

use tokio::sync::{mpsc, oneshot, watch};
use tracing::{debug, info, warn};

use crate::accounting::OutputPair;
use crate::shares::share_commitment::ShareCommitment;
use crate::stratum::work::block_template::BlockTemplate;

use super::error::Sv2Error;
use super::work::{
    Sv2ExtendedJobState, Sv2JobParams, Sv2JobState, build_new_extended_mining_job,
    build_new_mining_job,
};

// ---------------------------------------------------------------------------
// Commands
// ---------------------------------------------------------------------------

/// Commands sent to the job distributor actor.
pub enum JobDistributorCmd {
    /// A new block template arrived from the GBT poller.
    NewTemplate {
        template: Arc<BlockTemplate>,
        output_distribution: Vec<OutputPair>,
        pool_signature: Vec<u8>,
        commitment_hash: Option<bitcoin::hashes::sha256::Hash>,
        share_commitment: Option<ShareCommitment>,
    },
    /// Get the current active job state for a group (used to bootstrap new channels).
    GetActiveJob {
        group_channel_id: u32,
        reply: oneshot::Sender<Option<ActiveJobInfo>>,
    },
    /// Get a job state by job_id (used for share validation).
    GetJobState {
        job_id: u32,
        reply: oneshot::Sender<Option<Sv2JobState>>,
    },
    /// Register a group channel for job distribution.
    RegisterGroup {
        group_channel_id: u32,
        /// The extranonce prefix for this group (used in coinbase construction).
        extranonce: Vec<u8>,
    },
    /// Unregister a group channel (downstream disconnected).
    UnregisterGroup { group_channel_id: u32 },
    /// Register an extended channel for job distribution.
    RegisterExtendedChannel {
        channel_id: u32,
        extranonce_prefix: Vec<u8>,
    },
    /// Unregister an extended channel.
    UnregisterExtendedChannel { channel_id: u32 },
    /// Get the current active extended job for a channel (bootstrap).
    GetActiveExtendedJob {
        channel_id: u32,
        reply: oneshot::Sender<Option<ActiveExtendedJobInfo>>,
    },
    /// Get an extended job state by job_id (for share validation).
    GetExtendedJobState {
        job_id: u32,
        reply: oneshot::Sender<Option<Sv2ExtendedJobState>>,
    },
}

/// Info about the currently active job for a group channel.
#[derive(Debug, Clone)]
pub struct ActiveJobInfo {
    /// The NewMiningJob fields needed to send to a new channel.
    pub job_id: u32,
    pub version: u32,
    pub merkle_root: [u8; 32],
    pub min_ntime: u32,
    /// The SetNewPrevHash fields (if the job is activated).
    pub prev_hash: Option<[u8; 32]>,
    pub nbits: Option<u32>,
    /// The full job state for share validation.
    pub job_state: Sv2JobState,
}

/// Info about the currently active extended job for an extended channel.
#[derive(Debug, Clone)]
pub struct ActiveExtendedJobInfo {
    /// The job ID.
    pub job_id: u32,
    /// The full extended job state for share validation and bootstrap.
    pub job_state: Sv2ExtendedJobState,
}

/// Callback for sending job messages to downstreams.
///
/// The job distributor calls this when a new job needs to be sent to a
/// group channel. The callback is responsible for serializing the message
/// into Noise-encrypted frames and sending it to the downstream.
///
/// Arguments: `(group_channel_id, job_id, job_state)`
pub type JobNotifyCallback =
    Arc<dyn Fn(u32, &Sv2JobState, bool) -> Result<(), Sv2Error> + Send + Sync>;

// ---------------------------------------------------------------------------
// Group state
// ---------------------------------------------------------------------------

/// Per-group channel state tracked by the distributor.
struct GroupState {
    /// The extranonce prefix for this group.
    extranonce: Vec<u8>,
    /// The currently active job (most recent non-future, or most recent future + prev_hash).
    active_job: Option<Sv2JobState>,
}

/// Per-extended-channel state tracked by the distributor.
struct ExtendedChannelState {
    /// The extranonce prefix for this extended channel.
    extranonce_prefix: Vec<u8>,
    /// The currently active extended job.
    active_job: Option<Sv2ExtendedJobState>,
}

// ---------------------------------------------------------------------------
// Actor
// ---------------------------------------------------------------------------

/// Cached parameters from the most recent template distribution,
/// used to bootstrap newly-registered groups.
#[derive(Clone)]
struct CachedJobParams {
    output_distribution: Vec<OutputPair>,
    pool_signature: Vec<u8>,
    commitment_hash: Option<bitcoin::hashes::sha256::Hash>,
    share_commitment: Option<ShareCommitment>,
}

/// Internal actor state for the job distributor.
struct Sv2JobDistributor {
    /// Per-group channel state (standard channels).
    groups: HashMap<u32, GroupState>,
    /// Per-extended-channel state.
    extended_channels: HashMap<u32, ExtendedChannelState>,
    /// All standard job states, keyed by job_id (for share validation lookup).
    job_states: HashMap<u32, Sv2JobState>,
    /// All extended job states, keyed by job_id (for share validation lookup).
    extended_job_states: HashMap<u32, Sv2ExtendedJobState>,
    /// The most recent previous block hash seen (for detecting new blocks).
    last_prev_hash: Option<String>,
    /// The most recent block template.
    last_template: Option<Arc<BlockTemplate>>,
    /// Cached job parameters from the last template distribution.
    last_job_params: Option<CachedJobParams>,
    /// Server ID for extranonce prefix generation.
    _server_id: u16,
    /// Watch channel for broadcasting new job events (standard + extended).
    /// Receivers can subscribe to be notified when jobs change.
    job_event_tx: watch::Sender<Option<JobEvent>>,
    /// Max number of job states to retain (prevents memory growth).
    max_retained_jobs: usize,
}

/// Event emitted when a new job is ready for distribution.
#[derive(Debug, Clone)]
pub struct JobEvent {
    /// The group channel ID this job is for (0 = all groups).
    pub group_channel_id: u32,
    /// The job ID.
    pub job_id: u32,
    /// Whether this is a new-block event (clean jobs).
    pub clean_jobs: bool,
    /// The full job state (standard channels).
    pub job_state: Sv2JobState,
    /// Extended job info, if this event also carries an extended job.
    /// Each extended channel gets its own job, but we piggyback on the same
    /// watch channel. The handler's writer task checks `extended_jobs` to
    /// see if any belong to its connection's extended channels.
    pub extended_jobs: Vec<ExtendedJobEvent>,
}

/// Extended job info carried within a [`JobEvent`].
#[derive(Debug, Clone)]
pub struct ExtendedJobEvent {
    /// The extended channel ID this job is for.
    pub channel_id: u32,
    /// The extended job state.
    pub job_state: Sv2ExtendedJobState,
}

impl Sv2JobDistributor {
    fn new(server_id: u16) -> (Self, watch::Receiver<Option<JobEvent>>) {
        let (job_event_tx, job_event_rx) = watch::channel(None);
        (
            Self {
                groups: HashMap::new(),
                extended_channels: HashMap::new(),
                job_states: HashMap::new(),
                extended_job_states: HashMap::new(),
                last_prev_hash: None,
                last_template: None,
                last_job_params: None,
                _server_id: server_id,
                job_event_tx,
                max_retained_jobs: 1000,
            },
            job_event_rx,
        )
    }

    fn handle_new_template(
        &mut self,
        template: Arc<BlockTemplate>,
        output_distribution: Vec<OutputPair>,
        pool_signature: Vec<u8>,
        commitment_hash: Option<bitcoin::hashes::sha256::Hash>,
        share_commitment: Option<ShareCommitment>,
    ) {
        let clean_jobs = self
            .last_prev_hash
            .as_ref()
            .map(|prev| *prev != template.previousblockhash)
            .unwrap_or(true);

        if clean_jobs {
            info!(
                height = template.height,
                prev_hash = %template.previousblockhash,
                "new block detected, distributing clean jobs"
            );
        } else {
            debug!(
                height = template.height,
                "template update (same block), distributing new jobs"
            );
        }

        self.last_prev_hash = Some(template.previousblockhash.clone());
        self.last_template = Some(Arc::clone(&template));
        self.last_job_params = Some(CachedJobParams {
            output_distribution: output_distribution.clone(),
            pool_signature: pool_signature.clone(),
            commitment_hash,
            share_commitment: share_commitment.clone(),
        });

        // Build extended jobs for registered extended channels
        let ext_channel_ids: Vec<u32> = self.extended_channels.keys().cloned().collect();
        let mut extended_job_events = Vec::new();
        for ext_ch_id in ext_channel_ids {
            let params = Sv2JobParams {
                output_distribution: output_distribution.clone(),
                pool_signature: pool_signature.clone(),
                commitment_hash,
                share_commitment: share_commitment.clone(),
                is_future: false,
            };

            match build_new_extended_mining_job(&template, ext_ch_id, &params) {
                Ok((_, ext_job_state)) => {
                    let job_id = ext_job_state.job_id;
                    self.extended_job_states
                        .insert(job_id, ext_job_state.clone());

                    if let Some(ch_state) = self.extended_channels.get_mut(&ext_ch_id) {
                        ch_state.active_job = Some(ext_job_state.clone());
                    }

                    extended_job_events.push(ExtendedJobEvent {
                        channel_id: ext_ch_id,
                        job_state: ext_job_state,
                    });
                }
                Err(e) => {
                    warn!(
                        ext_ch_id,
                        "failed to build SV2 extended job for channel: {e}"
                    );
                }
            }
        }

        // Build a standard job for each registered group
        let group_ids: Vec<u32> = self.groups.keys().cloned().collect();
        let has_groups = !group_ids.is_empty();
        for group_channel_id in group_ids {
            let extranonce = match self.groups.get(&group_channel_id) {
                Some(gs) => gs.extranonce.clone(),
                None => continue,
            };

            let params = Sv2JobParams {
                output_distribution: output_distribution.clone(),
                pool_signature: pool_signature.clone(),
                commitment_hash,
                share_commitment: share_commitment.clone(),
                is_future: false, // For now, always send immediately-minable jobs
            };

            match build_new_mining_job(&template, group_channel_id, &extranonce, &params) {
                Ok((_, job_state)) => {
                    let job_id = job_state.job_id;

                    // Store the job state
                    self.job_states.insert(job_id, job_state.clone());

                    // Update the group's active job
                    if let Some(group) = self.groups.get_mut(&group_channel_id) {
                        group.active_job = Some(job_state.clone());
                    }

                    // Emit job event (includes any extended jobs built above)
                    let event = JobEvent {
                        group_channel_id,
                        job_id,
                        clean_jobs,
                        job_state,
                        extended_jobs: extended_job_events.clone(),
                    };
                    let _ = self.job_event_tx.send(Some(event));
                }
                Err(e) => {
                    warn!(group_channel_id, "failed to build SV2 job for group: {e}");
                }
            }
        }

        // If there are extended jobs but no standard groups, still emit an event
        // so the writer tasks for extended-only connections get notified.
        if !has_groups && !extended_job_events.is_empty() {
            // Use a sentinel job event with group_channel_id=0
            if let Some(first_ext) = extended_job_events.first() {
                let event = JobEvent {
                    group_channel_id: 0,
                    job_id: first_ext.job_state.job_id,
                    clean_jobs,
                    // We need a Sv2JobState for the event, but for extended-only
                    // we don't have one. Use a dummy standard job state.
                    // The handler's writer task will check extended_jobs instead.
                    job_state: Sv2JobState {
                        job_id: first_ext.job_state.job_id,
                        template: Arc::clone(&first_ext.job_state.template),
                        coinbase: bitcoin::consensus::deserialize(&{
                            let mut bytes = first_ext.job_state.coinbase_tx_prefix.clone();
                            bytes.extend_from_slice(&[0u8; 12]);
                            bytes.extend_from_slice(&first_ext.job_state.coinbase_tx_suffix);
                            bytes
                        })
                        .expect("valid coinbase"),
                        merkle_root: [0u8; 32],
                        version: first_ext.job_state.version,
                        is_future: first_ext.job_state.is_future,
                        prev_hash: first_ext.job_state.prev_hash,
                        nbits: first_ext.job_state.nbits,
                        min_ntime: first_ext.job_state.min_ntime,
                        share_commitment: first_ext.job_state.share_commitment.clone(),
                    },
                    extended_jobs: extended_job_events,
                };
                let _ = self.job_event_tx.send(Some(event));
            }
        }

        // Garbage-collect old job states
        self.gc_job_states();
    }

    fn handle_register_group(&mut self, group_channel_id: u32, extranonce: Vec<u8>) {
        debug!(group_channel_id, "registered group for job distribution");
        self.groups.insert(
            group_channel_id,
            GroupState {
                extranonce,
                active_job: None,
            },
        );

        // If we have a template and cached params, immediately build a job
        // for this group (bootstrap new downstreams with the current work).
        if let (Some(template), Some(cached)) =
            (self.last_template.clone(), self.last_job_params.clone())
        {
            let extranonce = self.groups[&group_channel_id].extranonce.clone();
            let params = Sv2JobParams {
                output_distribution: cached.output_distribution,
                pool_signature: cached.pool_signature,
                commitment_hash: cached.commitment_hash,
                share_commitment: cached.share_commitment,
                is_future: false,
            };

            match build_new_mining_job(&template, group_channel_id, &extranonce, &params) {
                Ok((_, job_state)) => {
                    self.job_states.insert(job_state.job_id, job_state.clone());
                    if let Some(group) = self.groups.get_mut(&group_channel_id) {
                        group.active_job = Some(job_state);
                    }
                }
                Err(e) => {
                    warn!(
                        group_channel_id,
                        "failed to bootstrap job for new group: {e}"
                    );
                }
            }
        }
    }

    fn handle_unregister_group(&mut self, group_channel_id: u32) {
        debug!(group_channel_id, "unregistered group from job distribution");
        self.groups.remove(&group_channel_id);
    }

    fn handle_get_active_job(&self, group_channel_id: u32) -> Option<ActiveJobInfo> {
        let group = self.groups.get(&group_channel_id)?;
        let job_state = group.active_job.as_ref()?;

        Some(ActiveJobInfo {
            job_id: job_state.job_id,
            version: job_state.version,
            merkle_root: job_state.merkle_root,
            min_ntime: job_state.min_ntime,
            prev_hash: job_state.prev_hash,
            nbits: Some(job_state.nbits),
            job_state: job_state.clone(),
        })
    }

    fn handle_get_job_state(&self, job_id: u32) -> Option<Sv2JobState> {
        self.job_states.get(&job_id).cloned()
    }

    fn handle_register_extended_channel(&mut self, channel_id: u32, extranonce_prefix: Vec<u8>) {
        debug!(
            channel_id,
            "registered extended channel for job distribution"
        );
        self.extended_channels.insert(
            channel_id,
            ExtendedChannelState {
                extranonce_prefix,
                active_job: None,
            },
        );

        // Bootstrap: if we have a template, immediately build an extended job
        if let (Some(template), Some(cached)) =
            (self.last_template.clone(), self.last_job_params.clone())
        {
            let params = Sv2JobParams {
                output_distribution: cached.output_distribution,
                pool_signature: cached.pool_signature,
                commitment_hash: cached.commitment_hash,
                share_commitment: cached.share_commitment,
                is_future: false,
            };

            match build_new_extended_mining_job(&template, channel_id, &params) {
                Ok((_, ext_job_state)) => {
                    self.extended_job_states
                        .insert(ext_job_state.job_id, ext_job_state.clone());
                    if let Some(ch_state) = self.extended_channels.get_mut(&channel_id) {
                        ch_state.active_job = Some(ext_job_state);
                    }
                }
                Err(e) => {
                    warn!(
                        channel_id,
                        "failed to bootstrap extended job for new channel: {e}"
                    );
                }
            }
        }
    }

    fn handle_unregister_extended_channel(&mut self, channel_id: u32) {
        debug!(
            channel_id,
            "unregistered extended channel from job distribution"
        );
        self.extended_channels.remove(&channel_id);
    }

    fn handle_get_active_extended_job(&self, channel_id: u32) -> Option<ActiveExtendedJobInfo> {
        let ch_state = self.extended_channels.get(&channel_id)?;
        let job_state = ch_state.active_job.as_ref()?;

        Some(ActiveExtendedJobInfo {
            job_id: job_state.job_id,
            job_state: job_state.clone(),
        })
    }

    fn handle_get_extended_job_state(&self, job_id: u32) -> Option<Sv2ExtendedJobState> {
        self.extended_job_states.get(&job_id).cloned()
    }

    /// Remove old job states beyond the retention limit.
    fn gc_job_states(&mut self) {
        if self.job_states.len() > self.max_retained_jobs {
            let mut ids: Vec<u32> = self.job_states.keys().cloned().collect();
            ids.sort();
            let to_remove = ids.len() - self.max_retained_jobs;
            for id in ids.into_iter().take(to_remove) {
                self.job_states.remove(&id);
            }
        }

        if self.extended_job_states.len() > self.max_retained_jobs {
            let mut ids: Vec<u32> = self.extended_job_states.keys().cloned().collect();
            ids.sort();
            let to_remove = ids.len() - self.max_retained_jobs;
            for id in ids.into_iter().take(to_remove) {
                self.extended_job_states.remove(&id);
            }
        }
    }

    /// Run the actor event loop.
    async fn run(mut self, mut cmd_rx: mpsc::Receiver<JobDistributorCmd>) {
        while let Some(cmd) = cmd_rx.recv().await {
            match cmd {
                JobDistributorCmd::NewTemplate {
                    template,
                    output_distribution,
                    pool_signature,
                    commitment_hash,
                    share_commitment,
                } => {
                    self.handle_new_template(
                        template,
                        output_distribution,
                        pool_signature,
                        commitment_hash,
                        share_commitment,
                    );
                }
                JobDistributorCmd::GetActiveJob {
                    group_channel_id,
                    reply,
                } => {
                    let _ = reply.send(self.handle_get_active_job(group_channel_id));
                }
                JobDistributorCmd::GetJobState { job_id, reply } => {
                    let _ = reply.send(self.handle_get_job_state(job_id));
                }
                JobDistributorCmd::RegisterGroup {
                    group_channel_id,
                    extranonce,
                } => {
                    self.handle_register_group(group_channel_id, extranonce);
                }
                JobDistributorCmd::UnregisterGroup { group_channel_id } => {
                    self.handle_unregister_group(group_channel_id);
                }
                JobDistributorCmd::RegisterExtendedChannel {
                    channel_id,
                    extranonce_prefix,
                } => {
                    self.handle_register_extended_channel(channel_id, extranonce_prefix);
                }
                JobDistributorCmd::UnregisterExtendedChannel { channel_id } => {
                    self.handle_unregister_extended_channel(channel_id);
                }
                JobDistributorCmd::GetActiveExtendedJob { channel_id, reply } => {
                    let _ = reply.send(self.handle_get_active_extended_job(channel_id));
                }
                JobDistributorCmd::GetExtendedJobState { job_id, reply } => {
                    let _ = reply.send(self.handle_get_extended_job_state(job_id));
                }
            }
        }
        debug!("job distributor actor shutting down");
    }
}

// ---------------------------------------------------------------------------
// Public handle
// ---------------------------------------------------------------------------

const JOB_DIST_CMD_BUFFER: usize = 256;

/// Cheaply-cloneable handle for interacting with the job distributor.
#[derive(Clone)]
pub struct Sv2JobDistributorHandle {
    cmd_tx: mpsc::Sender<JobDistributorCmd>,
    job_event_rx: watch::Receiver<Option<JobEvent>>,
}

/// Start the job distributor actor and return a handle.
pub fn start_job_distributor(server_id: u16) -> Sv2JobDistributorHandle {
    let (cmd_tx, cmd_rx) = mpsc::channel(JOB_DIST_CMD_BUFFER);
    let (distributor, job_event_rx) = Sv2JobDistributor::new(server_id);
    tokio::spawn(distributor.run(cmd_rx));
    Sv2JobDistributorHandle {
        cmd_tx,
        job_event_rx,
    }
}

impl Sv2JobDistributorHandle {
    /// Notify the distributor of a new block template.
    pub async fn new_template(
        &self,
        template: Arc<BlockTemplate>,
        output_distribution: Vec<OutputPair>,
        pool_signature: Vec<u8>,
        commitment_hash: Option<bitcoin::hashes::sha256::Hash>,
        share_commitment: Option<ShareCommitment>,
    ) -> Result<(), Sv2Error> {
        self.cmd_tx
            .send(JobDistributorCmd::NewTemplate {
                template,
                output_distribution,
                pool_signature,
                commitment_hash,
                share_commitment,
            })
            .await
            .map_err(|_| Sv2Error::ChannelError("job distributor stopped".to_string()))
    }

    /// Get the currently active job for a group channel.
    ///
    /// Used to bootstrap new channels — send them the current job immediately.
    pub async fn get_active_job(
        &self,
        group_channel_id: u32,
    ) -> Result<Option<ActiveJobInfo>, Sv2Error> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.cmd_tx
            .send(JobDistributorCmd::GetActiveJob {
                group_channel_id,
                reply: reply_tx,
            })
            .await
            .map_err(|_| Sv2Error::ChannelError("job distributor stopped".to_string()))?;

        reply_rx
            .await
            .map_err(|_| Sv2Error::ChannelError("job distributor reply dropped".to_string()))
    }

    /// Look up a job state by job_id (for share validation).
    pub async fn get_job_state(&self, job_id: u32) -> Result<Option<Sv2JobState>, Sv2Error> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.cmd_tx
            .send(JobDistributorCmd::GetJobState {
                job_id,
                reply: reply_tx,
            })
            .await
            .map_err(|_| Sv2Error::ChannelError("job distributor stopped".to_string()))?;

        reply_rx
            .await
            .map_err(|_| Sv2Error::ChannelError("job distributor reply dropped".to_string()))
    }

    /// Register a group channel for job distribution.
    pub async fn register_group(
        &self,
        group_channel_id: u32,
        extranonce: Vec<u8>,
    ) -> Result<(), Sv2Error> {
        self.cmd_tx
            .send(JobDistributorCmd::RegisterGroup {
                group_channel_id,
                extranonce,
            })
            .await
            .map_err(|_| Sv2Error::ChannelError("job distributor stopped".to_string()))
    }

    /// Unregister a group channel (downstream disconnected).
    pub async fn unregister_group(&self, group_channel_id: u32) -> Result<(), Sv2Error> {
        self.cmd_tx
            .send(JobDistributorCmd::UnregisterGroup { group_channel_id })
            .await
            .map_err(|_| Sv2Error::ChannelError("job distributor stopped".to_string()))
    }

    /// Register an extended channel for job distribution.
    pub async fn register_extended_channel(
        &self,
        channel_id: u32,
        extranonce_prefix: Vec<u8>,
    ) -> Result<(), Sv2Error> {
        self.cmd_tx
            .send(JobDistributorCmd::RegisterExtendedChannel {
                channel_id,
                extranonce_prefix,
            })
            .await
            .map_err(|_| Sv2Error::ChannelError("job distributor stopped".to_string()))
    }

    /// Unregister an extended channel.
    pub async fn unregister_extended_channel(&self, channel_id: u32) -> Result<(), Sv2Error> {
        self.cmd_tx
            .send(JobDistributorCmd::UnregisterExtendedChannel { channel_id })
            .await
            .map_err(|_| Sv2Error::ChannelError("job distributor stopped".to_string()))
    }

    /// Get the currently active extended job for an extended channel.
    pub async fn get_active_extended_job(
        &self,
        channel_id: u32,
    ) -> Result<Option<ActiveExtendedJobInfo>, Sv2Error> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.cmd_tx
            .send(JobDistributorCmd::GetActiveExtendedJob {
                channel_id,
                reply: reply_tx,
            })
            .await
            .map_err(|_| Sv2Error::ChannelError("job distributor stopped".to_string()))?;

        reply_rx
            .await
            .map_err(|_| Sv2Error::ChannelError("job distributor reply dropped".to_string()))
    }

    /// Look up an extended job state by job_id (for share validation).
    pub async fn get_extended_job_state(
        &self,
        job_id: u32,
    ) -> Result<Option<Sv2ExtendedJobState>, Sv2Error> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.cmd_tx
            .send(JobDistributorCmd::GetExtendedJobState {
                job_id,
                reply: reply_tx,
            })
            .await
            .map_err(|_| Sv2Error::ChannelError("job distributor stopped".to_string()))?;

        reply_rx
            .await
            .map_err(|_| Sv2Error::ChannelError("job distributor reply dropped".to_string()))
    }

    /// Subscribe to job events.
    ///
    /// Returns a watch receiver that is updated whenever a new job is ready
    /// for distribution. The per-connection write task should subscribe to
    /// this and serialize + encrypt the job for its downstream.
    pub fn subscribe_job_events(&self) -> watch::Receiver<Option<JobEvent>> {
        self.job_event_rx.clone()
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

    fn test_template(prev_hash: &str, height: u32) -> BlockTemplate {
        BlockTemplate {
            version: 0x20000000,
            rules: vec!["segwit".to_string()],
            vbavailable: HashMap::new(),
            vbrequired: 0,
            previousblockhash: prev_hash.to_string(),
            transactions: vec![],
            coinbaseaux: HashMap::new(),
            coinbasevalue: 625_000_000,
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
            height,
            default_witness_commitment: Some(
                "6a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf9"
                    .to_string(),
            ),
        }
    }

    fn test_output_distribution() -> Vec<OutputPair> {
        vec![OutputPair {
            address: bitcoin::Address::from_str("tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx")
                .unwrap()
                .assume_checked(),
            amount: bitcoin::Amount::from_sat(625_000_000),
        }]
    }

    use std::str::FromStr;

    #[tokio::test]
    async fn test_register_group_and_get_active_job_none() {
        let handle = start_job_distributor(0);

        // Register a group
        handle.register_group(1, vec![0x00; 6]).await.unwrap();

        // No template yet, so no active job
        let active = handle.get_active_job(1).await.unwrap();
        assert!(active.is_none());
    }

    #[tokio::test]
    async fn test_new_template_distributes_to_groups() {
        let handle = start_job_distributor(0);

        // Register two groups
        handle.register_group(10, vec![0x00; 6]).await.unwrap();
        handle.register_group(20, vec![0x01; 6]).await.unwrap();

        // Send a template
        let template = Arc::new(test_template(
            "000000000000000000034b3f4f4d3e3b2c1a0f0e0d0c0b0a0908070605040302",
            850000,
        ));
        handle
            .new_template(
                template,
                test_output_distribution(),
                b"P2Pool".to_vec(),
                None,
                None,
            )
            .await
            .unwrap();

        // Both groups should now have active jobs (get_active_job is request-reply,
        // so it synchronizes with the actor)
        let job10 = handle.get_active_job(10).await.unwrap();
        assert!(job10.is_some());
        let job10 = job10.unwrap();
        assert_eq!(job10.job_state.template.height, 850000);

        let job20 = handle.get_active_job(20).await.unwrap();
        assert!(job20.is_some());
        let job20 = job20.unwrap();

        // Different groups should have different job_ids (different extranonces)
        assert_ne!(job10.job_id, job20.job_id);
    }

    #[tokio::test]
    async fn test_get_job_state_by_id() {
        let handle = start_job_distributor(0);
        handle.register_group(1, vec![0x00; 6]).await.unwrap();

        let template = Arc::new(test_template(
            "000000000000000000034b3f4f4d3e3b2c1a0f0e0d0c0b0a0908070605040302",
            850000,
        ));
        handle
            .new_template(
                template,
                test_output_distribution(),
                b"P2Pool".to_vec(),
                None,
                None,
            )
            .await
            .unwrap();

        let active = handle.get_active_job(1).await.unwrap().unwrap();
        let state = handle.get_job_state(active.job_id).await.unwrap();
        assert!(state.is_some());
        assert_eq!(state.unwrap().job_id, active.job_id);

        // Unknown job_id
        let missing = handle.get_job_state(999999).await.unwrap();
        assert!(missing.is_none());
    }

    #[tokio::test]
    async fn test_unregister_group() {
        let handle = start_job_distributor(0);
        handle.register_group(1, vec![0x00; 6]).await.unwrap();

        let template = Arc::new(test_template(
            "000000000000000000034b3f4f4d3e3b2c1a0f0e0d0c0b0a0908070605040302",
            850000,
        ));
        handle
            .new_template(
                template,
                test_output_distribution(),
                b"P2Pool".to_vec(),
                None,
                None,
            )
            .await
            .unwrap();

        // Unregister (get_active_job below synchronizes with the actor)
        handle.unregister_group(1).await.unwrap();

        // Should no longer have an active job
        let active = handle.get_active_job(1).await.unwrap();
        assert!(active.is_none());
    }

    #[tokio::test]
    async fn test_new_block_clean_jobs_event() {
        let handle = start_job_distributor(0);
        let mut events = handle.subscribe_job_events();

        handle.register_group(1, vec![0x00; 6]).await.unwrap();

        // First template
        let t1 = Arc::new(test_template(
            "000000000000000000034b3f4f4d3e3b2c1a0f0e0d0c0b0a0908070605040302",
            850000,
        ));
        handle
            .new_template(
                t1,
                test_output_distribution(),
                b"P2Pool".to_vec(),
                None,
                None,
            )
            .await
            .unwrap();

        // Wait for event
        events.changed().await.unwrap();
        let event1 = events.borrow_and_update().clone().unwrap();
        assert!(event1.clean_jobs); // First template is always clean

        // Second template with SAME prev_hash (not a new block)
        let t2 = Arc::new(test_template(
            "000000000000000000034b3f4f4d3e3b2c1a0f0e0d0c0b0a0908070605040302",
            850000,
        ));
        handle
            .new_template(
                t2,
                test_output_distribution(),
                b"P2Pool".to_vec(),
                None,
                None,
            )
            .await
            .unwrap();

        events.changed().await.unwrap();
        let event2 = events.borrow_and_update().clone().unwrap();
        assert!(!event2.clean_jobs); // Same prev_hash -> not clean

        // Third template with DIFFERENT prev_hash (new block!)
        let t3 = Arc::new(test_template(
            "000000000000000000034b3f4f4d3e3b2c1a0f0e0d0c0b0a090807060504ffff",
            850001,
        ));
        handle
            .new_template(
                t3,
                test_output_distribution(),
                b"P2Pool".to_vec(),
                None,
                None,
            )
            .await
            .unwrap();

        events.changed().await.unwrap();
        let event3 = events.borrow_and_update().clone().unwrap();
        assert!(event3.clean_jobs); // Different prev_hash -> clean!
    }

    #[tokio::test]
    async fn test_register_group_after_template_gets_bootstrapped() {
        let handle = start_job_distributor(0);

        // Send a template first (no groups registered yet)
        let template = Arc::new(test_template(
            "000000000000000000034b3f4f4d3e3b2c1a0f0e0d0c0b0a0908070605040302",
            850000,
        ));
        handle
            .new_template(
                template,
                test_output_distribution(),
                b"P2Pool".to_vec(),
                None,
                None,
            )
            .await
            .unwrap();

        // Register group AFTER template was sent — should get bootstrapped.
        // The register_group command is queued after new_template in the same
        // mpsc channel, so the actor processes them in order.
        handle.register_group(42, vec![0x42; 6]).await.unwrap();

        // get_active_job is a request-reply, so it synchronizes with the actor:
        // the actor must have processed all preceding commands before responding.
        let active = handle.get_active_job(42).await.unwrap();
        assert!(active.is_some());
        assert_eq!(active.unwrap().job_state.template.height, 850000);
    }
}
