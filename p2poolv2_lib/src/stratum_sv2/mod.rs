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

//! Stratum V2 Mining Protocol support for downstream miners.
//!
//! This module implements the pool-side SV2 Mining Protocol, running alongside
//! the existing SV1 stratum server. Both protocols feed validated shares into
//! the shared [`crate::stratum::emission::Emission`] pipeline.
//!
//! # Module Structure
//!
//! - [`channels`] - Standard mining channel management (open, track, group)
//! - [`connection`] - TCP listener, Noise NX handshake, per-connection read/write tasks
//! - [`connections`] - Connection registry actor for tracking and broadcasting to SV2 clients
//! - [`error`] - Error types for the SV2 subsystem
//! - [`job_distributor`] - Job distribution actor (template -> channels)
//! - [`setup`] - SetupConnection message handler
//! - [`shares`] - SubmitSharesStandard handler and Emission bridge
//! - [`work`] - GBT block template to SV2 job conversion

pub mod channels;
pub mod connection;
pub mod connections;
pub mod difficulty;
pub mod error;
pub mod handler;
pub mod job_distributor;
pub mod setup;
pub mod shares;
pub mod work;

#[cfg(test)]
mod tests {
    //! Smoke tests to verify stratum-core types are importable.

    #[test]
    fn smoke_test_sv2_imports() {
        // Noise handshake
        use stratum_core::noise_sv2::Responder;

        // Mining protocol messages
        use stratum_core::mining_sv2::{
            NewExtendedMiningJob, NewMiningJob, OpenExtendedMiningChannel,
            OpenExtendedMiningChannelSuccess, OpenStandardMiningChannel,
            OpenStandardMiningChannelSuccess, SetNewPrevHash, SetTarget, SubmitSharesExtended,
            SubmitSharesStandard,
        };

        // Common messages
        use stratum_core::common_messages_sv2::{
            SetupConnection, SetupConnectionError, SetupConnectionSuccess,
        };

        // Binary codec
        use stratum_core::binary_sv2::{Deserialize, Serialize};

        // Codec and framing
        use stratum_core::codec_sv2::State;
        use stratum_core::framing_sv2::framing::Sv2Frame;

        // Verify Responder is constructable (it needs key material, just check the type exists)
        let _responder_type = std::any::type_name::<Responder>();

        // Verify message types exist by checking their type names
        let _setup = std::any::type_name::<SetupConnection<'static>>();
        let _setup_ok = std::any::type_name::<SetupConnectionSuccess>();
        let _setup_err = std::any::type_name::<SetupConnectionError<'static>>();
        let _open_std = std::any::type_name::<OpenStandardMiningChannel<'static>>();
        let _open_std_ok = std::any::type_name::<OpenStandardMiningChannelSuccess>();
        let _open_ext = std::any::type_name::<OpenExtendedMiningChannel<'static>>();
        let _open_ext_ok = std::any::type_name::<OpenExtendedMiningChannelSuccess<'static>>();
        let _new_job = std::any::type_name::<NewMiningJob<'static>>();
        let _new_ext_job = std::any::type_name::<NewExtendedMiningJob<'static>>();
        let _prev_hash = std::any::type_name::<SetNewPrevHash<'static>>();
        let _set_target = std::any::type_name::<SetTarget<'static>>();
        let _submit_std = std::any::type_name::<SubmitSharesStandard>();
        let _submit_ext = std::any::type_name::<SubmitSharesExtended<'static>>();

        // Verify codec/framing types
        let _state = std::any::type_name::<State>();
        let _frame = std::any::type_name::<Sv2Frame<SubmitSharesStandard, Vec<u8>>>();

        // Verify binary_sv2 traits are usable
        fn _assert_serialize<T: Serialize>() {}
        fn _assert_deserialize<T: for<'a> Deserialize<'a>>() {}
    }
}
