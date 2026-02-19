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

//! SetupConnection message handler for SV2.
//!
//! The first application-layer message on every SV2 connection must be
//! `SetupConnection`. This module validates the request and produces
//! the appropriate `Success` or `Error` response.

use stratum_core::common_messages_sv2::{
    Protocol, SetupConnection, SetupConnectionError, SetupConnectionSuccess,
};
use tracing::debug;

use super::error::Sv2Error;

/// The SV2 protocol version we support.
pub const SUPPORTED_SV2_VERSION: u16 = 2;

/// Flags we support in SetupConnection.
///
/// `REQUIRES_STANDARD_JOBS` (bit 0) = the pool always sends standard jobs
/// (pre-computed merkle root). This is always true for standard channels.
///
/// We do NOT support `REQUIRES_WORK_SELECTION` (bit 1) since Job Declaration
/// is out of scope.
const SUPPORTED_FLAGS: u32 = 0x0000_0001; // REQUIRES_STANDARD_JOBS

/// Flag bit for REQUIRES_WORK_SELECTION (Job Declaration protocol).
const FLAG_REQUIRES_WORK_SELECTION: u32 = 0x0000_0002;

/// Result of a successful SetupConnection validation.
#[derive(Debug)]
pub struct SetupConnectionResult {
    /// The negotiated protocol version.
    pub version: u16,
    /// The negotiated feature flags.
    pub flags: u32,
}

/// Validate an incoming `SetupConnection` message and produce the response.
///
/// Returns `Ok(SetupConnectionResult)` on success, which should be used to
/// construct a `SetupConnectionSuccess` response. Returns `Err` with an
/// appropriate error message and code on failure.
pub fn validate_setup_connection(
    msg: &SetupConnection<'_>,
) -> Result<SetupConnectionResult, Sv2Error> {
    // Must be Mining Protocol
    let protocol = msg.protocol;
    if protocol != Protocol::MiningProtocol {
        return Err(Sv2Error::SetupConnectionFailed(format!(
            "unsupported protocol: expected MiningProtocol, got {protocol:?}"
        )));
    }

    // Negotiate version: we support exactly version 2
    let min_version = msg.min_version;
    let max_version = msg.max_version;
    if SUPPORTED_SV2_VERSION < min_version || SUPPORTED_SV2_VERSION > max_version {
        return Err(Sv2Error::UnsupportedVersion {
            min: min_version,
            max: max_version,
        });
    }

    // Check feature flags
    let requested_flags = msg.flags;
    if requested_flags & FLAG_REQUIRES_WORK_SELECTION != 0 {
        return Err(Sv2Error::UnsupportedFeature(
            "REQUIRES_WORK_SELECTION (Job Declaration not supported)".to_string(),
        ));
    }

    // Negotiate flags: intersection of what we support and what they request
    let negotiated_flags = requested_flags & SUPPORTED_FLAGS;

    debug!(
        version = SUPPORTED_SV2_VERSION,
        flags = negotiated_flags,
        "SetupConnection validated"
    );

    Ok(SetupConnectionResult {
        version: SUPPORTED_SV2_VERSION,
        flags: negotiated_flags,
    })
}

/// Build a `SetupConnectionSuccess` message from the validation result.
pub fn build_setup_connection_success(result: &SetupConnectionResult) -> SetupConnectionSuccess {
    SetupConnectionSuccess {
        used_version: result.version,
        flags: result.flags,
    }
}

/// Build a `SetupConnectionError` message from an error.
pub fn build_setup_connection_error(error: &Sv2Error) -> SetupConnectionError<'static> {
    let (flags, error_code) = match error {
        Sv2Error::UnsupportedVersion { .. } => (
            0,
            "unsupported-version"
                .to_string()
                .try_into()
                .expect("static error code"),
        ),
        Sv2Error::UnsupportedFeature(_) => (
            0,
            "unsupported-feature-flags"
                .to_string()
                .try_into()
                .expect("static error code"),
        ),
        Sv2Error::SetupConnectionFailed(_) => (
            0,
            "unsupported-protocol"
                .to_string()
                .try_into()
                .expect("static error code"),
        ),
        _ => (
            0,
            "unknown-error"
                .to_string()
                .try_into()
                .expect("static error code"),
        ),
    };

    SetupConnectionError { flags, error_code }
}

#[cfg(test)]
mod tests {
    use super::*;
    use stratum_core::common_messages_sv2::Protocol;

    fn make_setup_connection(
        protocol: Protocol,
        min_version: u16,
        max_version: u16,
        flags: u32,
    ) -> SetupConnection<'static> {
        SetupConnection {
            protocol,
            min_version,
            max_version,
            flags,
            endpoint_host: "pool.example.com".to_string().try_into().unwrap(),
            endpoint_port: 3334,
            vendor: "test".to_string().try_into().unwrap(),
            hardware_version: "v1".to_string().try_into().unwrap(),
            firmware: "fw1".to_string().try_into().unwrap(),
            device_id: "dev1".to_string().try_into().unwrap(),
        }
    }

    #[test]
    fn test_valid_setup_connection() {
        let msg = make_setup_connection(Protocol::MiningProtocol, 2, 2, 0x0000_0001);
        let result = validate_setup_connection(&msg);
        assert!(result.is_ok());
        let result = result.unwrap();
        assert_eq!(result.version, 2);
        assert_eq!(result.flags, 0x0000_0001); // REQUIRES_STANDARD_JOBS
    }

    #[test]
    fn test_valid_setup_connection_version_range() {
        // Client supports versions 1-3, we support 2
        let msg = make_setup_connection(Protocol::MiningProtocol, 1, 3, 0);
        let result = validate_setup_connection(&msg);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().version, 2);
    }

    #[test]
    fn test_setup_connection_version_mismatch() {
        // Client only supports version 1
        let msg = make_setup_connection(Protocol::MiningProtocol, 0, 1, 0);
        let result = validate_setup_connection(&msg);
        assert!(matches!(result, Err(Sv2Error::UnsupportedVersion { .. })));
    }

    #[test]
    fn test_setup_connection_work_selection_rejected() {
        let msg =
            make_setup_connection(Protocol::MiningProtocol, 2, 2, FLAG_REQUIRES_WORK_SELECTION);
        let result = validate_setup_connection(&msg);
        assert!(matches!(result, Err(Sv2Error::UnsupportedFeature(_))));
    }

    #[test]
    fn test_setup_connection_success_message() {
        let result = SetupConnectionResult {
            version: 2,
            flags: 1,
        };
        let success = build_setup_connection_success(&result);
        assert_eq!(success.used_version, 2);
        assert_eq!(success.flags, 1);
    }

    #[test]
    fn test_setup_connection_error_message() {
        let err = Sv2Error::UnsupportedVersion { min: 1, max: 1 };
        let error_msg = build_setup_connection_error(&err);
        assert_eq!(error_msg.flags, 0);
    }
}
