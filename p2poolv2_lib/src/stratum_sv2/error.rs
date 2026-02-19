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

//! Error types for the SV2 subsystem.

use std::fmt;

/// Errors that can occur in the SV2 connection and protocol handling.
#[derive(Debug)]
pub enum Sv2Error {
    /// TCP I/O error
    Io(std::io::Error),
    /// Noise handshake failed
    HandshakeFailed(String),
    /// Handshake timed out
    HandshakeTimeout,
    /// Codec frame encoding/decoding error
    Codec(String),
    /// Invalid SV2 message
    InvalidMessage(String),
    /// SetupConnection validation failed
    SetupConnectionFailed(String),
    /// Protocol version not supported
    UnsupportedVersion { min: u16, max: u16 },
    /// Feature flag not supported (e.g. REQUIRES_WORK_SELECTION)
    UnsupportedFeature(String),
    /// Connection was closed by the remote peer
    ConnectionClosed,
    /// Channel send/receive error
    ChannelError(String),
    /// Configuration error
    Config(String),
}

impl fmt::Display for Sv2Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e) => write!(f, "SV2 I/O error: {e}"),
            Self::HandshakeFailed(e) => write!(f, "SV2 Noise handshake failed: {e}"),
            Self::HandshakeTimeout => write!(f, "SV2 Noise handshake timed out"),
            Self::Codec(e) => write!(f, "SV2 codec error: {e}"),
            Self::InvalidMessage(e) => write!(f, "SV2 invalid message: {e}"),
            Self::SetupConnectionFailed(e) => write!(f, "SV2 SetupConnection failed: {e}"),
            Self::UnsupportedVersion { min, max } => {
                write!(f, "SV2 unsupported protocol version range: {min}-{max}")
            }
            Self::UnsupportedFeature(e) => write!(f, "SV2 unsupported feature: {e}"),
            Self::ConnectionClosed => write!(f, "SV2 connection closed"),
            Self::ChannelError(e) => write!(f, "SV2 channel error: {e}"),
            Self::Config(e) => write!(f, "SV2 config error: {e}"),
        }
    }
}

impl std::error::Error for Sv2Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<std::io::Error> for Sv2Error {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}
