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

//! Difficulty ↔ target conversion utilities for SV2.
//!
//! SV2 uses a 32-byte `maximum_target` (little-endian U256) in `SetTarget`
//! and `OpenStandardMiningChannelSuccess` messages. The existing SV1 code
//! (and the `DifficultyAdjuster`) uses integer `difficulty` values.
//!
//! Bitcoin difficulty-1 target is:
//! `0x00000000FFFF0000000000000000000000000000000000000000000000000000`
//!
//! Conversion:
//! - `target = DIFF1_TARGET / difficulty`
//! - `difficulty = DIFF1_TARGET / target`
//!
//! All targets are represented as 32-byte arrays in **little-endian** byte
//! order (matching the SV2 `U256` wire encoding).

/// The difficulty-1 target as a big-endian 32-byte array.
///
/// `0x00000000FFFF0000...0000` — the numerator for `target = DIFF1 / difficulty`.
const DIFF1_TARGET_BE: [u8; 32] = [
    0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];

/// Convert an integer difficulty to a 32-byte target (little-endian).
///
/// `target = DIFF1_TARGET / difficulty`
///
/// If `difficulty` is 0 it is treated as 1 (the easiest possible target).
pub fn difficulty_to_target(difficulty: u64) -> [u8; 32] {
    let difficulty = difficulty.max(1);

    // Perform big-integer division: DIFF1_TARGET / difficulty.
    // We treat DIFF1_TARGET as a 256-bit big-endian number and do
    // long division by a 64-bit divisor, producing a 256-bit quotient.
    let mut quotient_be = [0u8; 32];
    let mut remainder: u128 = 0;

    for i in 0..32 {
        remainder = (remainder << 8) | DIFF1_TARGET_BE[i] as u128;
        let q = remainder / difficulty as u128;
        quotient_be[i] = q as u8;
        remainder %= difficulty as u128;
    }

    // Convert big-endian quotient to little-endian (SV2 wire format).
    let mut target_le = [0u8; 32];
    for i in 0..32 {
        target_le[i] = quotient_be[31 - i];
    }
    target_le
}

/// Convert a 32-byte target (little-endian) to an integer difficulty.
///
/// `difficulty = DIFF1_TARGET / target`
///
/// If the target is zero or higher than DIFF1, returns 1.
pub fn target_to_difficulty(target_le: &[u8; 32]) -> u64 {
    // Convert little-endian to big-endian for comparison / division.
    let mut target_be = [0u8; 32];
    for i in 0..32 {
        target_be[i] = target_le[31 - i];
    }

    // If target is all zeros, return difficulty 1 (avoid division by zero).
    if target_be == [0u8; 32] {
        return 1;
    }

    // Simple approach: divide DIFF1_TARGET by target as big-endian byte arrays.
    // Since we only need a u64 result, we can use a simplified division.
    //
    // We find the ratio by treating both as f64 (losing some precision for
    // very large difficulties, but sufficient for mining difficulty values).
    let diff1_f64 = be_bytes_to_f64(&DIFF1_TARGET_BE);
    let target_f64 = be_bytes_to_f64(&target_be);

    if target_f64 == 0.0 {
        return 1;
    }

    let difficulty = diff1_f64 / target_f64;

    // Clamp to valid range.
    if difficulty < 1.0 {
        1
    } else if difficulty > u64::MAX as f64 {
        u64::MAX
    } else {
        difficulty.round() as u64
    }
}

/// Convert a 32-byte big-endian number to f64 (approximate).
///
/// Only the most significant non-zero bytes matter for the floating-point
/// approximation. This is sufficient for difficulty conversions.
fn be_bytes_to_f64(bytes: &[u8; 32]) -> f64 {
    let mut value: f64 = 0.0;
    for &b in bytes.iter() {
        value = value * 256.0 + b as f64;
    }
    value
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_difficulty_1_produces_diff1_target() {
        let target = difficulty_to_target(1);
        // Convert to big-endian for comparison.
        let mut target_be = [0u8; 32];
        for i in 0..32 {
            target_be[i] = target[31 - i];
        }
        assert_eq!(target_be, DIFF1_TARGET_BE);
    }

    #[test]
    fn test_difficulty_roundtrip() {
        for diff in [1, 2, 10, 100, 1000, 65536, 1_000_000, 100_000_000] {
            let target = difficulty_to_target(diff);
            let recovered = target_to_difficulty(&target);
            // Allow +-1 rounding for large difficulties.
            assert!(
                recovered == diff || recovered == diff - 1 || recovered == diff + 1,
                "roundtrip failed for diff={diff}: recovered={recovered}"
            );
        }
    }

    #[test]
    fn test_difficulty_0_treated_as_1() {
        let target = difficulty_to_target(0);
        let target_1 = difficulty_to_target(1);
        assert_eq!(target, target_1);
    }

    #[test]
    fn test_higher_difficulty_produces_lower_target() {
        let target_low = difficulty_to_target(10);
        let target_high = difficulty_to_target(1000);
        // Higher difficulty -> smaller target.
        // Compare as big-endian (most significant byte first).
        let low_be = le_to_be(&target_low);
        let high_be = le_to_be(&target_high);
        assert!(high_be < low_be);
    }

    #[test]
    fn test_zero_target_returns_difficulty_1() {
        let zero = [0u8; 32];
        assert_eq!(target_to_difficulty(&zero), 1);
    }

    #[test]
    fn test_all_ff_target_returns_difficulty_1() {
        // An all-0xff target is larger than DIFF1, so difficulty should be 1.
        let all_ff = [0xff; 32];
        assert_eq!(target_to_difficulty(&all_ff), 1);
    }

    /// Helper: convert LE to BE for comparison.
    fn le_to_be(le: &[u8; 32]) -> [u8; 32] {
        let mut be = [0u8; 32];
        for i in 0..32 {
            be[i] = le[31 - i];
        }
        be
    }
}
