//! Configuration for bounded publisher jitter state.
//!
//! # Examples
//!
//! ```
//! # use refract_jitter::JitterConfig;
//! let config = JitterConfig::default();
//! assert_eq!(config.retransmit_window.as_millis(), 200);
//! ```

use std::time::Duration;

use crate::{JitterError, JitterResult};

/// Default RTX retention window.
pub const DEFAULT_RETRANSMIT_WINDOW: Duration = Duration::from_millis(200);
/// Default average RTP packet size used for bitrate-to-packet capacity.
pub const DEFAULT_AVERAGE_PACKET_BYTES: usize = 1_200;
/// Default maximum RTP packet bytes retained in the publisher buffer.
pub const DEFAULT_MAX_PACKET_BYTES: usize = 1_500;
/// Default maximum publisher bitrate used for capacity planning.
pub const DEFAULT_MAX_BITRATE_BPS: u64 = 5_000_000;
/// Default per-publisher jitter memory cap.
pub const DEFAULT_MEMORY_CAP_BYTES: usize = 1_048_576;
/// Maximum retained sequence slots addressable by a 16-bit RTP sequence.
pub const MAX_BUFFER_PACKETS: usize = 65_536;

const BITS_PER_BYTE: u128 = 8;
const MILLIS_PER_SECOND: u128 = 1_000;

/// Bounded jitter buffer configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct JitterConfig {
    /// Expected publisher bitrate bound in bits per second.
    pub max_bitrate_bps: u64,
    /// RTX retention window.
    pub retransmit_window: Duration,
    /// Average packet size used to translate bitrate into slot count.
    pub average_packet_bytes: usize,
    /// Maximum accepted packet bytes per retained RTP packet.
    pub max_packet_bytes: usize,
    /// Hard memory cap for one publisher buffer.
    pub memory_cap_bytes: usize,
}

impl Default for JitterConfig {
    fn default() -> Self {
        Self {
            max_bitrate_bps: DEFAULT_MAX_BITRATE_BPS,
            retransmit_window: DEFAULT_RETRANSMIT_WINDOW,
            average_packet_bytes: DEFAULT_AVERAGE_PACKET_BYTES,
            max_packet_bytes: DEFAULT_MAX_PACKET_BYTES,
            memory_cap_bytes: DEFAULT_MEMORY_CAP_BYTES,
        }
    }
}

impl JitterConfig {
    /// Validates configuration and returns the normalized copy.
    ///
    /// # Errors
    ///
    /// Returns [`JitterError::InvalidConfig`] when any configured bound is zero,
    /// when the memory cap cannot hold one packet, or when capacity arithmetic
    /// overflows `usize`.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_jitter::JitterConfig;
    /// assert!(JitterConfig::default().validate().is_ok());
    /// ```
    pub fn validate(self) -> JitterResult<Self> {
        if self.max_bitrate_bps == 0 {
            return Err(JitterError::InvalidConfig {
                field: "max_bitrate_bps",
            });
        }
        if self.retransmit_window.is_zero() {
            return Err(JitterError::InvalidConfig {
                field: "retransmit_window",
            });
        }
        if self.average_packet_bytes == 0 {
            return Err(JitterError::InvalidConfig {
                field: "average_packet_bytes",
            });
        }
        if self.max_packet_bytes == 0 {
            return Err(JitterError::InvalidConfig {
                field: "max_packet_bytes",
            });
        }
        if self.memory_cap_bytes < self.max_packet_bytes {
            return Err(JitterError::InvalidConfig {
                field: "memory_cap_bytes",
            });
        }

        let _capacity = self.capacity_packets()?;
        Ok(self)
    }

    /// Computes retained packet slots from bitrate, window, average packet size,
    /// RTP sequence space, and the hard memory cap.
    ///
    /// # Errors
    ///
    /// Returns [`JitterError::InvalidConfig`] if arithmetic overflows `usize` or
    /// if the config has invalid zero bounds.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_jitter::JitterConfig;
    /// let mut config = JitterConfig::default();
    /// config.max_bitrate_bps = 48_000;
    /// assert_eq!(config.capacity_packets()?, 1);
    /// # Ok::<(), refract_jitter::JitterError>(())
    /// ```
    pub fn capacity_packets(self) -> JitterResult<usize> {
        self.validate_without_capacity()?;

        let bitrate_bits = u128::from(self.max_bitrate_bps)
            .checked_mul(self.retransmit_window.as_millis())
            .ok_or(JitterError::InvalidConfig {
                field: "max_bitrate_bps",
            })?;
        let packet_bits = usize_to_u128(self.average_packet_bytes)?
            .checked_mul(BITS_PER_BYTE)
            .ok_or(JitterError::InvalidConfig {
                field: "average_packet_bytes",
            })?
            .checked_mul(MILLIS_PER_SECOND)
            .ok_or(JitterError::InvalidConfig {
                field: "average_packet_bytes",
            })?;
        let bitrate_slots = div_ceil_nonzero(bitrate_bits, packet_bits)?;
        let memory_slots = usize_to_u128(self.memory_cap_bytes / self.max_packet_bytes)?;
        let max_sequence_slots = usize_to_u128(MAX_BUFFER_PACKETS)?;
        let capped = bitrate_slots.min(memory_slots).min(max_sequence_slots);

        capped
            .max(1)
            .try_into()
            .map_err(|_error| JitterError::InvalidConfig {
                field: "capacity_packets",
            })
    }

    /// Returns the Stage 1 stability marker for this public API.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_jitter::{JitterConfig, Stability};
    /// assert_eq!(JitterConfig::default().stability(), Stability::Stage1);
    /// ```
    #[must_use]
    pub const fn stability(self) -> crate::Stability {
        crate::Stability::Stage1
    }

    const fn validate_without_capacity(self) -> JitterResult<()> {
        if self.max_bitrate_bps == 0 {
            return Err(JitterError::InvalidConfig {
                field: "max_bitrate_bps",
            });
        }
        if self.retransmit_window.is_zero() {
            return Err(JitterError::InvalidConfig {
                field: "retransmit_window",
            });
        }
        if self.average_packet_bytes == 0 {
            return Err(JitterError::InvalidConfig {
                field: "average_packet_bytes",
            });
        }
        if self.max_packet_bytes == 0 {
            return Err(JitterError::InvalidConfig {
                field: "max_packet_bytes",
            });
        }
        if self.memory_cap_bytes < self.max_packet_bytes {
            return Err(JitterError::InvalidConfig {
                field: "memory_cap_bytes",
            });
        }
        Ok(())
    }
}

const fn div_ceil_nonzero(numerator: u128, denominator: u128) -> JitterResult<u128> {
    if denominator == 0 {
        return Err(JitterError::InvalidConfig {
            field: "average_packet_bytes",
        });
    }

    Ok(numerator.saturating_add(denominator - 1) / denominator)
}

fn usize_to_u128(value: usize) -> JitterResult<u128> {
    u64::try_from(value)
        .map(u128::from)
        .map_err(|_error| JitterError::InvalidConfig { field: "usize" })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_capacity_uses_two_hundred_millis_at_expected_bitrate() {
        assert_eq!(JitterConfig::default().capacity_packets().unwrap(), 105);
    }

    #[test]
    fn memory_cap_limits_capacity() {
        let config = JitterConfig {
            max_bitrate_bps: 100_000_000,
            memory_cap_bytes: DEFAULT_MAX_PACKET_BYTES * 3,
            ..JitterConfig::default()
        };

        assert_eq!(config.capacity_packets().unwrap(), 3);
    }
}
