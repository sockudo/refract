//! Centralized bounded constants for refract.
//!
//! Production code must use these constants instead of repeating numeric
//! limits inline.

/// Number of bits in the lower half of a deterministic identifier.
pub const ID_LOW_BITS: u32 = 32;

/// Width of identifier hexadecimal display.
pub const ID_HEX_WIDTH: usize = 16;

/// Maximum RTP payload type value; payload types are seven-bit values.
pub const PAYLOAD_TYPE_MAX: u8 = 127;

/// Maximum simulcast or scalable-video spatial layer index represented by core
/// quality metadata.
pub const MAX_SPATIAL_LAYER: u8 = 7;

/// Maximum scalable-video temporal layer index represented by core quality
/// metadata.
pub const MAX_TEMPORAL_LAYER: u8 = 7;

/// Minimum normalized media quality score.
pub const QUALITY_SCORE_MIN: f32 = 0.0;

/// Maximum normalized media quality score.
pub const QUALITY_SCORE_MAX: f32 = 1.0;

/// Maximum number of structured fields emitted by one core error.
pub const ERROR_FIELD_CAPACITY: usize = 6;

/// Stable panic error code emitted by the panic hook.
pub const PANIC_ERROR_CODE: &str = "HSF-PANIC";

/// Panic metric name used by the panic hook.
pub const PANIC_METRIC_NAME: &str = "refract_core_panics_total";

/// Thread-name fragment used to identify runtime driver threads.
pub const RUNTIME_DRIVER_THREAD_NAME_FRAGMENT: &str = "runtime-driver";

/// Error code for I/O failures.
pub const ERROR_CODE_IO: &str = "HSF-1001";

/// Error code for parse failures.
pub const ERROR_CODE_PARSE: &str = "HSF-1002";

/// Error code for crypto failures.
pub const ERROR_CODE_CRYPTO: &str = "HSF-1003";

/// Error code for protocol failures.
pub const ERROR_CODE_PROTOCOL: &str = "HSF-1004";

/// Error code for capacity failures.
pub const ERROR_CODE_CAPACITY: &str = "HSF-1005";

/// Error code for timeout failures.
pub const ERROR_CODE_TIMEOUT: &str = "HSF-1006";

/// Error code for closed-resource failures.
pub const ERROR_CODE_CLOSED: &str = "HSF-1007";

/// Error code for configuration failures.
pub const ERROR_CODE_CONFIG: &str = "HSF-1008";

/// Error code for authentication failures.
pub const ERROR_CODE_AUTH: &str = "HSF-1009";

/// Error code for rate-limit failures.
pub const ERROR_CODE_RATE_LIMIT: &str = "HSF-1010";

/// Error code for internal failures.
pub const ERROR_CODE_INTERNAL: &str = "HSF-1011";

#[cfg(test)]
mod tests {
    use super::{
        ID_HEX_WIDTH, ID_LOW_BITS, MAX_SPATIAL_LAYER, MAX_TEMPORAL_LAYER, PAYLOAD_TYPE_MAX,
    };

    const _: () = assert!(super::ERROR_FIELD_CAPACITY >= 1);

    #[test]
    fn core_bounds_match_protocol_shapes() {
        assert_eq!(ID_LOW_BITS, u64::BITS / 2);
        assert_eq!(
            ID_HEX_WIDTH,
            usize::try_from(u64::BITS / 4).unwrap_or_default()
        );
        assert_eq!(PAYLOAD_TYPE_MAX, 0x7f);
        assert_eq!(MAX_SPATIAL_LAYER, 0x07);
        assert_eq!(MAX_TEMPORAL_LAYER, 0x07);
    }
}
