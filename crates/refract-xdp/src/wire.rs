//! Shared numeric constants for the XDP program and user-space loader.
//!
//! # Examples
//!
//! ```
//! assert_eq!(refract_xdp::DEFAULT_STUN_RATE_PER_SECOND, 100);
//! ```

/// STUN magic cookie from RFC 5389.
pub const STUN_MAGIC_COOKIE: u32 = 0x2112_a442;

/// Default accepted STUN binding request rate per source IP.
pub const DEFAULT_STUN_RATE_PER_SECOND: u32 = 100;

/// Default token bucket burst for STUN binding requests per source IP.
pub const DEFAULT_STUN_BURST: u32 = 100;

/// Number of stat counters exported by the eBPF program.
pub const STATS_COUNTERS: usize = 8;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exported_defaults_match_stage_contract() {
        assert_eq!(STUN_MAGIC_COOKIE, 0x2112_a442);
        assert_eq!(DEFAULT_STUN_RATE_PER_SECOND, 100);
        assert_eq!(DEFAULT_STUN_BURST, 100);
        assert_eq!(STATS_COUNTERS, 8);
    }
}
