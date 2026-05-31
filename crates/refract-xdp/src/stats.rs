//! XDP counter aggregation exposed by the eBPF stats map.
//!
//! # Examples
//!
//! ```
//! let stats = refract_xdp::XdpStats::default();
//! assert_eq!(stats.passed(), 0);
//! ```

use crate::wire::STATS_COUNTERS;

/// Stable counter identifiers matching the eBPF stats map indexes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum CounterId {
    /// Packets passed through the XDP program.
    Passed = 0,
    /// UDP packets dropped because their payload is unsupported.
    DroppedUnsupportedUdp = 1,
    /// Target-port fragmented packets dropped before socket delivery.
    DroppedFragmented = 2,
    /// STUN binding requests dropped by the token bucket.
    DroppedStunRateLimited = 3,
    /// STUN binding requests accepted.
    AcceptedStunBinding = 4,
    /// Other STUN packets accepted.
    AcceptedStunOther = 5,
    /// DTLS packets accepted.
    AcceptedDtls = 6,
    /// SRTP or SRTCP packets accepted.
    AcceptedSrtp = 7,
}

/// Snapshot of XDP counters summed across CPUs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct XdpStats {
    counters: [u64; STATS_COUNTERS],
}

impl XdpStats {
    /// Builds a stats snapshot from raw counter indexes.
    ///
    /// # Examples
    ///
    /// ```
    /// let stats = refract_xdp::XdpStats::from_counters([1, 2, 3, 4, 5, 6, 7, 8]);
    /// assert_eq!(stats.passed(), 1);
    /// ```
    #[must_use]
    pub const fn from_counters(counters: [u64; STATS_COUNTERS]) -> Self {
        Self { counters }
    }

    /// Returns a counter by stable identifier.
    ///
    /// # Examples
    ///
    /// ```
    /// let stats = refract_xdp::XdpStats::from_counters([9, 0, 0, 0, 0, 0, 0, 0]);
    /// assert_eq!(stats.counter(refract_xdp::CounterId::Passed), 9);
    /// ```
    #[must_use]
    pub const fn counter(self, id: CounterId) -> u64 {
        self.counters[id as usize]
    }

    /// Returns total packets passed.
    #[must_use]
    pub const fn passed(self) -> u64 {
        self.counter(CounterId::Passed)
    }

    /// Returns packets dropped for unsupported UDP payloads.
    #[must_use]
    pub const fn dropped_unsupported_udp(self) -> u64 {
        self.counter(CounterId::DroppedUnsupportedUdp)
    }

    /// Returns fragmented packets dropped on the media port.
    #[must_use]
    pub const fn dropped_fragmented(self) -> u64 {
        self.counter(CounterId::DroppedFragmented)
    }

    /// Returns STUN binding requests dropped by rate limiting.
    #[must_use]
    pub const fn dropped_stun_rate_limited(self) -> u64 {
        self.counter(CounterId::DroppedStunRateLimited)
    }

    /// Returns accepted STUN binding packets.
    #[must_use]
    pub const fn accepted_stun_binding(self) -> u64 {
        self.counter(CounterId::AcceptedStunBinding)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counter_accessors_use_stable_indexes() {
        let stats = XdpStats::from_counters([1, 2, 3, 4, 5, 6, 7, 8]);
        assert_eq!(stats.passed(), 1);
        assert_eq!(stats.dropped_unsupported_udp(), 2);
        assert_eq!(stats.dropped_fragmented(), 3);
        assert_eq!(stats.dropped_stun_rate_limited(), 4);
        assert_eq!(stats.accepted_stun_binding(), 5);
    }
}
