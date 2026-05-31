//! Metrics helpers for congestion-control surfaces.
//!
//! Hot-path callers record bounded-cardinality counters instead of logging.
//!
//! # Examples
//!
//! ```
//! # use refract_cc::{metrics::record_bandwidth_usage, BandwidthUsage};
//! record_bandwidth_usage(BandwidthUsage::Normal);
//! ```

use crate::{BandwidthUsage, PacketPriority, ProbeDecision};

/// Records a bandwidth-usage hypothesis.
///
/// # Examples
///
/// ```
/// # use refract_cc::{metrics::record_bandwidth_usage, BandwidthUsage};
/// record_bandwidth_usage(BandwidthUsage::Overusing);
/// ```
pub fn record_bandwidth_usage(usage: BandwidthUsage) {
    metrics::counter!(
        "refract.cc.gcc.usage",
        "usage" => usage.as_str(),
    )
    .increment(1);
}

/// Records a paced packet by priority.
///
/// # Examples
///
/// ```
/// # use refract_cc::{metrics::record_paced_packet, PacketPriority};
/// record_paced_packet(PacketPriority::Audio);
/// ```
pub fn record_paced_packet(priority: PacketPriority) {
    metrics::counter!(
        "refract.cc.pacer.packets",
        "priority" => priority.as_str(),
    )
    .increment(1);
}

/// Records a probe decision.
///
/// # Examples
///
/// ```
/// # use refract_cc::{metrics::record_probe_decision, ProbeDecision};
/// record_probe_decision(ProbeDecision::default());
/// ```
pub fn record_probe_decision(decision: ProbeDecision) {
    if decision.padding_bytes == 0 {
        metrics::counter!("refract.cc.prober.skipped").increment(1);
    } else {
        metrics::counter!("refract.cc.prober.padding_bytes")
            .increment(u64::try_from(decision.padding_bytes).unwrap_or(u64::MAX));
    }
}

/// Returns the Stage 1 stability marker for this public module API.
///
/// # Examples
///
/// ```
/// # use refract_cc::{metrics::stability, Stability};
/// assert_eq!(stability(), Stability::Stage1);
/// ```
#[must_use]
pub const fn stability() -> crate::Stability {
    crate::Stability::Stage1
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metric_helpers_are_callable() {
        record_bandwidth_usage(BandwidthUsage::Normal);
        record_paced_packet(PacketPriority::Padding);
        record_probe_decision(ProbeDecision::default());
    }
}
