//! Bounded-cardinality metrics for router slow-path events.
//!
//! Hot-path readers do not log. Slow-path snapshot publications record bounded
//! counters and gauges for operations visibility.
//!
//! # Examples
//!
//! ```
//! # use refract_router::metrics::record_snapshot;
//! record_snapshot(3);
//! ```

use metrics::{counter, gauge};

use crate::Stability;

/// Records a published routing snapshot.
///
/// # Examples
///
/// ```
/// # use refract_router::metrics::record_snapshot;
/// record_snapshot(2);
/// ```
pub fn record_snapshot(route_count: usize) {
    counter!("refract.router.snapshot.published").increment(1);
    let route_count_gauge =
        u32::try_from(route_count).map_or_else(|_error| f64::from(u32::MAX), f64::from);
    gauge!("refract.router.snapshot.routes").set(route_count_gauge);
}

/// Returns the Stage 1 stability marker for this public module.
///
/// # Examples
///
/// ```
/// # use refract_router::{metrics, Stability};
/// assert_eq!(metrics::stability(), Stability::Stage1);
/// ```
#[must_use]
pub const fn stability() -> Stability {
    Stability::Stage1
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metric_helpers_are_callable() {
        record_snapshot(4);
        assert_eq!(stability(), Stability::Stage1);
    }
}
