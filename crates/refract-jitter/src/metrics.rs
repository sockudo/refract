//! Metrics helpers for bounded jitter and feedback paths.
//!
//! Hot-path callers record bounded-cardinality counters instead of logging.
//!
//! # Examples
//!
//! ```
//! # use refract_jitter::{metrics::record_packet_insert, InsertOutcome};
//! record_packet_insert(InsertOutcome::Stored);
//! ```

use crate::{FeedbackKind, InsertOutcome, NackBatch};

/// Reason a `NACK` candidate was suppressed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NackSuppressReason {
    /// Sequence was already `NACK`ed inside the dedupe window.
    DedupeWindow,
    /// Per subscriber/publisher rate limit was exhausted.
    RateLimited,
    /// The fixed upstream `NACK` batch was full.
    BatchFull,
}

impl NackSuppressReason {
    /// Returns a bounded metrics label.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_jitter::metrics::NackSuppressReason;
    /// assert_eq!(NackSuppressReason::RateLimited.as_str(), "rate_limited");
    /// ```
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::DedupeWindow => "dedupe_window",
            Self::RateLimited => "rate_limited",
            Self::BatchFull => "batch_full",
        }
    }

    /// Returns the Stage 1 stability marker for this public API.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_jitter::{metrics::NackSuppressReason, Stability};
    /// assert_eq!(
    ///     NackSuppressReason::DedupeWindow.stability(),
    ///     Stability::Stage1
    /// );
    /// ```
    #[must_use]
    pub const fn stability(self) -> crate::Stability {
        crate::Stability::Stage1
    }
}

/// Records a publisher-buffer insert outcome.
///
/// # Examples
///
/// ```
/// # use refract_jitter::{metrics::record_packet_insert, InsertOutcome};
/// record_packet_insert(InsertOutcome::Stored);
/// ```
pub fn record_packet_insert(outcome: InsertOutcome) {
    metrics::counter!(
        "refract.jitter.publisher_buffer.inserts",
        "outcome" => outcome.as_str(),
    )
    .increment(1);
}

/// Records one forwarded upstream `NACK` batch.
///
/// # Examples
///
/// ```
/// # use refract_jitter::{metrics::record_nack_batch, NackBatch, RtpSequenceNumber};
/// let mut batch = NackBatch::new();
/// assert!(batch.try_push(RtpSequenceNumber::new(1)));
/// record_nack_batch(&batch);
/// ```
pub fn record_nack_batch(batch: &NackBatch) {
    if batch.is_empty() {
        return;
    }
    metrics::counter!("refract.jitter.nack.batches").increment(1);
    metrics::counter!("refract.jitter.nack.packets")
        .increment(u64::try_from(batch.len()).unwrap_or(u64::MAX));
}

/// Records a suppressed `NACK` candidate.
///
/// # Examples
///
/// ```
/// # use refract_jitter::metrics::{record_nack_suppressed, NackSuppressReason};
/// record_nack_suppressed(NackSuppressReason::DedupeWindow);
/// ```
pub fn record_nack_suppressed(reason: NackSuppressReason) {
    metrics::counter!(
        "refract.jitter.nack.suppressed",
        "reason" => reason.as_str(),
    )
    .increment(1);
}

/// Records whether `PLI` or `FIR` feedback was forwarded after coalescing.
///
/// # Examples
///
/// ```
/// # use refract_jitter::{metrics::record_feedback_request, FeedbackKind};
/// record_feedback_request(FeedbackKind::Pli, true);
/// ```
pub fn record_feedback_request(kind: FeedbackKind, forwarded: bool) {
    metrics::counter!(
        "refract.jitter.feedback.requests",
        "kind" => kind.as_str(),
        "outcome" => if forwarded { "forwarded" } else { "coalesced" },
    )
    .increment(1);
}

/// Returns the Stage 1 stability marker for this public module API.
///
/// # Examples
///
/// ```
/// # use refract_jitter::{metrics::stability, Stability};
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
    fn suppress_reason_labels_are_bounded() {
        assert_eq!(NackSuppressReason::DedupeWindow.as_str(), "dedupe_window");
        assert_eq!(NackSuppressReason::RateLimited.as_str(), "rate_limited");
        assert_eq!(NackSuppressReason::BatchFull.as_str(), "batch_full");
    }
}
