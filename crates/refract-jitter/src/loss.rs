//! RTP ingress loss detection by wrap-aware expected sequence number.
//!
//! # Examples
//!
//! ```
//! # use std::time::Duration;
//! # use refract_jitter::{LossDetector, NackAggregator, RtpSequenceNumber};
//! let mut detector = LossDetector::new();
//! let mut nacks = NackAggregator::default();
//! assert!(
//!     detector
//!         .observe(RtpSequenceNumber::new(1), Duration::ZERO, &mut nacks)
//!         .is_empty()
//! );
//! let batch = detector.observe(RtpSequenceNumber::new(3), Duration::ZERO, &mut nacks);
//! assert_eq!(batch.sequences(), &[RtpSequenceNumber::new(2)]);
//! ```

use std::time::Duration;

use crate::{NackAggregator, NackBatch, RtpSequenceNumber};

const HALF_SEQUENCE_SPACE: u16 = 0x8000;

/// Per-publisher ingress loss detector.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct LossDetector {
    expected_next: Option<RtpSequenceNumber>,
}

impl LossDetector {
    /// Creates an empty loss detector.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_jitter::LossDetector;
    /// assert_eq!(LossDetector::new().expected_next(), None);
    /// ```
    #[must_use]
    pub const fn new() -> Self {
        Self {
            expected_next: None,
        }
    }

    /// Observes an ingress RTP sequence number and emits one upstream `NACK`
    /// batch when a forward gap is detected.
    ///
    /// Reordered or duplicate packets older than `expected_next` do not advance
    /// the detector and do not emit `NACK`s.
    ///
    /// # Examples
    ///
    /// ```
    /// # use std::time::Duration;
    /// # use refract_jitter::{LossDetector, NackAggregator, RtpSequenceNumber};
    /// let mut detector = LossDetector::new();
    /// let mut nacks = NackAggregator::default();
    /// detector.observe(RtpSequenceNumber::new(10), Duration::ZERO, &mut nacks);
    /// let batch = detector.observe(RtpSequenceNumber::new(12), Duration::ZERO, &mut nacks);
    /// assert_eq!(batch.sequences(), &[RtpSequenceNumber::new(11)]);
    /// ```
    pub fn observe(
        &mut self,
        sequence: RtpSequenceNumber,
        now: Duration,
        nacks: &mut NackAggregator,
    ) -> NackBatch {
        let Some(expected) = self.expected_next else {
            self.expected_next = Some(sequence.next());
            return NackBatch::new();
        };

        if sequence == expected {
            self.expected_next = Some(sequence.next());
            return NackBatch::new();
        }

        let distance = expected.forward_distance_to(sequence);
        if (1..HALF_SEQUENCE_SPACE).contains(&distance) {
            self.expected_next = Some(sequence.next());
            return nacks.submit(
                (0..distance).map(|offset| expected.wrapping_add(offset)),
                now,
            );
        }

        NackBatch::new()
    }

    /// Returns the currently expected next sequence number.
    ///
    /// # Examples
    ///
    /// ```
    /// # use std::time::Duration;
    /// # use refract_jitter::{LossDetector, NackAggregator, RtpSequenceNumber};
    /// let mut detector = LossDetector::new();
    /// let mut nacks = NackAggregator::default();
    /// detector.observe(RtpSequenceNumber::new(5), Duration::ZERO, &mut nacks);
    /// assert_eq!(detector.expected_next(), Some(RtpSequenceNumber::new(6)));
    /// ```
    #[must_use]
    pub const fn expected_next(self) -> Option<RtpSequenceNumber> {
        self.expected_next
    }

    /// Returns the Stage 1 stability marker for this public API.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_jitter::{LossDetector, Stability};
    /// assert_eq!(LossDetector::new().stability(), Stability::Stage1);
    /// ```
    #[must_use]
    pub const fn stability(self) -> crate::Stability {
        crate::Stability::Stage1
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_loss_and_ignores_reorder_and_duplicates() {
        let mut detector = LossDetector::new();
        let mut nacks = NackAggregator::default();

        assert!(
            detector
                .observe(RtpSequenceNumber::new(1), Duration::ZERO, &mut nacks)
                .is_empty()
        );
        assert_eq!(
            detector
                .observe(RtpSequenceNumber::new(3), Duration::ZERO, &mut nacks)
                .sequences(),
            &[RtpSequenceNumber::new(2)]
        );
        assert!(
            detector
                .observe(RtpSequenceNumber::new(2), Duration::ZERO, &mut nacks)
                .is_empty()
        );
        assert!(
            detector
                .observe(RtpSequenceNumber::new(3), Duration::ZERO, &mut nacks)
                .is_empty()
        );
    }

    #[test]
    fn detects_rollover_gap() {
        let mut detector = LossDetector::new();
        let mut nacks = NackAggregator::default();

        assert!(
            detector
                .observe(
                    RtpSequenceNumber::new(u16::MAX - 1),
                    Duration::ZERO,
                    &mut nacks
                )
                .is_empty()
        );
        assert_eq!(
            detector
                .observe(RtpSequenceNumber::new(1), Duration::ZERO, &mut nacks)
                .sequences(),
            &[RtpSequenceNumber::new(u16::MAX), RtpSequenceNumber::new(0)]
        );
    }

    #[test]
    fn loss_and_nack_hot_path_does_not_allocate() {
        let mut detector = LossDetector::new();
        let mut nacks = NackAggregator::default();

        refract_slab::assert_no_alloc!(|| {
            assert!(
                detector
                    .observe(RtpSequenceNumber::new(10), Duration::ZERO, &mut nacks)
                    .is_empty()
            );
            assert_eq!(
                detector
                    .observe(RtpSequenceNumber::new(13), Duration::ZERO, &mut nacks)
                    .sequences(),
                &[RtpSequenceNumber::new(11), RtpSequenceNumber::new(12)]
            );
            assert!(
                detector
                    .observe(RtpSequenceNumber::new(12), Duration::ZERO, &mut nacks)
                    .is_empty()
            );
        });
    }
}
