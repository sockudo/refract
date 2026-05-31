//! Fixed-size `NACK` batching, dedupe, and rate limiting.
//!
//! # Examples
//!
//! ```
//! # use std::time::Duration;
//! # use refract_jitter::{NackAggregator, NackRateLimit, RtpSequenceNumber};
//! let mut aggregator = NackAggregator::new(
//!     Duration::from_millis(20),
//!     NackRateLimit::new(10, Duration::from_secs(1))?,
//! );
//! let batch = aggregator.submit([RtpSequenceNumber::new(4)], Duration::ZERO);
//! assert_eq!(batch.len(), 1);
//! # Ok::<(), refract_jitter::JitterError>(())
//! ```

use std::time::Duration;

use crate::{JitterError, JitterResult, RtpSequenceNumber};

/// Per-subscriber bounded `NACK` history size.
pub const MAX_NACK_HISTORY: usize = 256;
/// Default `NACK` dedupe window.
pub const DEFAULT_NACK_DEDUPE_WINDOW: Duration = Duration::from_millis(20);
/// Default upstream `NACK` rate-limit window.
pub const DEFAULT_NACK_RATE_WINDOW: Duration = Duration::from_secs(1);
/// Default upstream `NACK` batches per rate-limit window for one subscriber/publisher pair.
pub const DEFAULT_NACKS_PER_WINDOW: u16 = 64;

/// Fixed-capacity upstream `NACK` batch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NackBatch {
    sequences: [RtpSequenceNumber; MAX_NACK_HISTORY],
    len: usize,
}

impl Default for NackBatch {
    fn default() -> Self {
        Self::new()
    }
}

impl NackBatch {
    /// Creates an empty fixed-capacity batch.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_jitter::NackBatch;
    /// assert!(NackBatch::new().is_empty());
    /// ```
    #[must_use]
    pub const fn new() -> Self {
        Self {
            sequences: [RtpSequenceNumber::new(0); MAX_NACK_HISTORY],
            len: 0,
        }
    }

    /// Appends `sequence` when capacity remains.
    ///
    /// Returns `false` if the batch is full.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_jitter::{NackBatch, RtpSequenceNumber};
    /// let mut batch = NackBatch::new();
    /// assert!(batch.try_push(RtpSequenceNumber::new(3)));
    /// assert_eq!(batch.len(), 1);
    /// ```
    pub const fn try_push(&mut self, sequence: RtpSequenceNumber) -> bool {
        if self.len == MAX_NACK_HISTORY {
            return false;
        }
        self.sequences[self.len] = sequence;
        self.len += 1;
        true
    }

    /// Returns the number of sequence numbers in the batch.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_jitter::NackBatch;
    /// assert_eq!(NackBatch::new().len(), 0);
    /// ```
    #[must_use]
    pub const fn len(&self) -> usize {
        self.len
    }

    /// Returns whether the batch is empty.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_jitter::NackBatch;
    /// assert!(NackBatch::new().is_empty());
    /// ```
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Returns a borrowed slice of sequence numbers in insertion order.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_jitter::{NackBatch, RtpSequenceNumber};
    /// let mut batch = NackBatch::new();
    /// assert!(batch.try_push(RtpSequenceNumber::new(9)));
    /// assert_eq!(batch.sequences(), &[RtpSequenceNumber::new(9)]);
    /// ```
    #[must_use]
    pub fn sequences(&self) -> &[RtpSequenceNumber] {
        &self.sequences[..self.len]
    }

    /// Iterates over sequence numbers in insertion order.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_jitter::{NackBatch, RtpSequenceNumber};
    /// let mut batch = NackBatch::new();
    /// assert!(batch.try_push(RtpSequenceNumber::new(2)));
    /// assert_eq!(
    ///     batch.iter().collect::<Vec<_>>(),
    ///     vec![RtpSequenceNumber::new(2)]
    /// );
    /// ```
    #[must_use]
    pub fn iter(&self) -> impl ExactSizeIterator<Item = RtpSequenceNumber> + '_ {
        self.sequences().iter().copied()
    }

    /// Returns the Stage 1 stability marker for this public API.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_jitter::{NackBatch, Stability};
    /// assert_eq!(NackBatch::new().stability(), Stability::Stage1);
    /// ```
    #[must_use]
    pub const fn stability(&self) -> crate::Stability {
        crate::Stability::Stage1
    }
}

/// Token-bucket-like rate limit for one subscriber/publisher `NACK` lane.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NackRateLimit {
    max_per_window: u16,
    window: Duration,
    window_start: Duration,
    sent_in_window: u16,
}

impl Default for NackRateLimit {
    fn default() -> Self {
        Self {
            max_per_window: DEFAULT_NACKS_PER_WINDOW,
            window: DEFAULT_NACK_RATE_WINDOW,
            window_start: Duration::ZERO,
            sent_in_window: 0,
        }
    }
}

impl NackRateLimit {
    /// Creates a rate limit for one subscriber/publisher `NACK` lane.
    ///
    /// # Errors
    ///
    /// Returns [`JitterError::InvalidConfig`] when `max_per_window` is zero or
    /// `window` is zero.
    ///
    /// # Examples
    ///
    /// ```
    /// # use std::time::Duration;
    /// # use refract_jitter::NackRateLimit;
    /// let limit = NackRateLimit::new(8, Duration::from_secs(1))?;
    /// assert_eq!(limit.max_per_window(), 8);
    /// # Ok::<(), refract_jitter::JitterError>(())
    /// ```
    pub const fn new(max_per_window: u16, window: Duration) -> JitterResult<Self> {
        if max_per_window == 0 {
            return Err(JitterError::InvalidConfig {
                field: "max_per_window",
            });
        }
        if window.is_zero() {
            return Err(JitterError::InvalidConfig { field: "window" });
        }

        Ok(Self {
            max_per_window,
            window,
            window_start: Duration::ZERO,
            sent_in_window: 0,
        })
    }

    /// Returns maximum forwarded `NACK` batches per window.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_jitter::NackRateLimit;
    /// assert_eq!(NackRateLimit::default().max_per_window(), 64);
    /// ```
    #[must_use]
    pub const fn max_per_window(self) -> u16 {
        self.max_per_window
    }

    /// Returns the rate-limit window.
    ///
    /// # Examples
    ///
    /// ```
    /// # use std::time::Duration;
    /// # use refract_jitter::NackRateLimit;
    /// assert_eq!(NackRateLimit::default().window(), Duration::from_secs(1));
    /// ```
    #[must_use]
    pub const fn window(self) -> Duration {
        self.window
    }

    /// Returns the Stage 1 stability marker for this public API.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_jitter::{NackRateLimit, Stability};
    /// assert_eq!(NackRateLimit::default().stability(), Stability::Stage1);
    /// ```
    #[must_use]
    pub const fn stability(self) -> crate::Stability {
        crate::Stability::Stage1
    }

    fn allow(&mut self, now: Duration) -> bool {
        if now.saturating_sub(self.window_start) >= self.window {
            self.window_start = now;
            self.sent_in_window = 0;
        }

        if self.sent_in_window >= self.max_per_window {
            return false;
        }
        self.sent_in_window += 1;
        true
    }
}

/// Deduplicating `NACK` aggregator for one subscriber/publisher pair.
#[derive(Debug, Clone)]
pub struct NackAggregator {
    history: [Option<NackHistoryEntry>; MAX_NACK_HISTORY],
    cursor: usize,
    dedupe_window: Duration,
    rate_limit: NackRateLimit,
}

impl Default for NackAggregator {
    fn default() -> Self {
        Self::new(DEFAULT_NACK_DEDUPE_WINDOW, NackRateLimit::default())
    }
}

impl NackAggregator {
    /// Creates a deduplicating `NACK` aggregator.
    ///
    /// # Examples
    ///
    /// ```
    /// # use std::time::Duration;
    /// # use refract_jitter::{NackAggregator, NackRateLimit};
    /// let aggregator = NackAggregator::new(Duration::from_millis(20), NackRateLimit::default());
    /// assert_eq!(aggregator.dedupe_window(), Duration::from_millis(20));
    /// ```
    #[must_use]
    pub const fn new(dedupe_window: Duration, rate_limit: NackRateLimit) -> Self {
        Self {
            history: [None; MAX_NACK_HISTORY],
            cursor: 0,
            dedupe_window,
            rate_limit,
        }
    }

    /// Submits missing RTP sequence numbers and returns one bounded upstream
    /// `NACK` batch after dedupe and rate limiting.
    ///
    /// # Examples
    ///
    /// ```
    /// # use std::time::Duration;
    /// # use refract_jitter::{NackAggregator, RtpSequenceNumber};
    /// let mut aggregator = NackAggregator::default();
    /// let batch = aggregator.submit([RtpSequenceNumber::new(11)], Duration::ZERO);
    /// assert_eq!(batch.sequences(), &[RtpSequenceNumber::new(11)]);
    /// ```
    pub fn submit(
        &mut self,
        missing: impl IntoIterator<Item = RtpSequenceNumber>,
        now: Duration,
    ) -> NackBatch {
        let mut batch = NackBatch::new();

        for sequence in missing {
            if self.seen_recent(sequence, now) {
                continue;
            }
            if !batch.try_push(sequence) {
                break;
            }
        }

        if batch.is_empty() || !self.rate_limit.allow(now) {
            return NackBatch::new();
        }

        for sequence in batch.iter() {
            self.record(sequence, now);
        }

        batch
    }

    /// Returns the configured dedupe window.
    ///
    /// # Examples
    ///
    /// ```
    /// # use std::time::Duration;
    /// # use refract_jitter::NackAggregator;
    /// assert_eq!(
    ///     NackAggregator::default().dedupe_window(),
    ///     Duration::from_millis(20)
    /// );
    /// ```
    #[must_use]
    pub const fn dedupe_window(&self) -> Duration {
        self.dedupe_window
    }

    /// Returns the fixed history capacity.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_jitter::{NackAggregator, MAX_NACK_HISTORY};
    /// assert_eq!(
    ///     NackAggregator::default().history_capacity(),
    ///     MAX_NACK_HISTORY
    /// );
    /// ```
    #[must_use]
    pub const fn history_capacity(&self) -> usize {
        MAX_NACK_HISTORY
    }

    /// Returns the Stage 1 stability marker for this public API.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_jitter::{NackAggregator, Stability};
    /// assert_eq!(NackAggregator::default().stability(), Stability::Stage1);
    /// ```
    #[must_use]
    pub const fn stability(&self) -> crate::Stability {
        crate::Stability::Stage1
    }

    fn seen_recent(&self, sequence: RtpSequenceNumber, now: Duration) -> bool {
        self.history.iter().flatten().any(|entry| {
            entry.sequence == sequence && now.saturating_sub(entry.sent_at) < self.dedupe_window
        })
    }

    const fn record(&mut self, sequence: RtpSequenceNumber, now: Duration) {
        self.history[self.cursor] = Some(NackHistoryEntry {
            sequence,
            sent_at: now,
        });
        self.cursor = (self.cursor + 1) % MAX_NACK_HISTORY;
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct NackHistoryEntry {
    sequence: RtpSequenceNumber,
    sent_at: Duration,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dedupes_within_window_and_allows_after_window() {
        let mut aggregator = NackAggregator::default();
        let seq = RtpSequenceNumber::new(7);

        assert_eq!(aggregator.submit([seq], Duration::ZERO).len(), 1);
        assert!(
            aggregator
                .submit([seq], Duration::from_millis(19))
                .is_empty()
        );
        assert_eq!(aggregator.submit([seq], Duration::from_millis(20)).len(), 1);
    }

    #[test]
    fn rate_limits_batches_per_subscriber_publisher_pair() {
        let limit = NackRateLimit::new(2, Duration::from_secs(1)).unwrap();
        let mut aggregator = NackAggregator::new(DEFAULT_NACK_DEDUPE_WINDOW, limit);

        assert_eq!(
            aggregator
                .submit([RtpSequenceNumber::new(1)], Duration::ZERO)
                .len(),
            1
        );
        assert_eq!(
            aggregator
                .submit([RtpSequenceNumber::new(2)], Duration::ZERO)
                .len(),
            1
        );
        assert!(
            aggregator
                .submit([RtpSequenceNumber::new(3)], Duration::ZERO)
                .is_empty()
        );
        assert_eq!(
            aggregator
                .submit([RtpSequenceNumber::new(3)], Duration::from_secs(1))
                .len(),
            1
        );
    }

    #[test]
    fn history_is_bounded_to_two_hundred_fifty_six_entries() {
        let mut batch = NackBatch::new();

        for value in 0..=u16::try_from(MAX_NACK_HISTORY).unwrap() {
            let pushed = batch.try_push(RtpSequenceNumber::new(value));
            assert_eq!(pushed, usize::from(value) < MAX_NACK_HISTORY);
        }

        assert_eq!(batch.len(), MAX_NACK_HISTORY);
    }
}
