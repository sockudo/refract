//! RTP sequence number helpers with wrap-aware ordering.
//!
//! # Examples
//!
//! ```
//! # use refract_jitter::RtpSequenceNumber;
//! assert_eq!(
//!     RtpSequenceNumber::new(u16::MAX).next(),
//!     RtpSequenceNumber::new(0)
//! );
//! ```

/// RTP sequence number newtype.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[repr(transparent)]
pub struct RtpSequenceNumber(u16);

impl RtpSequenceNumber {
    /// Creates a sequence number from its raw RTP value.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_jitter::RtpSequenceNumber;
    /// assert_eq!(RtpSequenceNumber::new(7).as_u16(), 7);
    /// ```
    #[must_use]
    pub const fn new(value: u16) -> Self {
        Self(value)
    }

    /// Returns the raw RTP sequence number.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_jitter::RtpSequenceNumber;
    /// assert_eq!(RtpSequenceNumber::new(9).as_u16(), 9);
    /// ```
    #[must_use]
    pub const fn as_u16(self) -> u16 {
        self.0
    }

    /// Returns the next RTP sequence number, wrapping at `u16::MAX`.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_jitter::RtpSequenceNumber;
    /// assert_eq!(RtpSequenceNumber::new(u16::MAX).next().as_u16(), 0);
    /// ```
    #[must_use]
    pub const fn next(self) -> Self {
        Self(self.0.wrapping_add(1))
    }

    /// Adds a wrapping offset to the sequence number.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_jitter::RtpSequenceNumber;
    /// assert_eq!(RtpSequenceNumber::new(u16::MAX).wrapping_add(2).as_u16(), 1);
    /// ```
    #[must_use]
    pub const fn wrapping_add(self, offset: u16) -> Self {
        Self(self.0.wrapping_add(offset))
    }

    /// Returns the forward distance from `self` to `newer` in RTP sequence space.
    ///
    /// Distances below `32768` are considered forward by [`crate::LossDetector`].
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_jitter::RtpSequenceNumber;
    /// assert_eq!(
    ///     RtpSequenceNumber::new(10).forward_distance_to(RtpSequenceNumber::new(13)),
    ///     3
    /// );
    /// assert_eq!(
    ///     RtpSequenceNumber::new(u16::MAX).forward_distance_to(RtpSequenceNumber::new(1)),
    ///     2
    /// );
    /// ```
    #[must_use]
    pub const fn forward_distance_to(self, newer: Self) -> u16 {
        newer.0.wrapping_sub(self.0)
    }

    /// Returns the Stage 1 stability marker for this public API.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_jitter::{RtpSequenceNumber, Stability};
    /// assert_eq!(RtpSequenceNumber::new(1).stability(), Stability::Stage1);
    /// ```
    #[must_use]
    pub const fn stability(self) -> crate::Stability {
        crate::Stability::Stage1
    }
}

impl From<u16> for RtpSequenceNumber {
    fn from(value: u16) -> Self {
        Self::new(value)
    }
}

impl From<RtpSequenceNumber> for u16 {
    fn from(value: RtpSequenceNumber) -> Self {
        value.as_u16()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wraps_at_sequence_boundary() {
        assert_eq!(
            RtpSequenceNumber::new(u16::MAX).next(),
            RtpSequenceNumber::new(0)
        );
        assert_eq!(
            RtpSequenceNumber::new(u16::MAX).forward_distance_to(RtpSequenceNumber::new(1)),
            2
        );
    }
}
