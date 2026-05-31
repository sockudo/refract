//! Error taxonomy for congestion-control boundaries.
//!
//! Every variant has a stable operations-facing error code.
//!
//! # Examples
//!
//! ```
//! # use refract_cc::CcError;
//! assert_eq!(
//!     CcError::InvalidConfig { field: "rate" }.error_code(),
//!     "CC_CONFIG_0001"
//! );
//! ```

use thiserror::Error;

/// Result alias for `refract-cc` operations.
pub type CcResult<T> = Result<T, CcError>;

/// Congestion-control, pacing, probing, and transport-cc errors.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum CcError {
    /// Configuration was outside documented bounds.
    #[error("invalid congestion-control configuration: field={field}")]
    InvalidConfig {
        /// Invalid field name.
        field: &'static str,
    },
    /// A bounded queue was full.
    #[error("bounded congestion-control queue is full: component={component}")]
    QueueFull {
        /// Queue component name.
        component: &'static str,
    },
    /// Transport-wide congestion control feedback bytes were malformed.
    #[error("malformed transport-cc feedback: reason={reason}")]
    MalformedTwcc {
        /// Stable parse failure reason.
        reason: &'static str,
    },
    /// Encoding would exceed a documented byte bound.
    #[error("transport-cc feedback exceeds bound: len={len} max={max}")]
    PacketTooLarge {
        /// Attempted encoded length.
        len: usize,
        /// Maximum encoded length.
        max: usize,
    },
    /// Bounded allocation failed outside the packet hot path.
    #[error("congestion-control preallocation failed: component={component} source={source}")]
    Allocation {
        /// Component being allocated.
        component: &'static str,
        /// Source allocation failure.
        source: std::collections::TryReserveError,
    },
}

impl CcError {
    /// Returns the unique stable error code for this variant.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_cc::CcError;
    /// assert_eq!(
    ///     CcError::QueueFull { component: "pacer" }.error_code(),
    ///     "CC_QUEUE_0001"
    /// );
    /// ```
    #[must_use]
    pub const fn error_code(&self) -> &'static str {
        match self {
            Self::InvalidConfig { .. } => "CC_CONFIG_0001",
            Self::QueueFull { .. } => "CC_QUEUE_0001",
            Self::MalformedTwcc { .. } => "CC_TWCC_0001",
            Self::PacketTooLarge { .. } => "CC_TWCC_0002",
            Self::Allocation { .. } => "CC_ALLOC_0001",
        }
    }

    /// Returns the Stage 1 stability marker for this public API.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_cc::{CcError, Stability};
    /// assert_eq!(
    ///     CcError::InvalidConfig { field: "x" }.stability(),
    ///     Stability::Stage1
    /// );
    /// ```
    #[must_use]
    pub const fn stability(&self) -> crate::Stability {
        crate::Stability::Stage1
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_codes_are_unique_for_variants() {
        assert_eq!(
            CcError::MalformedTwcc { reason: "short" }.error_code(),
            "CC_TWCC_0001"
        );
        assert_eq!(
            CcError::PacketTooLarge { len: 2, max: 1 }.error_code(),
            "CC_TWCC_0002"
        );
    }
}
