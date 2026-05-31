//! Error taxonomy for bounded jitter and feedback state.
//!
//! Every variant has a stable operations-facing error code.
//!
//! # Examples
//!
//! ```
//! # use refract_jitter::JitterError;
//! assert_eq!(
//!     JitterError::InvalidConfig {
//!         field: "memory_cap_bytes"
//!     }
//!     .error_code(),
//!     "JITTER_CONFIG_0001"
//! );
//! ```

use thiserror::Error;

/// Result alias for `refract-jitter` operations.
pub type JitterResult<T> = Result<T, JitterError>;

/// Errors returned by bounded jitter buffer and feedback helpers.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum JitterError {
    /// Configuration was outside documented bounds.
    #[error("invalid jitter configuration: field={field}")]
    InvalidConfig {
        /// Invalid field name.
        field: &'static str,
    },
    /// A packet exceeded the configured per-packet byte bound.
    #[error("rtp packet exceeds jitter packet bound: len={len} max={max}")]
    PacketTooLarge {
        /// Observed packet length.
        len: usize,
        /// Configured maximum packet length.
        max: usize,
    },
    /// Preallocation failed while warming the jitter state.
    #[error("jitter preallocation failed: component={component} source={source}")]
    Allocation {
        /// Component being allocated.
        component: &'static str,
        /// Source allocation failure.
        source: std::collections::TryReserveError,
    },
}

impl JitterError {
    /// Returns the unique stable error code for this variant.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_jitter::JitterError;
    /// assert_eq!(
    ///     JitterError::PacketTooLarge {
    ///         len: 1501,
    ///         max: 1200
    ///     }
    ///     .error_code(),
    ///     "JITTER_PACKET_0001"
    /// );
    /// ```
    #[must_use]
    pub const fn error_code(&self) -> &'static str {
        match self {
            Self::InvalidConfig { .. } => "JITTER_CONFIG_0001",
            Self::PacketTooLarge { .. } => "JITTER_PACKET_0001",
            Self::Allocation { .. } => "JITTER_ALLOC_0001",
        }
    }

    /// Returns the Stage 1 stability marker for this public API.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_jitter::{JitterError, Stability};
    /// assert_eq!(
    ///     JitterError::InvalidConfig { field: "window" }.stability(),
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
    fn error_codes_are_stable() {
        assert_eq!(
            JitterError::InvalidConfig { field: "x" }.error_code(),
            "JITTER_CONFIG_0001"
        );
        assert_eq!(
            JitterError::PacketTooLarge { len: 2, max: 1 }.error_code(),
            "JITTER_PACKET_0001"
        );
    }
}
