//! Error taxonomy for router slow-path inputs.
//!
//! Every variant has a stable operations-facing error code.
//!
//! # Examples
//!
//! ```
//! # use refract_router::RouterError;
//! assert_eq!(
//!     RouterError::InvalidConfig {
//!         field: "max_subscriptions"
//!     }
//!     .error_code(),
//!     "ROUTER_CONFIG_0001"
//! );
//! ```

use thiserror::Error;

/// Result alias for fallible router operations.
pub type RouterResult<T> = Result<T, RouterError>;

/// Errors returned by routing table and allocator construction.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum RouterError {
    /// Configuration was outside documented bounds.
    #[error("invalid router configuration: field={field}")]
    InvalidConfig {
        /// Invalid field name.
        field: &'static str,
    },
    /// A subscription did not contain any routable layers.
    #[error("subscription has no layers")]
    EmptyLayers,
    /// A subscription contained more layers than the bounded slow-path limit.
    #[error("subscription has too many layers: len={len} max={max}")]
    TooManyLayers {
        /// Observed layer count.
        len: usize,
        /// Maximum allowed layer count.
        max: usize,
    },
    /// A bounded router collection reached its configured cap.
    #[error("router collection full: component={component} len={len} max={max}")]
    Capacity {
        /// Component being grown.
        component: &'static str,
        /// Current collection length.
        len: usize,
        /// Maximum configured length.
        max: usize,
    },
    /// Allocation failed while building slow-path state.
    #[error("router allocation failed: component={component} source={source}")]
    Allocation {
        /// Component being allocated.
        component: &'static str,
        /// Source allocation failure.
        source: std::collections::TryReserveError,
    },
}

impl RouterError {
    /// Returns the unique stable error code for this variant.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_router::RouterError;
    /// assert_eq!(
    ///     RouterError::EmptyLayers.error_code(),
    ///     "ROUTER_SUBSCRIPTION_0001"
    /// );
    /// ```
    #[must_use]
    pub const fn error_code(&self) -> &'static str {
        match self {
            Self::InvalidConfig { .. } => "ROUTER_CONFIG_0001",
            Self::EmptyLayers => "ROUTER_SUBSCRIPTION_0001",
            Self::TooManyLayers { .. } => "ROUTER_SUBSCRIPTION_0002",
            Self::Capacity { .. } => "ROUTER_CAPACITY_0001",
            Self::Allocation { .. } => "ROUTER_ALLOC_0001",
        }
    }

    /// Returns the Stage 1 stability marker for this public API.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_router::{RouterError, Stability};
    /// assert_eq!(RouterError::EmptyLayers.stability(), Stability::Stage1);
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
            RouterError::InvalidConfig { field: "x" }.error_code(),
            "ROUTER_CONFIG_0001"
        );
        assert_eq!(
            RouterError::EmptyLayers.error_code(),
            "ROUTER_SUBSCRIPTION_0001"
        );
        assert_eq!(
            RouterError::TooManyLayers { len: 9, max: 8 }.error_code(),
            "ROUTER_SUBSCRIPTION_0002"
        );
        assert_eq!(
            RouterError::Capacity {
                component: "subscriptions",
                len: 1,
                max: 1,
            }
            .error_code(),
            "ROUTER_CAPACITY_0001"
        );
    }
}
