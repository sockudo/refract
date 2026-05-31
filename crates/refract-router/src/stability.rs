//! API stability markers for `refract-router`.
//!
//! # Examples
//!
//! ```
//! # use refract_router::Stability;
//! assert_eq!(Stability::Stage1.as_str(), "stage1");
//! ```

/// Stability state for public `refract-router` APIs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Stability {
    /// Stage 1 API surface; usable inside the workspace but not externally stable.
    Stage1,
}

impl Stability {
    /// Returns a stable string label for docs, metrics, and diagnostics.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_router::Stability;
    /// assert_eq!(Stability::Stage1.as_str(), "stage1");
    /// ```
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Stage1 => "stage1",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exposes_stage_label() {
        assert_eq!(Stability::Stage1.as_str(), "stage1");
    }
}
