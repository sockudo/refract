//! Public API stability markers for deterministic simulation types.
//!
//! # Examples
//!
//! ```
//! # use refract_sim::Stability;
//! assert_eq!(Stability::Stage1.as_str(), "stage1");
//! ```

/// Stability marker for public simulator APIs.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum Stability {
    /// Stage 1 public API surface.
    Stage1,
}

impl Stability {
    /// Returns the bounded label for this stability marker.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_sim::Stability;
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
    use super::Stability;

    #[test]
    fn stability_label_is_bounded() {
        assert_eq!(Stability::Stage1.as_str(), "stage1");
    }
}
