//! Stability markers for the public `refract-crypto` API.
//!
//! # Examples
//!
//! ```
//! # use refract_crypto::Stability;
//! assert_eq!(Stability::Stage1.as_str(), "stage1");
//! ```

/// Stability state for public `refract-crypto` APIs.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum Stability {
    /// Stage 1 API surface; usable inside the workspace but not externally stable.
    Stage1,
}

impl Stability {
    /// Returns a stable label for diagnostics, docs, and metrics.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_crypto::Stability;
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
    fn stability_label_is_stage1() {
        assert_eq!(Stability::Stage1.as_str(), "stage1");
    }
}
