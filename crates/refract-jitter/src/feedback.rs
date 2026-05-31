//! Coalescing for picture-loss and full-intra-request feedback.
//!
//! `PLI` and `FIR` are tracked independently because their upstream semantics
//! are distinct even though they share the same coalescing policy.
//!
//! # Examples
//!
//! ```
//! # use std::time::Duration;
//! # use refract_jitter::FeedbackCoalescer;
//! let mut coalescer = FeedbackCoalescer::default();
//! assert!(coalescer.request_pli(Duration::ZERO));
//! assert!(!coalescer.request_pli(Duration::from_millis(100)));
//! ```

use std::time::Duration;

/// Default `PLI` and `FIR` coalescing window.
pub const DEFAULT_FEEDBACK_COALESCE_WINDOW: Duration = Duration::from_millis(200);

/// Feedback kind handled by the coalescer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FeedbackKind {
    /// Picture Loss Indication.
    Pli,
    /// Full Intra Request.
    Fir,
}

impl FeedbackKind {
    /// Returns a bounded metrics label.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_jitter::FeedbackKind;
    /// assert_eq!(FeedbackKind::Pli.as_str(), "pli");
    /// ```
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pli => "pli",
            Self::Fir => "fir",
        }
    }

    /// Returns the Stage 1 stability marker for this public API.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_jitter::{FeedbackKind, Stability};
    /// assert_eq!(FeedbackKind::Fir.stability(), Stability::Stage1);
    /// ```
    #[must_use]
    pub const fn stability(self) -> crate::Stability {
        crate::Stability::Stage1
    }
}

/// Independent `PLI` and `FIR` coalescer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FeedbackCoalescer {
    window: Duration,
    last_pli: Option<Duration>,
    last_fir: Option<Duration>,
}

impl Default for FeedbackCoalescer {
    fn default() -> Self {
        Self::new(DEFAULT_FEEDBACK_COALESCE_WINDOW)
    }
}

impl FeedbackCoalescer {
    /// Creates a coalescer with a caller-selected window.
    ///
    /// # Examples
    ///
    /// ```
    /// # use std::time::Duration;
    /// # use refract_jitter::FeedbackCoalescer;
    /// let coalescer = FeedbackCoalescer::new(Duration::from_millis(200));
    /// assert_eq!(coalescer.window(), Duration::from_millis(200));
    /// ```
    #[must_use]
    pub const fn new(window: Duration) -> Self {
        Self {
            window,
            last_pli: None,
            last_fir: None,
        }
    }

    /// Requests a `PLI` and returns whether it should be forwarded upstream.
    ///
    /// # Examples
    ///
    /// ```
    /// # use std::time::Duration;
    /// # use refract_jitter::FeedbackCoalescer;
    /// let mut coalescer = FeedbackCoalescer::default();
    /// assert!(coalescer.request_pli(Duration::ZERO));
    /// assert!(!coalescer.request_pli(Duration::from_millis(1)));
    /// ```
    pub fn request_pli(&mut self, now: Duration) -> bool {
        should_forward(&mut self.last_pli, self.window, now)
    }

    /// Requests an `FIR` and returns whether it should be forwarded upstream.
    ///
    /// # Examples
    ///
    /// ```
    /// # use std::time::Duration;
    /// # use refract_jitter::FeedbackCoalescer;
    /// let mut coalescer = FeedbackCoalescer::default();
    /// assert!(coalescer.request_fir(Duration::ZERO));
    /// assert!(!coalescer.request_fir(Duration::from_millis(1)));
    /// ```
    pub fn request_fir(&mut self, now: Duration) -> bool {
        should_forward(&mut self.last_fir, self.window, now)
    }

    /// Requests a feedback kind and returns whether it should be forwarded.
    ///
    /// # Examples
    ///
    /// ```
    /// # use std::time::Duration;
    /// # use refract_jitter::{FeedbackCoalescer, FeedbackKind};
    /// let mut coalescer = FeedbackCoalescer::default();
    /// assert!(coalescer.request(FeedbackKind::Pli, Duration::ZERO));
    /// ```
    pub fn request(&mut self, kind: FeedbackKind, now: Duration) -> bool {
        match kind {
            FeedbackKind::Pli => self.request_pli(now),
            FeedbackKind::Fir => self.request_fir(now),
        }
    }

    /// Returns the coalescing window.
    ///
    /// # Examples
    ///
    /// ```
    /// # use std::time::Duration;
    /// # use refract_jitter::FeedbackCoalescer;
    /// assert_eq!(
    ///     FeedbackCoalescer::default().window(),
    ///     Duration::from_millis(200)
    /// );
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
    /// # use refract_jitter::{FeedbackCoalescer, Stability};
    /// assert_eq!(FeedbackCoalescer::default().stability(), Stability::Stage1);
    /// ```
    #[must_use]
    pub const fn stability(self) -> crate::Stability {
        crate::Stability::Stage1
    }
}

fn should_forward(last: &mut Option<Duration>, window: Duration, now: Duration) -> bool {
    if last.is_none_or(|sent_at| now.saturating_sub(sent_at) >= window) {
        *last = Some(now);
        return true;
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn coalesces_pli_burst() {
        let mut coalescer = FeedbackCoalescer::default();

        assert!(coalescer.request_pli(Duration::ZERO));
        assert!(!coalescer.request_pli(Duration::from_millis(50)));
        assert!(!coalescer.request_pli(Duration::from_millis(199)));
        assert!(coalescer.request_pli(Duration::from_millis(200)));
    }

    #[test]
    fn coalesces_fir_separately_from_pli() {
        let mut coalescer = FeedbackCoalescer::default();

        assert!(coalescer.request_pli(Duration::ZERO));
        assert!(coalescer.request_fir(Duration::ZERO));
        assert!(!coalescer.request_pli(Duration::from_millis(100)));
        assert!(!coalescer.request_fir(Duration::from_millis(100)));
    }
}
