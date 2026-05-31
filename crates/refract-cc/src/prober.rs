//! Padding-based bandwidth prober.
//!
//! The prober emits padding byte budgets when the target send rate exceeds the
//! current media send rate.
//!
//! # Examples
//!
//! ```
//! # use std::time::Duration;
//! # use refract_cc::{Prober, ProberConfig};
//! let mut prober = Prober::new(ProberConfig::default());
//! assert!(
//!     prober
//!         .update(500_000, 1_000_000, Duration::from_millis(20))
//!         .padding_bytes
//!         > 0
//! );
//! ```

use std::time::Duration;

use crate::{CcError, CcResult};

/// Default maximum padding emitted by one probe decision.
pub const DEFAULT_MAX_PADDING_BYTES: usize = 12_000;
/// Default probe interval.
pub const DEFAULT_PROBE_INTERVAL: Duration = Duration::from_millis(15);

/// Prober configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProberConfig {
    /// Maximum padding bytes per probe decision.
    pub max_padding_bytes: usize,
    /// Minimum time between probe decisions.
    pub interval: Duration,
}

impl Default for ProberConfig {
    fn default() -> Self {
        Self {
            max_padding_bytes: DEFAULT_MAX_PADDING_BYTES,
            interval: DEFAULT_PROBE_INTERVAL,
        }
    }
}

impl ProberConfig {
    /// Validates prober configuration.
    ///
    /// # Errors
    ///
    /// Returns [`CcError::InvalidConfig`] when max padding or interval is zero.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_cc::ProberConfig;
    /// assert!(ProberConfig::default().validate().is_ok());
    /// ```
    pub const fn validate(self) -> CcResult<Self> {
        if self.max_padding_bytes == 0 {
            return Err(CcError::InvalidConfig {
                field: "max_padding_bytes",
            });
        }
        if self.interval.is_zero() {
            return Err(CcError::InvalidConfig { field: "interval" });
        }
        Ok(self)
    }

    /// Returns the Stage 1 stability marker for this public API.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_cc::{ProberConfig, Stability};
    /// assert_eq!(ProberConfig::default().stability(), Stability::Stage1);
    /// ```
    #[must_use]
    pub const fn stability(self) -> crate::Stability {
        crate::Stability::Stage1
    }
}

/// Probe decision for one scheduling tick.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct ProbeDecision {
    /// Padding bytes to enqueue.
    pub padding_bytes: usize,
    /// Target bitrate used for this decision.
    pub target_bps: u64,
    /// Current media send bitrate used for this decision.
    pub current_bps: u64,
}

impl ProbeDecision {
    /// Returns whether the decision asks for padding.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_cc::ProbeDecision;
    /// assert!(!ProbeDecision::default().has_padding());
    /// ```
    #[must_use]
    pub const fn has_padding(self) -> bool {
        self.padding_bytes != 0
    }

    /// Returns the Stage 1 stability marker for this public API.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_cc::{ProbeDecision, Stability};
    /// assert_eq!(ProbeDecision::default().stability(), Stability::Stage1);
    /// ```
    #[must_use]
    pub const fn stability(self) -> crate::Stability {
        crate::Stability::Stage1
    }
}

/// Padding prober state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Prober {
    config: ProberConfig,
    last_probe: Option<Duration>,
}

impl Prober {
    /// Creates a prober.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_cc::{Prober, ProberConfig};
    /// assert_eq!(
    ///     Prober::new(ProberConfig::default())
    ///         .config()
    ///         .max_padding_bytes,
    ///     12_000
    /// );
    /// ```
    #[must_use]
    pub const fn new(config: ProberConfig) -> Self {
        Self {
            config,
            last_probe: None,
        }
    }

    /// Updates probe state and returns padding bytes to send.
    ///
    /// # Examples
    ///
    /// ```
    /// # use std::time::Duration;
    /// # use refract_cc::{Prober, ProberConfig};
    /// let mut prober = Prober::new(ProberConfig::default());
    /// assert!(
    ///     prober
    ///         .update(500_000, 1_000_000, Duration::from_millis(15))
    ///         .has_padding()
    /// );
    /// ```
    pub fn update(
        &mut self,
        current_send_bps: u64,
        target_bps: u64,
        now: Duration,
    ) -> ProbeDecision {
        if target_bps <= current_send_bps {
            return ProbeDecision {
                padding_bytes: 0,
                target_bps,
                current_bps: current_send_bps,
            };
        }
        if self
            .last_probe
            .is_some_and(|last_probe| now.saturating_sub(last_probe) < self.config.interval)
        {
            return ProbeDecision {
                padding_bytes: 0,
                target_bps,
                current_bps: current_send_bps,
            };
        }

        let deficit_bps = target_bps - current_send_bps;
        let interval_micros = self.config.interval.as_micros();
        let bytes = (u128::from(deficit_bps) * interval_micros) / 8_000_000;
        let padding_bytes = usize::try_from(bytes)
            .unwrap_or(usize::MAX)
            .min(self.config.max_padding_bytes);
        self.last_probe = Some(now);
        ProbeDecision {
            padding_bytes,
            target_bps,
            current_bps: current_send_bps,
        }
    }

    /// Returns the prober configuration.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_cc::{Prober, ProberConfig};
    /// assert_eq!(
    ///     Prober::new(ProberConfig::default()).config(),
    ///     ProberConfig::default()
    /// );
    /// ```
    #[must_use]
    pub const fn config(self) -> ProberConfig {
        self.config
    }

    /// Returns the Stage 1 stability marker for this public API.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_cc::{Prober, ProberConfig, Stability};
    /// assert_eq!(
    ///     Prober::new(ProberConfig::default()).stability(),
    ///     Stability::Stage1
    /// );
    /// ```
    #[must_use]
    pub const fn stability(self) -> crate::Stability {
        crate::Stability::Stage1
    }
}

impl Default for Prober {
    fn default() -> Self {
        Self::new(ProberConfig::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn probes_with_padding_when_target_exceeds_current() {
        let mut prober = Prober::new(ProberConfig {
            max_padding_bytes: 2_000,
            interval: Duration::from_millis(20),
        });

        let decision = prober.update(500_000, 1_300_000, Duration::from_millis(20));
        assert_eq!(decision.padding_bytes, 2_000);
        assert!(
            !prober
                .update(500_000, 1_300_000, Duration::from_millis(25))
                .has_padding()
        );
    }

    #[test]
    fn probe_accuracy_matches_rate_deficit() {
        let mut prober = Prober::new(ProberConfig {
            max_padding_bytes: 10_000,
            interval: Duration::from_millis(20),
        });

        let decision = prober.update(800_000, 1_200_000, Duration::from_millis(20));
        assert_eq!(decision.padding_bytes, 1_000);
    }
}
