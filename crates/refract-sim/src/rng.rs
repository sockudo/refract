//! Seeded deterministic pseudo-random number generation.
//!
//! The simulator uses `SplitMix64` because it is tiny, deterministic across
//! platforms, and sufficient for fault scheduling. It is not cryptographic.

use std::fmt;

use crate::{SimError, SimResult, Stability, network::PPM_DENOMINATOR};

const SPLITMIX_INCREMENT: u64 = 0x9E37_79B9_7F4A_7C15;
const SPLITMIX_MUL_1: u64 = 0xBF58_476D_1CE4_E5B9;
const SPLITMIX_MUL_2: u64 = 0x94D0_49BB_1331_11EB;

/// Reproducibility seed for a simulation run.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct Seed(u64);

impl Seed {
    /// Creates a reproducibility seed.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_sim::Seed;
    /// assert_eq!(Seed::new(42).as_u64(), 42);
    /// ```
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    /// Returns the raw seed value.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_sim::Seed;
    /// assert_eq!(Seed::new(9).as_u64(), 9);
    /// ```
    #[must_use]
    pub const fn as_u64(self) -> u64 {
        self.0
    }

    /// Returns the Stage 1 stability marker.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_sim::{Seed, Stability};
    /// assert_eq!(Seed::new(1).stability(), Stability::Stage1);
    /// ```
    #[must_use]
    pub const fn stability(self) -> Stability {
        Stability::Stage1
    }
}

impl From<u64> for Seed {
    fn from(value: u64) -> Self {
        Self::new(value)
    }
}

impl fmt::Display for Seed {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}", self.0)
    }
}

/// Deterministic `SplitMix64` generator.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeterministicRng {
    seed: Seed,
    state: u64,
}

impl DeterministicRng {
    /// Creates a deterministic generator from a seed.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_sim::{DeterministicRng, Seed};
    /// let mut left = DeterministicRng::new(Seed::new(5));
    /// let mut right = DeterministicRng::new(Seed::new(5));
    /// assert_eq!(left.next_u64(), right.next_u64());
    /// ```
    #[must_use]
    pub const fn new(seed: Seed) -> Self {
        Self {
            seed,
            state: seed.as_u64(),
        }
    }

    /// Returns the seed used to initialize the generator.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_sim::{DeterministicRng, Seed};
    /// assert_eq!(DeterministicRng::new(Seed::new(11)).seed(), Seed::new(11));
    /// ```
    #[must_use]
    pub const fn seed(&self) -> Seed {
        self.seed
    }

    /// Returns the next deterministic `u64`.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_sim::{DeterministicRng, Seed};
    /// let mut rng = DeterministicRng::new(Seed::new(1));
    /// assert_ne!(rng.next_u64(), rng.next_u64());
    /// ```
    pub const fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(SPLITMIX_INCREMENT);
        let mut value = self.state;
        value = (value ^ (value >> 30)).wrapping_mul(SPLITMIX_MUL_1);
        value = (value ^ (value >> 27)).wrapping_mul(SPLITMIX_MUL_2);
        value ^ (value >> 31)
    }

    /// Returns a deterministic integer below `upper_exclusive`.
    ///
    /// # Errors
    ///
    /// Returns [`SimError::RngBoundZero`] when `upper_exclusive` is zero.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_sim::{DeterministicRng, Seed};
    /// let mut rng = DeterministicRng::new(Seed::new(3));
    /// assert!(rng.below(10)? < 10);
    /// # Ok::<(), refract_sim::SimError>(())
    /// ```
    pub const fn below(&mut self, upper_exclusive: u64) -> SimResult<u64> {
        if upper_exclusive == 0 {
            return Err(SimError::RngBoundZero);
        }
        Ok(self.next_u64() % upper_exclusive)
    }

    /// Returns whether a parts-per-million probability hit.
    ///
    /// # Errors
    ///
    /// Returns [`SimError::ProbabilityOutOfRange`] when `ppm` exceeds
    /// [`PPM_DENOMINATOR`].
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_sim::{DeterministicRng, Seed, PPM_DENOMINATOR};
    /// let mut rng = DeterministicRng::new(Seed::new(1));
    /// assert!(rng.chance_per_million(PPM_DENOMINATOR)?);
    /// # Ok::<(), refract_sim::SimError>(())
    /// ```
    pub fn chance_per_million(&mut self, ppm: u32) -> SimResult<bool> {
        if ppm > PPM_DENOMINATOR {
            return Err(SimError::ProbabilityOutOfRange { ppm });
        }
        Ok(self.chance_ppm(ppm))
    }

    pub(crate) fn chance_ppm(&mut self, ppm: u32) -> bool {
        ppm == PPM_DENOMINATOR || self.next_u64() % u64::from(PPM_DENOMINATOR) < u64::from(ppm)
    }

    /// Returns the Stage 1 stability marker.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_sim::{DeterministicRng, Seed, Stability};
    /// assert_eq!(
    ///     DeterministicRng::new(Seed::new(1)).stability(),
    ///     Stability::Stage1
    /// );
    /// ```
    #[must_use]
    pub const fn stability(&self) -> Stability {
        Stability::Stage1
    }
}

#[cfg(test)]
mod tests {
    use super::{DeterministicRng, Seed};

    #[test]
    fn same_seed_replays_same_stream() {
        let mut left = DeterministicRng::new(Seed::new(0xCAFE));
        let mut right = DeterministicRng::new(Seed::new(0xCAFE));
        let left_values = (0..16).map(|_| left.next_u64()).collect::<Vec<_>>();
        let right_values = (0..16).map(|_| right.next_u64()).collect::<Vec<_>>();

        assert_eq!(left_values, right_values);
    }

    #[test]
    fn zero_bound_is_rejected() {
        let mut rng = DeterministicRng::new(Seed::new(1));

        assert!(rng.below(0).is_err());
    }
}
