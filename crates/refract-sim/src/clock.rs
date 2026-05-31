//! Virtual monotonic clock for deterministic simulation.
//!
//! The clock stores deterministic elapsed time and presents a
//! [`refract_core::Clock`] view for code that accepts the workspace clock
//! abstraction.

use std::time::Duration;

use refract_core::{Clock, Instant};

use crate::{SimError, SimResult, Stability};

/// Deterministic monotonic clock used by [`crate::Simulation`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VirtualClock {
    base: Instant,
    elapsed: Duration,
}

impl VirtualClock {
    /// Creates a virtual clock starting at elapsed time zero.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_sim::VirtualClock;
    /// let clock = VirtualClock::new();
    /// assert_eq!(clock.elapsed(), std::time::Duration::ZERO);
    /// ```
    #[must_use]
    pub fn new() -> Self {
        Self {
            base: Instant::now(),
            elapsed: Duration::ZERO,
        }
    }

    /// Creates a virtual clock with an explicit base instant.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_core::Instant;
    /// # use refract_sim::VirtualClock;
    /// let clock = VirtualClock::from_base(Instant::now());
    /// assert_eq!(clock.elapsed(), std::time::Duration::ZERO);
    /// ```
    #[must_use]
    pub const fn from_base(base: Instant) -> Self {
        Self {
            base,
            elapsed: Duration::ZERO,
        }
    }

    /// Returns deterministic elapsed virtual time.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_sim::VirtualClock;
    /// let clock = VirtualClock::new();
    /// assert_eq!(clock.elapsed(), std::time::Duration::ZERO);
    /// ```
    #[must_use]
    pub const fn elapsed(&self) -> Duration {
        self.elapsed
    }

    /// Advances virtual time by `duration`.
    ///
    /// # Errors
    ///
    /// Returns [`SimError::TimeOverflow`] when the elapsed duration overflows.
    ///
    /// # Examples
    ///
    /// ```
    /// # use std::time::Duration;
    /// # use refract_sim::VirtualClock;
    /// let mut clock = VirtualClock::new();
    /// clock.advance(Duration::from_millis(5))?;
    /// assert_eq!(clock.elapsed(), Duration::from_millis(5));
    /// # Ok::<(), refract_sim::SimError>(())
    /// ```
    pub fn advance(&mut self, duration: Duration) -> SimResult<()> {
        self.elapsed = self
            .elapsed
            .checked_add(duration)
            .ok_or(SimError::TimeOverflow)?;
        Ok(())
    }

    /// Advances virtual time to an exact elapsed deadline.
    ///
    /// # Errors
    ///
    /// Returns [`SimError::TimeReversal`] when `deadline` is before the current
    /// elapsed time.
    ///
    /// # Examples
    ///
    /// ```
    /// # use std::time::Duration;
    /// # use refract_sim::VirtualClock;
    /// let mut clock = VirtualClock::new();
    /// clock.advance_to(Duration::from_millis(7))?;
    /// assert_eq!(clock.elapsed(), Duration::from_millis(7));
    /// # Ok::<(), refract_sim::SimError>(())
    /// ```
    pub fn advance_to(&mut self, deadline: Duration) -> SimResult<()> {
        if deadline < self.elapsed {
            return Err(SimError::TimeReversal {
                now: self.elapsed,
                requested: deadline,
            });
        }
        self.elapsed = deadline;
        Ok(())
    }

    /// Returns the workspace monotonic instant corresponding to virtual time.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_sim::VirtualClock;
    /// let clock = VirtualClock::new();
    /// let _instant = clock.now_instant();
    /// ```
    #[must_use]
    pub fn now_instant(&self) -> Instant {
        self.base + self.elapsed
    }

    /// Returns the Stage 1 stability marker.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_sim::{Stability, VirtualClock};
    /// assert_eq!(VirtualClock::new().stability(), Stability::Stage1);
    /// ```
    #[must_use]
    pub const fn stability(&self) -> Stability {
        Stability::Stage1
    }
}

impl Default for VirtualClock {
    fn default() -> Self {
        Self::new()
    }
}

impl Clock for VirtualClock {
    fn now(&self) -> Instant {
        self.now_instant()
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use refract_core::Clock;

    use super::VirtualClock;

    #[test]
    fn elapsed_time_advances_deterministically() {
        let mut clock = VirtualClock::new();

        clock.advance(Duration::from_micros(10)).expect("advance");
        clock.advance(Duration::from_micros(5)).expect("advance");

        assert_eq!(clock.elapsed(), Duration::from_micros(15));
    }

    #[test]
    fn clock_trait_tracks_virtual_elapsed_time() {
        let mut clock = VirtualClock::new();
        let before = clock.now();

        clock.advance(Duration::from_millis(1)).expect("advance");

        assert_eq!(clock.now() - before, Duration::from_millis(1));
    }
}
