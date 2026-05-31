//! Monotonic time abstractions.

use core::ops::{Add, AddAssign, Sub, SubAssign};
use std::cell::Cell;
pub use std::time::Duration;

type CompioInstant = std::time::Instant;

/// Monotonic instant used by refract and compatible with `compio::time`.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct Instant(CompioInstant);

impl Instant {
    /// Returns the current monotonic instant.
    #[must_use]
    pub fn now() -> Self {
        Self(CompioInstant::now())
    }

    /// Wraps the instant type consumed by `compio::time`.
    #[must_use]
    pub const fn from_compio(inner: CompioInstant) -> Self {
        Self(inner)
    }

    /// Returns the wrapped instant used by `compio::time`.
    #[must_use]
    pub const fn into_compio(self) -> CompioInstant {
        self.0
    }
}

impl Add<Duration> for Instant {
    type Output = Self;

    fn add(self, rhs: Duration) -> Self::Output {
        Self(self.0 + rhs)
    }
}

impl AddAssign<Duration> for Instant {
    fn add_assign(&mut self, rhs: Duration) {
        self.0 += rhs;
    }
}

impl Sub<Duration> for Instant {
    type Output = Self;

    fn sub(self, rhs: Duration) -> Self::Output {
        self.0.checked_sub(rhs).map_or(self, Self)
    }
}

impl SubAssign<Duration> for Instant {
    fn sub_assign(&mut self, rhs: Duration) {
        *self = *self - rhs;
    }
}

impl Sub for Instant {
    type Output = Duration;

    fn sub(self, rhs: Self) -> Self::Output {
        self.0
            .checked_duration_since(rhs.0)
            .unwrap_or(Duration::ZERO)
    }
}

/// Monotonic clock source.
pub trait Clock {
    /// Returns the current monotonic instant.
    #[must_use]
    fn now(&self) -> Instant;
}

/// Clock backed by the system monotonic timer.
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> Instant {
        Instant::now()
    }
}

/// Deterministic clock for tests and simulations.
#[derive(Debug)]
pub struct MockClock {
    now: Cell<Instant>,
}

impl MockClock {
    /// Creates a mock clock at the supplied instant.
    #[must_use]
    pub const fn new(now: Instant) -> Self {
        Self {
            now: Cell::new(now),
        }
    }

    /// Advances the mock clock by a duration.
    pub fn advance(&self, duration: Duration) {
        self.now.set(self.now.get() + duration);
    }

    /// Sets the mock clock to an exact instant.
    pub fn set(&self, now: Instant) {
        self.now.set(now);
    }
}

impl Clock for MockClock {
    fn now(&self) -> Instant {
        self.now.get()
    }
}

/// Monotonic deadline.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Deadline {
    at: Instant,
}

impl Deadline {
    /// Creates a deadline at an exact instant.
    #[must_use]
    pub const fn at(at: Instant) -> Self {
        Self { at }
    }

    /// Creates a deadline after a duration from the supplied clock.
    #[must_use]
    pub fn after<C: Clock>(clock: &C, duration: Duration) -> Self {
        Self {
            at: clock.now() + duration,
        }
    }

    /// Returns the deadline instant.
    #[must_use]
    pub const fn instant(self) -> Instant {
        self.at
    }

    /// Returns whether this deadline has expired using [`SystemClock`].
    #[must_use]
    pub fn expired(self) -> bool {
        self.expired_with(&SystemClock)
    }

    /// Returns whether this deadline has expired using the supplied clock.
    #[must_use]
    pub fn expired_with<C: Clock>(self, clock: &C) -> bool {
        clock.now() >= self.at
    }
}

#[cfg(test)]
mod tests {
    use super::{Clock, Deadline, Duration, Instant, MockClock};

    #[test]
    fn instant_arithmetic_round_trips() {
        let start = Instant::now();
        let duration = Duration::from_millis(5);
        let end = start + duration;

        assert_eq!(end - start, duration);
        assert_eq!(end - duration, start);
    }

    #[test]
    fn mock_clock_controls_deadline_expiry() {
        let clock = MockClock::new(Instant::now());
        let deadline = Deadline::after(&clock, Duration::from_millis(10));

        assert!(!deadline.expired_with(&clock));
        clock.advance(Duration::from_millis(10));
        assert!(deadline.expired_with(&clock));
        assert_eq!(clock.now(), deadline.instant());
    }
}
