//! Error types for deterministic simulation.
//!
//! Every error variant has a stable operator-facing error code so failed seeds
//! can be indexed in dashboards and reproduced without parsing display text.

use std::time::Duration;

use thiserror::Error;

use crate::{Seed, Stability};

/// Result alias for simulator operations.
pub type SimResult<T> = Result<T, SimError>;

/// Deterministic simulation error.
#[derive(Debug, Error)]
pub enum SimError {
    /// Node identifier was already registered.
    #[error("duplicate simulation node: node={node}")]
    DuplicateNode {
        /// Duplicate node identifier.
        node: u32,
    },
    /// Socket address was already registered.
    #[error("duplicate simulation address: address={address}")]
    DuplicateAddress {
        /// Duplicate socket address.
        address: std::net::SocketAddr,
    },
    /// Node identifier is unknown.
    #[error("unknown simulation node: node={node}")]
    UnknownNode {
        /// Unknown node identifier.
        node: u32,
    },
    /// Socket address is unknown.
    #[error("unknown simulation address: address={address}")]
    UnknownAddress {
        /// Unknown socket address.
        address: std::net::SocketAddr,
    },
    /// Node count exceeded the bounded simulator capacity.
    #[error("too many simulation nodes: max={max}")]
    TooManyNodes {
        /// Maximum supported node count.
        max: usize,
    },
    /// Scripted event count exceeded the bounded simulator capacity.
    #[error("too many scripted events: max={max}")]
    TooManyEvents {
        /// Maximum supported scripted event count.
        max: usize,
    },
    /// Pending network datagram count exceeded the bounded simulator capacity.
    #[error("too many pending datagrams: max={max}")]
    TooManyPendingDatagrams {
        /// Maximum supported pending datagram count.
        max: usize,
    },
    /// Datagram payload exceeded the bounded simulator packet size.
    #[error("datagram payload too large: len={len} max={max}")]
    PayloadTooLarge {
        /// Supplied payload length.
        len: usize,
        /// Maximum accepted payload length.
        max: usize,
    },
    /// Text label exceeded the bounded simulator label size.
    #[error("simulation label too large: len={len} max={max}")]
    LabelTooLarge {
        /// Supplied label length.
        len: usize,
        /// Maximum accepted label length.
        max: usize,
    },
    /// Probability was outside the parts-per-million range.
    #[error("probability out of range: ppm={ppm}")]
    ProbabilityOutOfRange {
        /// Supplied probability in parts per million.
        ppm: u32,
    },
    /// A duration exceeded the simulator's bounded time range.
    #[error("duration too large: duration={duration:?}")]
    DurationTooLarge {
        /// Supplied duration.
        duration: Duration,
    },
    /// Virtual time arithmetic overflowed.
    #[error("virtual time overflow")]
    TimeOverflow,
    /// Caller attempted to move virtual time backwards.
    #[error("virtual time cannot move backwards: now={now:?} requested={requested:?}")]
    TimeReversal {
        /// Current virtual time.
        now: Duration,
        /// Requested virtual time.
        requested: Duration,
    },
    /// A deterministic run exceeded its configured step bound.
    #[error("simulation step limit exceeded: max={max}")]
    StepLimit {
        /// Maximum allowed steps.
        max: usize,
    },
    /// Random range upper bound was zero.
    #[error("random range upper bound must be non-zero")]
    RngBoundZero,
    /// Simulator state is already mutably borrowed by another operation.
    #[error("simulation state is busy")]
    StateBusy,
    /// Bounded allocation failed during simulator setup or execution.
    #[error("simulation allocation failed: component={component}")]
    Allocation {
        /// Component that failed to allocate bounded storage.
        component: &'static str,
    },
    /// A scripted bug injection was reached.
    #[error("injected simulation bug: seed={seed} at={at:?} label={label}")]
    InjectedBug {
        /// Seed that reproduced the injected failure.
        seed: Seed,
        /// Virtual time when the injected failure fired.
        at: Duration,
        /// Bounded failure label.
        label: Box<str>,
    },
}

impl SimError {
    /// Returns the stable operator-facing error code.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_sim::SimError;
    /// let error = SimError::TooManyNodes { max: 1 };
    /// assert_eq!(error.error_code(), "SIM_TOPOLOGY_0003");
    /// ```
    #[must_use]
    pub const fn error_code(&self) -> &'static str {
        match self {
            Self::DuplicateNode { .. } => "SIM_TOPOLOGY_0001",
            Self::DuplicateAddress { .. } => "SIM_TOPOLOGY_0002",
            Self::TooManyNodes { .. } => "SIM_TOPOLOGY_0003",
            Self::UnknownNode { .. } => "SIM_TOPOLOGY_0004",
            Self::UnknownAddress { .. } => "SIM_TOPOLOGY_0005",
            Self::TooManyEvents { .. } => "SIM_SCRIPT_0001",
            Self::TooManyPendingDatagrams { .. } => "SIM_NETWORK_0001",
            Self::PayloadTooLarge { .. } => "SIM_NETWORK_0002",
            Self::LabelTooLarge { .. } => "SIM_SCRIPT_0002",
            Self::ProbabilityOutOfRange { .. } => "SIM_NETWORK_0003",
            Self::DurationTooLarge { .. } => "SIM_TIME_0001",
            Self::TimeOverflow => "SIM_TIME_0002",
            Self::TimeReversal { .. } => "SIM_TIME_0003",
            Self::StepLimit { .. } => "SIM_RUN_0001",
            Self::RngBoundZero => "SIM_RNG_0001",
            Self::StateBusy => "SIM_STATE_0001",
            Self::Allocation { .. } => "SIM_ALLOC_0001",
            Self::InjectedBug { .. } => "SIM_REPRO_0001",
        }
    }

    /// Returns the Stage 1 stability marker.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_sim::{SimError, Stability};
    /// let error = SimError::RngBoundZero;
    /// assert_eq!(error.stability(), Stability::Stage1);
    /// ```
    #[must_use]
    pub const fn stability(&self) -> Stability {
        Stability::Stage1
    }
}

#[cfg(test)]
mod tests {
    use super::SimError;

    #[test]
    fn every_error_has_unique_code_for_sampled_variants() {
        let errors = [
            SimError::DuplicateNode { node: 1 },
            SimError::TooManyEvents { max: 1 },
            SimError::RngBoundZero,
        ];
        let mut codes = errors.iter().map(SimError::error_code).collect::<Vec<_>>();
        codes.sort_unstable();
        codes.dedup();
        assert_eq!(codes.len(), errors.len());
    }
}
