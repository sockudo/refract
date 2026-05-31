//! Production load-generation scenarios for refract release gates.
//!
//! `refract-loadgen` owns deterministic, automatable load scenarios that can
//! be driven from `xtask` and CI. Stage 1 includes a signaling open/signal/close
//! scenario that exercises the WebSocket connection lifecycle through the
//! `refract-signal` safety envelope: connection ceiling admission, handshake
//! progress, defensive JSON parsing, per-connection rate limiting, send-queue
//! backpressure accounting, idle tracking, and close accounting.
//!
//! # Examples
//!
//! ```
//! # use refract_loadgen::{SignalLoadgenConfig, run_signal_open_signal_close};
//! let report = run_signal_open_signal_close(SignalLoadgenConfig::for_connections(4)?)?;
//! assert!(report.passed());
//! # Ok::<(), refract_loadgen::LoadgenError>(())
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![warn(clippy::pedantic)]
#![warn(clippy::nursery)]
#![warn(rust_2024_compatibility)]
#![allow(clippy::multiple_crate_versions)]

use std::time::{Duration, Instant};

use refract_signal::{
    ConnectionLedger, DEFAULT_CONNECTION_CEILING, HandshakeTracker, IdleTracker, SendQueue,
    SignalConfig, SignalError, SignalRateLimiter, parse_client_message,
};
use thiserror::Error;

/// Default Stage 1 signaling load gate: 100k concurrent WebSocket lifecycles.
pub const DEFAULT_SIGNAL_LOAD_CONNECTIONS: usize = 100_000;

/// Default messages sent by each simulated WebSocket connection.
pub const DEFAULT_SIGNAL_MESSAGES_PER_CONNECTION: usize = 1;

const DEFAULT_HANDSHAKE_BYTES: usize = 512;
const SIGNAL_REQUEST_FRAME: &[u8] =
    br#"{"version":1,"request_id":"loadgen","app":"room","type":"ping","nonce":"stage1"}"#;
const SIGNAL_RESPONSE_FRAME: &[u8] = br#"{"version":1,"ok":true}"#;

/// Result alias for load-generation operations.
pub type LoadgenResult<T> = Result<T, LoadgenError>;

/// Public API stability marker.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum Stability {
    /// Stage 1 API surface.
    Stage1,
}

impl Stability {
    /// Returns the stable marker label.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_loadgen::Stability;
    /// assert_eq!(Stability::Stage1.as_str(), "stage1");
    /// ```
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Stage1 => "stage1",
        }
    }
}

/// Error taxonomy for production load-generation scenarios.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum LoadgenError {
    /// A load-generation configuration field was invalid.
    #[error("invalid loadgen configuration: {field}")]
    InvalidConfig {
        /// Invalid field name.
        field: &'static str,
    },
    /// A signaling safety gate rejected the scenario.
    #[error("signaling loadgen failed")]
    Signal {
        /// Signaling failure source.
        #[source]
        source: SignalError,
    },
    /// A bounded allocation failed before the scenario could start.
    #[error("allocation failed in {component}")]
    Allocation {
        /// Component that failed to allocate.
        component: &'static str,
    },
    /// A checked counter overflowed.
    #[error("counter overflow in {component}")]
    CounterOverflow {
        /// Counter component.
        component: &'static str,
    },
}

impl LoadgenError {
    /// Returns a unique operations dashboard error code.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_loadgen::LoadgenError;
    /// assert_eq!(
    ///     LoadgenError::InvalidConfig {
    ///         field: "connections"
    ///     }
    ///     .error_code(),
    ///     "LOADGEN_CONFIG_0001",
    /// );
    /// ```
    #[must_use]
    pub const fn error_code(&self) -> &'static str {
        match self {
            Self::InvalidConfig { .. } => "LOADGEN_CONFIG_0001",
            Self::Signal { .. } => "LOADGEN_SIGNAL_0001",
            Self::Allocation { .. } => "LOADGEN_ALLOC_0001",
            Self::CounterOverflow { .. } => "LOADGEN_COUNTER_0001",
        }
    }

    /// Returns the Stage 1 stability marker.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_loadgen::{LoadgenError, Stability};
    /// assert_eq!(
    ///     LoadgenError::InvalidConfig {
    ///         field: "connections"
    ///     }
    ///     .stability(),
    ///     Stability::Stage1,
    /// );
    /// ```
    #[must_use]
    pub const fn stability(&self) -> Stability {
        Stability::Stage1
    }
}

impl From<SignalError> for LoadgenError {
    fn from(source: SignalError) -> Self {
        Self::Signal { source }
    }
}

/// Configuration for the Stage 1 signaling open/signal/close load gate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SignalLoadgenConfig {
    signal: SignalConfig,
    connections: usize,
    messages_per_connection: usize,
}

impl SignalLoadgenConfig {
    /// Creates a signaling load-generation configuration.
    ///
    /// # Errors
    ///
    /// Returns [`LoadgenError::InvalidConfig`] if the target count is zero,
    /// if messages per connection is zero, or if the scenario would exceed the
    /// configured signaling connection ceiling.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_loadgen::SignalLoadgenConfig;
    /// # use refract_signal::SignalConfig;
    /// let config = SignalLoadgenConfig::new(SignalConfig::default(), 10, 1)?;
    /// assert_eq!(config.connections(), 10);
    /// # Ok::<(), refract_loadgen::LoadgenError>(())
    /// ```
    pub fn new(
        signal: SignalConfig,
        connections: usize,
        messages_per_connection: usize,
    ) -> LoadgenResult<Self> {
        let config = Self {
            signal,
            connections,
            messages_per_connection,
        };
        config.validate()?;
        Ok(config)
    }

    /// Creates a configuration using the default signaling envelope.
    ///
    /// # Errors
    ///
    /// Returns [`LoadgenError::InvalidConfig`] when `connections` is zero or
    /// above the default signaling ceiling.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_loadgen::SignalLoadgenConfig;
    /// let config = SignalLoadgenConfig::for_connections(100)?;
    /// assert_eq!(config.messages_per_connection(), 1);
    /// # Ok::<(), refract_loadgen::LoadgenError>(())
    /// ```
    pub fn for_connections(connections: usize) -> LoadgenResult<Self> {
        Self::new(
            SignalConfig::default(),
            connections,
            DEFAULT_SIGNAL_MESSAGES_PER_CONNECTION,
        )
    }

    /// Creates the default Stage 1 100k signaling gate configuration.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_loadgen::{SignalLoadgenConfig, DEFAULT_SIGNAL_LOAD_CONNECTIONS};
    /// assert_eq!(
    ///     SignalLoadgenConfig::stage1_default().connections(),
    ///     DEFAULT_SIGNAL_LOAD_CONNECTIONS,
    /// );
    /// ```
    #[must_use]
    pub fn stage1_default() -> Self {
        Self {
            signal: SignalConfig::default(),
            connections: DEFAULT_SIGNAL_LOAD_CONNECTIONS,
            messages_per_connection: DEFAULT_SIGNAL_MESSAGES_PER_CONNECTION,
        }
    }

    /// Validates the load-generation configuration.
    ///
    /// # Errors
    ///
    /// Returns [`LoadgenError::InvalidConfig`] for zero counts or a connection
    /// target larger than the configured signaling ceiling.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_loadgen::SignalLoadgenConfig;
    /// SignalLoadgenConfig::stage1_default().validate()?;
    /// # Ok::<(), refract_loadgen::LoadgenError>(())
    /// ```
    pub const fn validate(self) -> LoadgenResult<()> {
        if self.connections == 0 {
            return Err(LoadgenError::InvalidConfig {
                field: "connections",
            });
        }
        if self.messages_per_connection == 0 {
            return Err(LoadgenError::InvalidConfig {
                field: "messages_per_connection",
            });
        }
        if self.connections > self.signal.connection_ceiling() {
            return Err(LoadgenError::InvalidConfig {
                field: "connection_ceiling",
            });
        }
        Ok(())
    }

    /// Returns the signaling safety-envelope configuration.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_loadgen::SignalLoadgenConfig;
    /// assert_eq!(
    ///     SignalLoadgenConfig::stage1_default()
    ///         .signal_config()
    ///         .connection_ceiling(),
    ///     refract_signal::DEFAULT_CONNECTION_CEILING,
    /// );
    /// ```
    #[must_use]
    pub const fn signal_config(self) -> SignalConfig {
        self.signal
    }

    /// Returns the target concurrent connection count.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_loadgen::SignalLoadgenConfig;
    /// assert_eq!(SignalLoadgenConfig::stage1_default().connections(), 100_000);
    /// ```
    #[must_use]
    pub const fn connections(self) -> usize {
        self.connections
    }

    /// Returns the number of messages sent by each connection.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_loadgen::SignalLoadgenConfig;
    /// assert_eq!(
    ///     SignalLoadgenConfig::stage1_default().messages_per_connection(),
    ///     1
    /// );
    /// ```
    #[must_use]
    pub const fn messages_per_connection(self) -> usize {
        self.messages_per_connection
    }

    /// Returns the expected total accepted signal messages.
    ///
    /// # Errors
    ///
    /// Returns [`LoadgenError::CounterOverflow`] if the multiplication
    /// overflows on the current target.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_loadgen::SignalLoadgenConfig;
    /// assert_eq!(
    ///     SignalLoadgenConfig::for_connections(4)?.expected_messages()?,
    ///     4
    /// );
    /// # Ok::<(), refract_loadgen::LoadgenError>(())
    /// ```
    pub const fn expected_messages(self) -> LoadgenResult<usize> {
        match self.connections.checked_mul(self.messages_per_connection) {
            Some(value) => Ok(value),
            None => Err(LoadgenError::CounterOverflow {
                component: "signal_expected_messages",
            }),
        }
    }

    /// Returns the Stage 1 stability marker.
    ///
    /// # Examples
    ///
    /// ```
    /// # use refract_loadgen::{SignalLoadgenConfig, Stability};
    /// assert_eq!(
    ///     SignalLoadgenConfig::stage1_default().stability(),
    ///     Stability::Stage1
    /// );
    /// ```
    #[must_use]
    pub const fn stability(self) -> Stability {
        Stability::Stage1
    }
}

impl Default for SignalLoadgenConfig {
    fn default() -> Self {
        Self::stage1_default()
    }
}

/// Report returned by the Stage 1 signaling load gate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SignalLoadgenReport {
    target_connections: usize,
    messages_per_connection: usize,
    opened_connections: usize,
    signaled_messages: usize,
    closed_connections: usize,
    rejected_connections: usize,
    elapsed: Duration,
}

impl SignalLoadgenReport {
    /// Creates a report from final scenario counters.
    ///
    /// # Examples
    ///
    /// ```
    /// # use std::time::Duration;
    /// # use refract_loadgen::SignalLoadgenReport;
    /// let report = SignalLoadgenReport::new(1, 1, 1, 1, 1, 0, Duration::ZERO);
    /// assert!(report.passed());
    /// ```
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub const fn new(
        target_connections: usize,
        messages_per_connection: usize,
        opened_connections: usize,
        signaled_messages: usize,
        closed_connections: usize,
        rejected_connections: usize,
        elapsed: Duration,
    ) -> Self {
        Self {
            target_connections,
            messages_per_connection,
            opened_connections,
            signaled_messages,
            closed_connections,
            rejected_connections,
            elapsed,
        }
    }

    /// Returns whether all open/signal/close gates passed.
    ///
    /// # Examples
    ///
    /// ```
    /// # use std::time::Duration;
    /// # use refract_loadgen::SignalLoadgenReport;
    /// let report = SignalLoadgenReport::new(2, 1, 2, 2, 2, 0, Duration::ZERO);
    /// assert!(report.passed());
    /// ```
    #[must_use]
    pub const fn passed(self) -> bool {
        self.rejected_connections == 0
            && self.opened_connections == self.target_connections
            && self.closed_connections == self.opened_connections
            && self.signaled_messages == self.expected_messages()
    }

    /// Returns the target connection count.
    ///
    /// # Examples
    ///
    /// ```
    /// # use std::time::Duration;
    /// # use refract_loadgen::SignalLoadgenReport;
    /// assert_eq!(
    ///     SignalLoadgenReport::new(3, 1, 3, 3, 3, 0, Duration::ZERO).target_connections(),
    ///     3
    /// );
    /// ```
    #[must_use]
    pub const fn target_connections(self) -> usize {
        self.target_connections
    }

    /// Returns opened connections.
    ///
    /// # Examples
    ///
    /// ```
    /// # use std::time::Duration;
    /// # use refract_loadgen::SignalLoadgenReport;
    /// assert_eq!(
    ///     SignalLoadgenReport::new(1, 1, 1, 1, 1, 0, Duration::ZERO).opened_connections(),
    ///     1
    /// );
    /// ```
    #[must_use]
    pub const fn opened_connections(self) -> usize {
        self.opened_connections
    }

    /// Returns accepted signal messages.
    ///
    /// # Examples
    ///
    /// ```
    /// # use std::time::Duration;
    /// # use refract_loadgen::SignalLoadgenReport;
    /// assert_eq!(
    ///     SignalLoadgenReport::new(1, 2, 1, 2, 1, 0, Duration::ZERO).signaled_messages(),
    ///     2
    /// );
    /// ```
    #[must_use]
    pub const fn signaled_messages(self) -> usize {
        self.signaled_messages
    }

    /// Returns closed connections.
    ///
    /// # Examples
    ///
    /// ```
    /// # use std::time::Duration;
    /// # use refract_loadgen::SignalLoadgenReport;
    /// assert_eq!(
    ///     SignalLoadgenReport::new(1, 1, 1, 1, 1, 0, Duration::ZERO).closed_connections(),
    ///     1
    /// );
    /// ```
    #[must_use]
    pub const fn closed_connections(self) -> usize {
        self.closed_connections
    }

    /// Returns rejected connections.
    ///
    /// # Examples
    ///
    /// ```
    /// # use std::time::Duration;
    /// # use refract_loadgen::SignalLoadgenReport;
    /// assert_eq!(
    ///     SignalLoadgenReport::new(1, 1, 1, 1, 1, 0, Duration::ZERO).rejected_connections(),
    ///     0
    /// );
    /// ```
    #[must_use]
    pub const fn rejected_connections(self) -> usize {
        self.rejected_connections
    }

    /// Returns elapsed wall-clock time.
    ///
    /// # Examples
    ///
    /// ```
    /// # use std::time::Duration;
    /// # use refract_loadgen::SignalLoadgenReport;
    /// assert_eq!(
    ///     SignalLoadgenReport::new(1, 1, 1, 1, 1, 0, Duration::ZERO).elapsed(),
    ///     Duration::ZERO
    /// );
    /// ```
    #[must_use]
    pub const fn elapsed(self) -> Duration {
        self.elapsed
    }

    /// Returns expected accepted signal messages.
    ///
    /// # Examples
    ///
    /// ```
    /// # use std::time::Duration;
    /// # use refract_loadgen::SignalLoadgenReport;
    /// assert_eq!(
    ///     SignalLoadgenReport::new(4, 2, 4, 8, 4, 0, Duration::ZERO).expected_messages(),
    ///     8
    /// );
    /// ```
    #[must_use]
    pub const fn expected_messages(self) -> usize {
        self.target_connections
            .saturating_mul(self.messages_per_connection)
    }

    /// Returns the Stage 1 stability marker.
    ///
    /// # Examples
    ///
    /// ```
    /// # use std::time::Duration;
    /// # use refract_loadgen::{SignalLoadgenReport, Stability};
    /// assert_eq!(
    ///     SignalLoadgenReport::new(1, 1, 1, 1, 1, 0, Duration::ZERO).stability(),
    ///     Stability::Stage1,
    /// );
    /// ```
    #[must_use]
    pub const fn stability(self) -> Stability {
        Stability::Stage1
    }
}

/// Runs the Stage 1 signaling open/signal/close scenario.
///
/// The scenario keeps all connection permits open before signaling begins, so
/// the default configuration exercises the 100k connection ceiling path instead
/// of only opening one connection at a time.
///
/// # Errors
///
/// Returns [`LoadgenError`] when configuration is invalid, a signaling safety
/// gate rejects any connection or message, or bounded allocation fails.
///
/// # Examples
///
/// ```
/// # use refract_loadgen::{SignalLoadgenConfig, run_signal_open_signal_close};
/// let report = run_signal_open_signal_close(SignalLoadgenConfig::for_connections(8)?)?;
/// assert_eq!(report.opened_connections(), 8);
/// # Ok::<(), refract_loadgen::LoadgenError>(())
/// ```
pub fn run_signal_open_signal_close(
    config: SignalLoadgenConfig,
) -> LoadgenResult<SignalLoadgenReport> {
    config.validate()?;
    let expected_messages = config.expected_messages()?;
    let started = Instant::now();
    let mut ledger = ConnectionLedger::new(config.signal_config());
    let mut permits = Vec::new();
    permits
        .try_reserve_exact(config.connections())
        .map_err(|_source| LoadgenError::Allocation {
            component: "signal_connection_permits",
        })?;

    for _connection in 0..config.connections() {
        match ledger.try_open() {
            Ok(permit) => permits.push(permit),
            Err(source) => return Err(LoadgenError::Signal { source }),
        }
    }

    let mut signaled_messages = 0_usize;
    for _permit in &permits {
        run_signal_connection_script(config.signal_config(), config.messages_per_connection())?;
        signaled_messages = signaled_messages
            .checked_add(config.messages_per_connection())
            .ok_or(LoadgenError::CounterOverflow {
                component: "signal_signaled_messages",
            })?;
    }

    let mut closed_connections = 0_usize;
    for permit in permits {
        ledger.close(permit);
        closed_connections =
            closed_connections
                .checked_add(1)
                .ok_or(LoadgenError::CounterOverflow {
                    component: "signal_closed_connections",
                })?;
    }

    let report = SignalLoadgenReport::new(
        config.connections(),
        config.messages_per_connection(),
        config.connections(),
        signaled_messages,
        closed_connections,
        0,
        started.elapsed(),
    );
    if signaled_messages == expected_messages && report.passed() {
        Ok(report)
    } else {
        Err(LoadgenError::CounterOverflow {
            component: "signal_report_mismatch",
        })
    }
}

fn run_signal_connection_script(
    signal: SignalConfig,
    messages_per_connection: usize,
) -> LoadgenResult<()> {
    let started = Instant::now();
    let mut handshake = HandshakeTracker::start(started, signal);
    handshake.record_bytes(DEFAULT_HANDSHAKE_BYTES, signal)?;
    handshake.mark_complete();
    handshake.check_deadline(started)?;

    let limiter = SignalRateLimiter::new(signal)?;
    let mut idle = IdleTracker::start(started, signal);
    let mut send_queue = SendQueue::new(signal);

    for _message in 0..messages_per_connection {
        limiter.check()?;
        let envelope = parse_client_message(SIGNAL_REQUEST_FRAME, &signal)?;
        let _app_message = envelope.to_app_message()?;
        send_queue.enqueue(SIGNAL_RESPONSE_FRAME)?;
        let _sent_frame = send_queue.pop();
        let now = Instant::now();
        idle.touch(now);
        idle.check_deadline(now)?;
    }

    Ok(())
}

const _: () = {
    assert!(DEFAULT_SIGNAL_LOAD_CONNECTIONS == DEFAULT_CONNECTION_CEILING);
};

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use refract_signal::SignalConfig;

    use super::{
        DEFAULT_SIGNAL_LOAD_CONNECTIONS, DEFAULT_SIGNAL_MESSAGES_PER_CONNECTION, LoadgenError,
        SignalLoadgenConfig, SignalLoadgenReport, run_signal_open_signal_close,
    };

    #[test]
    fn default_stage1_config_targets_one_hundred_thousand_connections() {
        let config = SignalLoadgenConfig::stage1_default();

        assert_eq!(config.connections(), DEFAULT_SIGNAL_LOAD_CONNECTIONS);
        assert_eq!(
            config.messages_per_connection(),
            DEFAULT_SIGNAL_MESSAGES_PER_CONNECTION
        );
    }

    #[test]
    fn invalid_zero_connection_config_fails_closed() {
        assert!(matches!(
            SignalLoadgenConfig::for_connections(0),
            Err(LoadgenError::InvalidConfig {
                field: "connections"
            })
        ));
    }

    #[test]
    fn invalid_connection_target_above_ceiling_fails_closed() {
        let signal = SignalConfig::new(
            1024,
            512,
            Duration::from_secs(5),
            Duration::from_secs(30),
            2,
            100,
            100,
            1024,
        )
        .expect("signal config");

        assert!(matches!(
            SignalLoadgenConfig::new(signal, 3, 1),
            Err(LoadgenError::InvalidConfig {
                field: "connection_ceiling"
            })
        ));
    }

    #[test]
    fn signal_open_signal_close_small_scenario_passes() {
        let report = run_signal_open_signal_close(
            SignalLoadgenConfig::for_connections(128).expect("config"),
        )
        .expect("loadgen");

        assert!(report.passed());
        assert_eq!(report.opened_connections(), 128);
        assert_eq!(report.signaled_messages(), 128);
        assert_eq!(report.closed_connections(), 128);
        assert_eq!(report.rejected_connections(), 0);
    }

    #[test]
    fn report_pass_requires_all_expected_counts() {
        assert!(SignalLoadgenReport::new(2, 1, 2, 2, 2, 0, Duration::ZERO).passed());
        assert!(!SignalLoadgenReport::new(2, 1, 2, 1, 2, 0, Duration::ZERO).passed());
    }
}
